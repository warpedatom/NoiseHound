"""Graph ingestion: BloodHound data -> internal networkx.DiGraph.

Two input formats are supported:

1. **BloodHound CE export** - a .zip of *_users.json / *_groups.json /
   *_computers.json / *_domains.json / *_ous.json / *_gpos.json /
   *_containers.json / *_certtemplates.json / *_enterprisecas.json files (the
   same data SharpHound produces), or a single such .json file, or a directory
   of them. A pragmatic parser extracts the relationship collections that
   matter for path-finding.

2. **Normalised NoiseHound JSON** - ``{"nodes": [...], "edges": [...]}`` - a
   simple, explicit format used for offline analysis and deterministic tests.

Coverage notes: control ACEs (GenericAll, WriteDacl, WriteOwner, Owns,
GenericWrite, WriteSPN, AddMember, AddSelf, ForceChangePassword,
AddKeyCredentialLink, AddAllowedToAct, ReadLAPSPassword, ReadGMSAPassword,
AllExtendedRights, ...) flow through generically from every node's ``Aces``
array, so enrollment rights on certificate templates and CAs are captured too.
Group membership, container hierarchy, local-admin/RDP/DCOM/PSRemote access,
sessions, constrained/resource-based delegation, GPO links, SID history, and
domain trusts are parsed explicitly. DCSync is synthesised the way BloodHound
does it (GenericAll on the domain object, or GetChanges + GetChangesAll
together) rather than trusting a single replication right. Synthetic ADCS ESCx
edges are consumed if a post-processed export already contains them, but are not
re-derived here.
"""
from __future__ import annotations

import json
import os
import zipfile
from typing import Any

import networkx as nx

from .adcs import synthesize_adcs


# ---- Node identity -----------------------------------------------------------

# Node types whose raw Properties are retained for ADCS ESC analysis. These are
# few in number, so keeping their props does not bloat large graphs.
_PROPS_RETAINED_TYPES = {
    "CertTemplate", "EnterpriseCA", "RootCA", "NTAuthStore", "AIACA", "Domain",
    "IssuancePolicy",
}

def _node_label(props: dict, oid: str) -> str:
    name = props.get("name") or props.get("distinguishedname") or oid
    return str(name).upper()


# ---- BloodHound CE parsing ---------------------------------------------------

# Replication rights are only meaningful in combination; they are collapsed into
# a synthetic DCSync edge rather than becoming standalone edges.
_REPLICATION_RIGHTS = {"getchanges", "getchangesall", "getchangesinfilteredset"}

# A few rights normalise to a canonical edge name.
_RIGHT_ALIASES = {
    "dcsync": "DCSync",
    "allextendedrights": "AllExtendedRights",
}


def _norm_right(right: str) -> str:
    return _RIGHT_ALIASES.get(right.strip().lower(), right)


def _add_node(g: nx.DiGraph, oid: str, node_type: str, props: dict | None = None) -> None:
    props = props or {}
    if oid in g:
        if node_type and node_type != "Base":
            g.nodes[oid]["type"] = node_type
        if props.get("name") and g.nodes[oid].get("name") in (None, oid):
            g.nodes[oid]["name"] = _node_label(props, oid)
        return
    g.add_node(oid, name=_node_label(props, oid), type=node_type or "Base")


def _add_edge(g: nx.DiGraph, src: str, dst: str, edge_type: str) -> None:
    if not src or not dst:
        return
    if src not in g:
        g.add_node(src, name=src, type="Base")
    if dst not in g:
        g.add_node(dst, name=dst, type="Base")
    existing = g.get_edge_data(src, dst)
    if existing is None:
        g.add_edge(src, dst, edge_type=edge_type, edge_types=[edge_type])
    elif edge_type not in existing["edge_types"]:
        existing["edge_types"].append(edge_type)


def _parse_bh_node(g: nx.DiGraph, node: dict, node_type: str) -> None:
    props = node.get("Properties", {}) or {}
    oid = node.get("ObjectIdentifier") or props.get("objectid")
    if not oid:
        return
    _add_node(g, oid, node_type, props)

    # Retain ADCS-relevant properties/relationships for ESC synthesis.
    if node_type in _PROPS_RETAINED_TYPES:
        g.nodes[oid]["props"] = {str(k).lower(): v for k, v in props.items()}
    # Flag roastable service/user accounts for Kerberoast / AS-REP synthesis.
    if node_type == "User":
        lp = {str(k).lower(): v for k, v in props.items()}
        if lp.get("hasspn"):
            g.nodes[oid]["roastable_spn"] = True
        if lp.get("dontreqpreauth"):
            g.nodes[oid]["roastable_asrep"] = True
    # ESC13: an issuance-policy OID object may be linked to a group
    # (msDS-OIDToGroupLink); enrolling a template that asserts the OID then grants
    # membership in that group. Retain the linked group so synthesis can use it.
    if node_type == "IssuancePolicy":
        gl = node.get("GroupLink") or {}
        gsid = gl.get("ObjectIdentifier") if isinstance(gl, dict) else gl
        if gsid:
            _add_node(g, gsid, gl.get("ObjectType", "Group") if isinstance(gl, dict) else "Group")
            g.nodes[oid]["oid_group_link"] = gsid
    if node_type == "EnterpriseCA":
        enabled = node.get("EnabledCertTemplates") or []
        ids = []
        for item in enabled:
            ids.append(item.get("ObjectIdentifier") if isinstance(item, dict) else item)
        g.nodes[oid]["enabled_templates"] = [i for i in ids if i]
        hc = node.get("HostingComputer")
        if isinstance(hc, dict):
            hc = hc.get("ObjectIdentifier")
        if hc:
            g.nodes[oid]["hosting_computer"] = hc

    # ACE-based control edges: PrincipalSID --RightName--> this node.
    principal_rights: dict = {}
    for ace in node.get("Aces", []) or []:
        principal = ace.get("PrincipalSID")
        right = ace.get("RightName")
        if not principal or not right:
            continue
        _add_node(g, principal, ace.get("PrincipalType", "Base"))
        rlow = right.strip().lower()
        principal_rights.setdefault(principal, set()).add(rlow)
        if rlow in _REPLICATION_RIGHTS:
            continue  # folded into synthetic DCSync below
        _add_edge(g, principal, oid, _norm_right(right))

    # DCSync synthesis on the domain object (matches BloodHound's rule).
    if node_type == "Domain":
        for principal, rights in principal_rights.items():
            if (
                "genericall" in rights
                or "dcsync" in rights
                or {"getchanges", "getchangesall"} <= rights
            ):
                _add_edge(g, principal, oid, "DCSync")

    # Group membership: member --MemberOf--> group.
    for member in node.get("Members", []) or []:
        mid = member.get("ObjectIdentifier")
        if mid:
            _add_node(g, mid, member.get("ObjectType", "Base"))
            _add_edge(g, mid, oid, "MemberOf")

    # Container hierarchy: this node --Contains--> child.
    for child in node.get("ChildObjects", []) or []:
        cid = child.get("ObjectIdentifier")
        if cid:
            _add_node(g, cid, child.get("ObjectType", "Base"))
            _add_edge(g, oid, cid, "Contains")

    # Computer access collections: principal --<edge>--> computer.
    for coll_key, edge in (
        ("LocalAdmins", "AdminTo"),
        ("RemoteDesktopUsers", "CanRDP"),
        ("DcomUsers", "ExecuteDCOM"),
        ("PSRemoteUsers", "CanPSRemote"),
    ):
        coll = node.get(coll_key) or {}
        for r in coll.get("Results", []) or []:
            pid = r.get("ObjectIdentifier")
            if pid:
                _add_node(g, pid, r.get("ObjectType", "Base"))
                _add_edge(g, pid, oid, edge)

    # Sessions: computer --HasSession--> user. BloodHound CE splits sessions
    # across three collections - Sessions (NetSessionEnum), PrivilegedSessions
    # (LoggedOn), and RegistrySessions (remote registry) - all with the same
    # {UserSID, ComputerSID} shape. Read all three or interactive/privileged
    # logons (the quiet-lateral edges) are silently missed.
    for coll in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
        for s in (node.get(coll) or {}).get("Results", []) or []:
            user_sid = s.get("UserSID")
            comp_sid = s.get("ComputerSID", oid)
            if user_sid:
                _add_node(g, user_sid, "User")
                _add_edge(g, comp_sid, user_sid, "HasSession")

    # RBCD: principal --AllowedToAct--> this computer.
    for r in node.get("AllowedToAct", []) or []:
        pid = r.get("ObjectIdentifier")
        if pid:
            _add_node(g, pid, r.get("ObjectType", "Base"))
            _add_edge(g, pid, oid, "AllowedToAct")

    # Constrained delegation: this node --AllowedToDelegate--> target.
    for r in node.get("AllowedToDelegate", []) or []:
        tid = r.get("ObjectIdentifier")
        if tid:
            _add_node(g, tid, r.get("ObjectType", "Base"))
            _add_edge(g, oid, tid, "AllowedToDelegate")

    # SID history: this principal --HasSIDHistory--> the historical principal.
    for r in node.get("HasSIDHistory", []) or []:
        hid = r.get("ObjectIdentifier") if isinstance(r, dict) else r
        if hid:
            _add_node(g, hid, r.get("ObjectType", "Base") if isinstance(r, dict) else "Base")
            _add_edge(g, oid, hid, "HasSIDHistory")

    # GPO links: GPO --GpLink--> OU/domain.
    for link in node.get("Links", []) or []:
        tid = link.get("GUID") or link.get("ObjectIdentifier")
        if tid:
            _add_edge(g, oid, tid, "GpLink")

    # Domain trusts: this domain --<trust>--> target domain.
    if node_type == "Domain":
        for tr in node.get("Trusts", []) or []:
            target = tr.get("TargetDomainSid") or tr.get("TargetDomainName")
            if not target:
                continue
            _add_node(g, target, "Domain", {"name": tr.get("TargetDomainName", target)})
            ttype = str(tr.get("TrustType", "")).lower()
            edge = "SameForestTrust" if ttype in ("parentchild", "crosslink") else "CrossForestTrust"
            _add_edge(g, oid, target, edge)


_BH_TYPE_BY_META = {
    "users": "User",
    "groups": "Group",
    "computers": "Computer",
    "domains": "Domain",
    "ous": "OU",
    "gpos": "GPO",
    "containers": "Container",
    "certtemplates": "CertTemplate",
    "enterprisecas": "EnterpriseCA",
    "rootcas": "RootCA",
    "ntauthstores": "NTAuthStore",
    "aiacas": "AIACA",
    "issuancepolicies": "IssuancePolicy",
}


def _parse_bh_file(g: nx.DiGraph, doc: dict) -> None:
    meta = doc.get("meta", {}) or {}
    node_type = _BH_TYPE_BY_META.get(meta.get("type", ""), "Base")
    for node in doc.get("data", []) or []:
        _parse_bh_node(g, node, node_type)


# ---- Normalised format -------------------------------------------------------

def _parse_normalised(g: nx.DiGraph, doc: dict) -> None:
    for n in doc.get("nodes", []) or []:
        oid = n.get("id") or n.get("objectid")
        if not oid:
            continue
        g.add_node(oid, name=str(n.get("name", oid)).upper(), type=n.get("type", "Base"))
    for e in doc.get("edges", []) or []:
        src = e.get("source") or e.get("from")
        dst = e.get("target") or e.get("to")
        et = e.get("edge_type") or e.get("type")
        if src and dst and et:
            _add_edge(g, src, dst, et)


# ---- Public entry points -----------------------------------------------------

def _looks_normalised(doc: Any) -> bool:
    return isinstance(doc, dict) and "nodes" in doc and "edges" in doc


def _ingest_doc(g: nx.DiGraph, doc: Any) -> None:
    if _looks_normalised(doc):
        _parse_normalised(g, doc)
    elif isinstance(doc, dict) and "data" in doc:
        _parse_bh_file(g, doc)
    else:
        raise ValueError("unrecognised JSON document (not BloodHound or normalised)")


def load_graph(
    path: str,
    neo4j_user: str | None = None,
    neo4j_password: str | None = None,
    neo4j_database: str | None = None,
) -> nx.DiGraph:
    """Build an internal DiGraph from a .zip, .json, directory, or Bolt URI.

    A ``bolt://`` / ``neo4j://`` URI reads live from the Neo4j database
    BloodHound CE populates (credentials from the neo4j_* args or the
    NEO4J_USER / NEO4J_PASSWORD environment variables).
    """
    # Lazy import avoids a hard dependency on the neo4j driver for offline use.
    from .neo4j_ingest import is_bolt_uri, load_from_uri
    if is_bolt_uri(path):
        return load_from_uri(path, neo4j_user, neo4j_password, neo4j_database)

    g = nx.DiGraph()

    # utf-8-sig transparently strips a UTF-8 BOM (which SharpHound / BloodHound
    # CE exports sometimes carry) and is a no-op on plain UTF-8.
    if os.path.isdir(path):
        found = False
        for name in sorted(os.listdir(path)):
            if name.endswith(".json"):
                with open(os.path.join(path, name), "r", encoding="utf-8-sig") as fh:
                    _ingest_doc(g, json.load(fh))
                found = True
        if not found:
            raise ValueError("no .json files found in directory: %s" % path)
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            members = [n for n in zf.namelist() if n.endswith(".json")]
            if not members:
                raise ValueError("zip contains no .json files: %s" % path)
            for name in sorted(members):
                with zf.open(name) as fh:
                    _ingest_doc(g, json.loads(fh.read().decode("utf-8-sig")))
    elif path.endswith(".json"):
        with open(path, "r", encoding="utf-8-sig") as fh:
            _ingest_doc(g, json.load(fh))
    else:
        raise ValueError("unsupported input (expected .zip, .json, or directory): %s" % path)

    if g.number_of_nodes() == 0:
        raise ValueError("no nodes ingested from %s" % path)

    # Synthesise AD CS ESC1-8 escalation edges from the retained template/CA
    # facts. No-op when the export contains no ADCS nodes.
    g.graph["adcs_edges_synthesized"] = synthesize_adcs(g)
    # Synthesise Kerberoast / AS-REP edges to roastable accounts.
    g.graph["roasting_edges_synthesized"] = synthesize_roasting(g)
    return g


def synthesize_roasting(g: nx.DiGraph) -> int:
    """Add Kerberoast / AS-REP edges from a foothold to roastable accounts.

    BloodHound records roastability as node properties (hasspn,
    dontreqpreauth), so those accounts never enter a path. Any authenticated
    principal can roast them, so we draw an edge from the domain's Domain Users
    group (or Authenticated Users) to each roastable account - making the
    credential-access opportunity pathable and scored, the way ADCS ESC edges
    are. krbtgt (which carries an SPN but is not a useful roast target) is
    excluded.
    """
    source = None
    if "S-1-5-11" in g:  # Authenticated Users
        source = "S-1-5-11"
    else:
        for oid, d in g.nodes(data=True):
            if d.get("type") == "Domain":
                du = oid + "-513"  # Domain Users
                if du in g:
                    source = du
                    break
    if source is None:
        return 0

    added = 0
    for oid, d in list(g.nodes(data=True)):
        if d.get("type") != "User" or oid == source:
            continue
        if oid.endswith("-502") or d.get("name", "").upper().split("@", 1)[0] == "KRBTGT":
            continue
        if d.get("roastable_spn"):
            _add_edge(g, source, oid, "Kerberoast")
            added += 1
        if d.get("roastable_asrep"):
            _add_edge(g, source, oid, "ASREPRoast")
            added += 1
    return added


def edge_types_in(g: nx.DiGraph) -> set:
    """The set of distinct edge types present in the graph."""
    types: set = set()
    for _, _, data in g.edges(data=True):
        types.update(data.get("edge_types", [data.get("edge_type")]))
    types.discard(None)
    return types


def find_matches(g: nx.DiGraph, identifier: str) -> list:
    """All node ids a friendly identifier could refer to.

    Tried in order: object id, exact (case-insensitive) name, then name without
    the @DOMAIN suffix. The last can return several nodes in a multi-domain
    forest (e.g. one "Domain Admins" per domain) - callers should surface that
    ambiguity so the operator can qualify with @DOMAIN.
    """
    if identifier in g:
        return [identifier]
    want = identifier.strip().upper()
    exact = [oid for oid, d in g.nodes(data=True) if d.get("name", "").upper() == want]
    if exact:
        return exact
    return [
        oid for oid, d in g.nodes(data=True)
        if d.get("name", "").upper().split("@", 1)[0] == want
    ]


def find_node(g: nx.DiGraph, identifier: str) -> str | None:
    """Resolve a user-supplied identifier to a single node id.

    On a tie, prefers a Group node (objectives are usually groups such as
    "Domain Admins"). Use find_matches to detect ambiguity.
    """
    matches = find_matches(g, identifier)
    if not matches:
        return None
    groups = [m for m in matches if g.nodes[m].get("type") == "Group"]
    return (groups or matches)[0]
