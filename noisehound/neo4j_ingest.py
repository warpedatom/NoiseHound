"""Live BloodHound ingestion over the Neo4j Bolt protocol.

Reads the graph directly from the Neo4j database BloodHound CE / SharpHound
populate, instead of an offline zip. Computed edges the DB already carries
(including any ADCS ESCx BloodHound post-processed) arrive as relationship types
and are scored like any other edge. On top of that, NoiseHound runs its own ESC
and roasting synthesis here too - mirroring the zip path - so escalation edges
BloodHound's post-processing does not emit are still surfaced. That requires the
node properties (template flags, roastable flags) and the CA/policy
relationships, which are fetched below.

The pure record-to-graph step is separated from the driver connection so it can
be unit-tested without a running database; the connection is validated against a
real instance (e.g. BloodHound CE via Docker).
"""
from __future__ import annotations

import os

import networkx as nx

from .adcs import synthesize_adcs
from .ingest import _PROPS_RETAINED_TYPES, _add_edge, synthesize_roasting

# Most specific label wins when a node carries several (BloodHound nodes are
# usually tagged Base plus their kind).
_LABEL_PRIORITY = [
    "User", "Computer", "Group", "Domain", "OU", "GPO", "Container",
    "CertTemplate", "EnterpriseCA", "RootCA", "NTAuthStore", "AIACA",
    "IssuancePolicy",
]

# Node kinds whose properties we fetch over Bolt (for ESC synthesis + roastable
# flags). Fetching properties for every node would bloat large-graph transfers.
_PROPS_FETCH_LABELS = sorted(_PROPS_RETAINED_TYPES | {"User"})
_BOLT_SCHEMES = ("bolt://", "neo4j://", "bolt+s://", "neo4j+s://", "bolt+ssc://", "neo4j+ssc://")


def is_bolt_uri(path: str) -> bool:
    return isinstance(path, str) and path.startswith(_BOLT_SCHEMES)


def _primary_label(labels: list) -> str:
    labels = labels or []
    for lbl in _LABEL_PRIORITY:
        if lbl in labels:
            return lbl
    non_base = [lbl for lbl in labels if lbl != "Base"]
    return non_base[0] if non_base else (labels[0] if labels else "Base")


def _reconstruct_adcs_facts(g: nx.DiGraph) -> None:
    """Rebuild the CA/template facts synthesize_adcs expects from Bolt edges.

    In an analysed DB these arrive as *relationships*, not the JSON fields the
    zip parser reads: a template PublishedTo a CA, a computer HostsCAService a
    CA, and an issuance policy OIDGroupLink to a group.
    """
    for oid, d in g.nodes(data=True):
        t = d.get("type")
        if t == "EnterpriseCA":
            d["enabled_templates"] = [
                s for s, _, ed in g.in_edges(oid, data=True)
                if "PublishedTo" in (ed.get("edge_types") or [])
                and g.nodes[s].get("type") == "CertTemplate"
            ]
            hosts = [
                s for s, _, ed in g.in_edges(oid, data=True)
                if "HostsCAService" in (ed.get("edge_types") or [])
            ]
            if hosts:
                d["hosting_computer"] = hosts[0]
        elif t == "IssuancePolicy":
            links = [
                tgt for _, tgt, ed in g.out_edges(oid, data=True)
                if "OIDGroupLink" in (ed.get("edge_types") or [])
            ]
            if links:
                d["oid_group_link"] = links[0]


def build_graph_from_records(node_records: list, rel_records: list) -> nx.DiGraph:
    """Assemble a DiGraph from Neo4j node and relationship rows.

    node_records: dicts with keys oid, labels (list), name, and optional props.
    rel_records:  dicts with keys source, target, rtype.
    """
    g = nx.DiGraph()
    for n in node_records:
        oid = n.get("oid")
        if not oid:
            continue
        name = n.get("name") or oid
        ntype = _primary_label(n.get("labels"))
        g.add_node(oid, name=str(name).upper(), type=ntype)
        props = n.get("props")
        if props:
            lp = {str(k).lower(): v for k, v in props.items()}
            if ntype in _PROPS_RETAINED_TYPES:
                g.nodes[oid]["props"] = lp
            if ntype == "User":
                if lp.get("hasspn"):
                    g.nodes[oid]["roastable_spn"] = True
                if lp.get("dontreqpreauth"):
                    g.nodes[oid]["roastable_asrep"] = True
    for r in rel_records:
        _add_edge(g, r.get("source"), r.get("target"), r.get("rtype"))
    # The analysed DB may already carry computed ESC edges; NoiseHound's own
    # synthesis runs on top (idempotent - _add_edge dedups) so gaps BloodHound's
    # post-processing leaves are still surfaced, matching the zip path.
    _reconstruct_adcs_facts(g)
    g.graph["adcs_edges_synthesized"] = synthesize_adcs(g)
    g.graph["roasting_edges_synthesized"] = synthesize_roasting(g)
    return g


def load_graph_from_neo4j(
    uri: str,
    user: str,
    password: str,
    database: str | None = None,
) -> nx.DiGraph:
    """Connect to Neo4j over Bolt and build the internal graph."""
    try:
        from neo4j import GraphDatabase
    except ImportError as exc:
        raise RuntimeError(
            "the neo4j driver is required for Bolt ingestion - "
            "install it with: pip install 'noisehound[neo4j]'"
        ) from exc

    # Fetch full properties only for ADCS-relevant kinds + users (roastable
    # flags); every other node needs just oid/labels/name. Without the props,
    # ESC and roasting synthesis silently produce nothing on the live path.
    node_query = (
        "MATCH (n) WHERE n.objectid IS NOT NULL "
        "RETURN n.objectid AS oid, labels(n) AS labels, n.name AS name, "
        "CASE WHEN any(l IN labels(n) WHERE l IN $plabels) "
        "THEN properties(n) ELSE null END AS props"
    )
    rel_query = (
        "MATCH (a)-[r]->(b) WHERE a.objectid IS NOT NULL AND b.objectid IS NOT NULL "
        "RETURN a.objectid AS source, b.objectid AS target, type(r) AS rtype"
    )

    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session(database=database) as session:
            node_records = [
                {"oid": rec["oid"], "labels": rec["labels"], "name": rec["name"],
                 "props": rec["props"]}
                for rec in session.run(node_query, plabels=_PROPS_FETCH_LABELS)
            ]
            rel_records = [
                {"source": rec["source"], "target": rec["target"], "rtype": rec["rtype"]}
                for rec in session.run(rel_query)
            ]
    finally:
        driver.close()

    g = build_graph_from_records(node_records, rel_records)
    if g.number_of_nodes() == 0:
        raise ValueError("no nodes returned from Neo4j at %s (is the graph loaded?)" % uri)
    return g


def load_from_uri(
    uri: str,
    user: str | None = None,
    password: str | None = None,
    database: str | None = None,
) -> nx.DiGraph:
    """Resolve credentials (args then env) and load from a Bolt URI."""
    user = user or os.environ.get("NEO4J_USER", "neo4j")
    password = password if password is not None else os.environ.get("NEO4J_PASSWORD", "")
    database = database or os.environ.get("NEO4J_DATABASE") or None
    return load_graph_from_neo4j(uri, user, password, database)
