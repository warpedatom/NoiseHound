"""AD CS ESC1-13 edge synthesis.

BloodHound collects the certificate-template and enterprise-CA facts needed to
reason about AD CS domain escalation but leaves the ESC edges to a post-
processing pass. NoiseHound performs a focused version of that pass so the
solver can route through certificate-based escalation the same way it routes
through ACL abuse.

Edges are drawn from the abusing principal to the domain's escalation target -
the Domain Admins group (RID 512) of the object's domain if present, else the
domain node - because a successful ESC1/2/3/6/8 lets the attacker obtain a
certificate authenticating as an arbitrary principal, including a Domain Admin.

Known simplifications (documented; they fail safe toward showing more paths):
- CA-level enrollment restrictions are not modelled; template enrollment rights
  are treated as sufficient. Real environments often let Authenticated Users
  enroll at the CA, so this is usually correct and otherwise over-reports.
- ESC5 covers control of the CA object or its hosting computer, not every PKI
  container object.
- ESC9a (no-security-extension) and ESC10b (schannel weak-mapping) fire on the
  positive *template* signal (nosecurityextension / schannelauthenticationenabled)
  and treat the required write-over-victim / weak-DC-binding step as satisfied -
  a fail-safe over-report. ESC10a (Kerberos weak binding) has no template-level
  signal - it depends only on the DC registry setting
  StrongCertificateBindingEnforcement, which BloodHound does not currently collect
  - so it is intentionally not synthesised here.
- ESC13 draws its edge to the OID-linked *group*, not Domain Admins, and requires
  the IssuancePolicy's msDS-OIDToGroupLink (loaded by ingest.py).
- Synthetic ESC edges already present in a post-processed export are preserved.
"""
from __future__ import annotations

import networkx as nx

# EKU OIDs that make a certificate usable for domain authentication.
AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",       # Client Authentication
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    "1.3.6.1.5.2.3.4",         # PKINIT Client Authentication
    "2.5.29.37.0",             # Any Purpose
}
ANY_PURPOSE_EKU = "2.5.29.37.0"
ENROLLMENT_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"  # Certificate Request Agent

# Rights that grant enrollment on a template.
ENROLL_RIGHTS = {"enroll", "autoenroll", "allextendedrights", "genericall"}
# Rights that let a principal reconfigure a template into an ESC1 posture.
TEMPLATE_CONTROL_RIGHTS = {
    "genericall", "genericwrite", "writedacl", "writeowner", "owns",
    "writeownerlimitedrights", "writepkienrollmentflag", "writepkinameflag",
    "writeproperty",
}
# Rights that constitute control of a CA object.
CA_CONTROL_RIGHTS = {"genericall", "writedacl", "writeowner", "owns", "manageca"}
# Rights over a CA's hosting computer that yield CA control.
HOST_CONTROL_RIGHTS = {"genericall", "adminto", "writedacl", "writeowner", "owns"}

WELL_KNOWN_AUTHENTICATED_USERS = "S-1-5-11"


def _truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes", "enabled")
    return False


def _as_int(v, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _ekus(props: dict) -> set:
    out: set = set()
    for key in ("effectiveekus", "ekus"):
        val = props.get(key)
        if isinstance(val, list):
            out.update(str(x).strip() for x in val)
    return out


def _add_edge(g: nx.DiGraph, src: str, dst: str, edge_type: str) -> bool:
    if not src or not dst or src == dst:
        return False
    existing = g.get_edge_data(src, dst)
    if existing is None:
        g.add_edge(src, dst, edge_type=edge_type, edge_types=[edge_type])
        return True
    if edge_type not in existing["edge_types"]:
        existing["edge_types"].append(edge_type)
        return True
    return False


def _principals_with(g: nx.DiGraph, oid: str, rights: set) -> set:
    who: set = set()
    for src, _, data in g.in_edges(oid, data=True):
        ets = {e.lower() for e in (data.get("edge_types") or [data.get("edge_type")]) if e}
        if ets & rights:
            who.add(src)
    return who


def synthesize_adcs(g: nx.DiGraph) -> int:
    """Add ESC1-8 escalation edges to the graph in place. Returns edges added."""
    templates = {n: d for n, d in g.nodes(data=True) if d.get("type") == "CertTemplate"}
    cas = {n: d for n, d in g.nodes(data=True) if d.get("type") == "EnterpriseCA"}
    if not templates and not cas:
        return 0

    domains = {n for n, d in g.nodes(data=True) if d.get("type") == "Domain"}
    single_domain = next(iter(domains)) if len(domains) == 1 else None

    def target_for(props: dict) -> str | None:
        dom = (props or {}).get("domainsid")
        dom_node = dom if (dom and dom in g) else (single_domain if single_domain else None)
        if dom_node is None:
            return None
        da = dom_node + "-512"  # Domain Admins well-known RID
        return da if da in g else dom_node

    published: set = set()
    for ca in cas.values():
        published.update(ca.get("enabled_templates", []) or [])

    added = 0

    def esc(principal: str, target: str, kind: str) -> None:
        nonlocal added
        if target and _add_edge(g, principal, target, kind):
            added += 1

    for ca_id, ca in cas.items():
        props = ca.get("props", {}) or {}
        target = target_for(props)
        if target is None:
            continue

        san_enabled = _truthy(props.get("isuserspecifiessanenabled"))
        web_vuln = _truthy(props.get("hasenrollmentendpoint")) and not _truthy(
            props.get("hashttpsendpointwithchannelbinding")
        )

        # ESC7: ManageCA / ManageCertificates on the CA.
        for p in _principals_with(g, ca_id, {"manageca", "managecertificates"}):
            esc(p, target, "ADCSESC7")

        # ESC5: control of the CA object or its hosting computer.
        for p in _principals_with(g, ca_id, CA_CONTROL_RIGHTS):
            esc(p, target, "ADCSESC5")
        hc = ca.get("hosting_computer")
        if hc:
            for p in _principals_with(g, hc, HOST_CONTROL_RIGHTS):
                esc(p, target, "ADCSESC5")

        # ESC8: coerce + NTLM relay to a vulnerable web-enrollment endpoint.
        if web_vuln and WELL_KNOWN_AUTHENTICATED_USERS in g:
            esc(WELL_KNOWN_AUTHENTICATED_USERS, target, "ADCSESC8")

        agent_templates: list = []
        has_auth_template = False
        for tid in ca.get("enabled_templates", []) or []:
            node = g.nodes.get(tid)
            if node is None or node.get("type") != "CertTemplate":
                continue
            tp = node.get("props", {}) or {}
            approval = _truthy(tp.get("requiresmanagerapproval"))
            ra_sigs = _as_int(tp.get("authorizedsignatures"), 0)
            ekus = _ekus(tp)
            auth = (
                _truthy(tp.get("authenticationenabled"))
                or bool(ekus & AUTH_EKUS)
                or len(ekus) == 0
            )
            supplies_san = _truthy(tp.get("enrolleesuppliessubject"))
            any_purpose = ANY_PURPOSE_EKU in ekus or len(ekus) == 0
            agent = ENROLLMENT_AGENT_EKU in ekus
            no_sec_ext = _truthy(tp.get("nosecurityextension"))
            schannel = _truthy(tp.get("schannelauthenticationenabled"))
            enrollers = _principals_with(g, tid, ENROLL_RIGHTS)

            if approval or ra_sigs > 0:
                continue  # manager approval / RA signatures block the easy abuse
            if auth and supplies_san:
                for p in enrollers:
                    esc(p, target, "ADCSESC1")
            if any_purpose:
                for p in enrollers:
                    esc(p, target, "ADCSESC2")
            if san_enabled and auth:
                for p in enrollers:
                    esc(p, target, "ADCSESC6")
            # ESC9: no-security-extension auth template - enrol as a victim whose
            # UPN was rewritten (the write-over-victim step is a fail-safe
            # assumption; the missing security extension is the positive signal).
            if auth and no_sec_ext:
                for p in enrollers:
                    esc(p, target, "ADCSESC9a")
            # ESC10 (Schannel variant): a schannel-auth template maps a cert to an
            # account via weak DC binding. The DC registry posture
            # (CertificateMappingMethods) is not in BloodHound's collection, so
            # this fires on the template signal alone and over-reports (fail safe).
            if auth and schannel:
                for p in enrollers:
                    esc(p, target, "ADCSESC10b")
            if agent:
                agent_templates.append(enrollers)
            if auth:
                has_auth_template = True

        # ESC3: enrol on an enrollment-agent template, then enrol-on-behalf-of
        # against an authentication template published on the same CA.
        if agent_templates and has_auth_template:
            for enrollers in agent_templates:
                for p in enrollers:
                    esc(p, target, "ADCSESC3")

    # ESC4: dangerous control over a *published* template can be reshaped into
    # an ESC1 posture (add client-auth EKU + enrollee-supplies-subject).
    for tid, node in templates.items():
        if tid not in published:
            continue
        target = target_for(node.get("props", {}) or {})
        if target is None:
            continue
        for p in _principals_with(g, tid, TEMPLATE_CONTROL_RIGHTS):
            esc(p, target, "ADCSESC4")

    # ESC13: a template that asserts an issuance-policy OID which is linked to a
    # group (msDS-OIDToGroupLink) grants its enrollers membership in that group -
    # so the escalation target is the linked group, not Domain Admins.
    policy_group: dict = {}
    for _pid, pd in g.nodes(data=True):
        if pd.get("type") != "IssuancePolicy" or not pd.get("oid_group_link"):
            continue
        pp = pd.get("props", {}) or {}
        for oidval in (pp.get("certtemplateoid"), pp.get("oid"), pp.get("name")):
            if oidval:
                policy_group[str(oidval).strip().lower()] = pd["oid_group_link"]
    if policy_group:
        for tid, node in templates.items():
            if tid not in published:
                continue
            tp = node.get("props", {}) or {}
            asserted = tp.get("issuancepolicies") or tp.get("certificatepolicy") or []
            if isinstance(asserted, str):
                asserted = [asserted]
            for oidval in asserted:
                grp = policy_group.get(str(oidval).strip().lower())
                if grp and grp in g:
                    for p in _principals_with(g, tid, ENROLL_RIGHTS):
                        esc(p, grp, "ADCSESC13")

    return added
