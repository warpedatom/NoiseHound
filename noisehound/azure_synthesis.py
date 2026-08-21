"""Azure directory-role post-processing synthesis.

AzureHound's raw collection only carries structural facts (who holds which
directory role, group membership, ownership). BloodHound's backend derives
the actually-scored escalation edges from those facts at ingest time -
`AZGlobalAdmin`, `AZPrivilegedRoleAdmin`, `AZAddMembers`, `AZAddSecret`, and
`AZResetPassword` never appear in raw AzureHound output at all. Native ingest
(`azure_ingest.py`) alone therefore scores almost nothing the current 13-edge
corpus is calibrated against - this module closes that gap, mirroring how
`adcs.py` closes the equivalent ADCS ESC1-8 gap for SharpHound.

Grounded against BloodHound's `packages/go/analysis/azure/post.go` (role sets
and target rules) and `graphschema/azure` (role-template GUIDs), sourced via
the 2026-08-16 AzureHound-native-ingest recon - see
`docs/AZUREHOUND_NATIVE_INGEST.md`. Not independently re-verified against the
BloodHound source by this module's author; treat the exact target-eligibility
rules as recon-sourced, not first-hand-confirmed.

Known simplifications (documented; fail safe toward showing more paths, same
convention as adcs.py):
- `AZAddMembers`'s "non-role-assignable groups only" distinction (for the
  Groups/User/Intune-tier roles) is not applied - the `isAssignableToRole`
  group property was not sampled by the recon, so this over-reports those
  roles against all groups rather than risk an unconfirmed property name.
- `PartnerTier2Support` and `KnowledgeAdministrator` (both mentioned in the
  recon's qualitative descriptions but without a sourced role-template GUID)
  are not synthesised - no GUID to match on rather than guessing one.
- `AZUserAccessAdministrator` is intentionally NOT synthesised here - the
  recon found it is not in `post.go` at all; it's an Azure RBAC resource-plane
  edge that `azure_ingest.py`'s resource-role handler already emits directly
  from the `*UserAccessAdmin` collectors.
"""
from __future__ import annotations

import networkx as nx

from .ingest import _add_edge

# Entra directory role-template GUIDs (stable, tenant-independent), from
# BloodHound's graphschema/azure role constants via the recon.
ROLE_GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
ROLE_PRIVILEGED_ROLE_ADMIN = "e8611ab8-c189-46e8-94e1-60213ab1f814"
ROLE_PRIVILEGED_AUTH_ADMIN = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
ROLE_USER_ADMIN = "fe930be7-5e62-47db-91af-98c3a49a38b1"
ROLE_HELPDESK_ADMIN = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
ROLE_AUTH_ADMIN = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
ROLE_PASSWORD_ADMIN = "966707d0-3269-4727-9be2-8c3a10f19b9d"
ROLE_GROUPS_ADMIN = "fdd7a751-b60b-444a-984c-02652fe8fa1c"
ROLE_APP_ADMIN = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
ROLE_CLOUD_APP_ADMIN = "158c047a-c907-4556-b7ef-446551a6b5f7"
ROLE_INTUNE_ADMIN = "3a2c62db-5318-420d-8d74-23affee5d9d5"

# The full set of roles this module reasons about, for the "non-admin" target
# pool in AZResetPassword (a user holding none of these is a plain target).
_ALL_NAMED_ROLES = {
    ROLE_GLOBAL_ADMIN, ROLE_PRIVILEGED_ROLE_ADMIN, ROLE_PRIVILEGED_AUTH_ADMIN,
    ROLE_USER_ADMIN, ROLE_HELPDESK_ADMIN, ROLE_AUTH_ADMIN, ROLE_PASSWORD_ADMIN,
    ROLE_GROUPS_ADMIN, ROLE_APP_ADMIN, ROLE_CLOUD_APP_ADMIN, ROLE_INTUNE_ADMIN,
}


def _role_holders(g: nx.DiGraph, template_id: str) -> set:
    """Principals with AZHasRole -> a role node whose templateId matches."""
    roles = {
        oid for oid, d in g.nodes(data=True)
        if d.get("type") == "AZRole"
        and str((d.get("props") or {}).get("templateId", "")).lower() == template_id
    }
    holders: set = set()
    for role in roles:
        for src, _, ed in g.in_edges(role, data=True):
            if "AZHasRole" in (ed.get("edge_types") or []):
                holders.add(src)
    return holders


def synthesize_azure(g: nx.DiGraph) -> int:
    """Add the post-processed AZ* escalation edges. Returns edges added."""
    if not any(d.get("type") == "AZRole" for _, d in g.nodes(data=True)):
        return 0

    added = 0

    def draw(src: str, dst: str, kind: str) -> None:
        nonlocal added
        if not src or not dst or src == dst:
            return
        existing = g.get_edge_data(src, dst)
        before = existing["edge_types"][:] if existing else []
        _add_edge(g, src, dst, kind)
        after = g.get_edge_data(src, dst)["edge_types"]
        if len(after) > len(before):
            added += 1

    tenant = next((oid for oid, d in g.nodes(data=True) if d.get("type") == "AZTenant"), None)
    all_users = {oid for oid, d in g.nodes(data=True) if d.get("type") == "AZUser"}
    all_groups = {oid for oid, d in g.nodes(data=True) if d.get("type") == "AZGroup"}
    all_apps_sps = {oid for oid, d in g.nodes(data=True) if d.get("type") in ("AZApp", "AZServicePrincipal")}

    ga = _role_holders(g, ROLE_GLOBAL_ADMIN)
    pra = _role_holders(g, ROLE_PRIVILEGED_ROLE_ADMIN)
    priv_auth = _role_holders(g, ROLE_PRIVILEGED_AUTH_ADMIN)
    user_admin = _role_holders(g, ROLE_USER_ADMIN)
    helpdesk = _role_holders(g, ROLE_HELPDESK_ADMIN)
    auth_admin = _role_holders(g, ROLE_AUTH_ADMIN)
    pwd_admin = _role_holders(g, ROLE_PASSWORD_ADMIN)
    groups_admin = _role_holders(g, ROLE_GROUPS_ADMIN)
    app_admin = _role_holders(g, ROLE_APP_ADMIN)
    cloud_app_admin = _role_holders(g, ROLE_CLOUD_APP_ADMIN)
    intune_admin = _role_holders(g, ROLE_INTUNE_ADMIN)

    # AZGlobalAdmin / AZPrivilegedRoleAdmin: role holder -> tenant.
    if tenant:
        for p in ga:
            draw(p, tenant, "AZGlobalAdmin")
        for p in pra:
            draw(p, tenant, "AZPrivilegedRoleAdmin")

    # AZAddMembers: GA/PRA -> all groups; Groups/User/Intune admin -> all groups
    # too (the real rule restricts the second tier to non-role-assignable
    # groups only; not applied here - see module docstring).
    add_members_holders = ga | pra | groups_admin | user_admin | intune_admin
    for p in add_members_holders:
        for grp in all_groups:
            draw(p, grp, "AZAddMembers")

    # AZAddSecret: App Admin or Cloud App Admin -> every app + service principal.
    addsecret_holders = app_admin | cloud_app_admin
    for p in addsecret_holders:
        for t in all_apps_sps:
            draw(p, t, "AZAddSecret")

    # AZResetPassword: tiered so a lower-priv role can't reset a higher-priv
    # target. "non-admin" = holds none of the 11 named roles this module knows.
    non_admin_users = all_users - (ga | pra | priv_auth | user_admin | helpdesk
                                    | auth_admin | pwd_admin | groups_admin
                                    | app_admin | cloud_app_admin | intune_admin)
    for p in (ga | priv_auth):
        for u in all_users:
            draw(p, u, "AZResetPassword")
    for p in user_admin:
        for u in (user_admin | helpdesk | pwd_admin | groups_admin | non_admin_users):
            draw(p, u, "AZResetPassword")
    for p in helpdesk:
        for u in (helpdesk | pwd_admin | non_admin_users):
            draw(p, u, "AZResetPassword")
    for p in auth_admin:
        for u in (auth_admin | pwd_admin | non_admin_users):
            draw(p, u, "AZResetPassword")
    for p in pwd_admin:
        for u in (pwd_admin | non_admin_users):
            draw(p, u, "AZResetPassword")

    return added
