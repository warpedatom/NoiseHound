"""AzureHound-native ingest: parse `azurehound list -o` output directly.

Unlike the BloodHound-CE zip path, this reads AzureHound's own collector
output without BHCE as an intermediary. Format and field shapes are grounded
against a real `azurehound v3.1.0-rc1 list -o` collection (DreadHost tenant,
2026-08-16), not inferred from source alone - see `docs/AZUREHOUND_NATIVE_INGEST.md`
for the recon and its sourcing. The top-level shape is a single envelope,
distinct from AzureHound's streaming `IngestRequest{Meta,Data}` wrapper:

    {"meta": {"type": "azure", "count": N, ...},
     "data": [{"kind": "<Kind>", "data": {...}}, ...]}

Each element's own `kind` determines whether it produces a graph node or an
edge record - there is no per-node ACE list to derive edges from the way
SharpHound's zip format works; Azure's relationship collectors emit edges
directly. All object ids in AzureHound's output are UPPERCASED.

Known simplifications (documented; most fail safe toward showing more paths,
same convention as adcs.py):
- The directory-plane `*Owner` collectors' populated `owners[]` entry shape
  was not present in the real sample (both examples collected were `owners:
  null`) - only the resource-plane nesting was confirmed with real data.
  Assumed flat `{"id": ...}` entries (AzureHound's general convention
  elsewhere, e.g. `AZAppRoleAssignment.principalId`), with a fallback to the
  resource-plane `{"owner": {...}}` nesting if the flat lookup misses.
- Resource-plane container-id field names beyond `subscriptionId` (confirmed)
  and `virtualMachineId` (confirmed via source, not a live resource) are
  inferred by the same naming convention, not individually real-sampled.
- `AZRunsAs`'s exact collector/data shape was not resolved by the recon -
  intentionally not synthesised here rather than guessed.
- Non-`AZVMContributor` resource-plane Contributor edges (KeyVault,
  StorageAccount, ...) aren't in the current 13-edge corpus, so they're
  ingested under a passthrough edge type but won't score until the corpus
  covers them.
"""
from __future__ import annotations

from typing import Any

import networkx as nx

from .ingest import _add_edge, _add_node

# Collector kinds that map directly to one graph node, keyed by the element's
# own "kind". Node id = data["id"] (already uppercased by AzureHound).
_AZ_NODE_KINDS = {
    "AZTenant", "AZUser", "AZGroup", "AZApp", "AZServicePrincipal", "AZDevice",
    "AZRole", "AZVM", "AZSubscription", "AZResourceGroup", "AZManagementGroup",
    "AZKeyVault", "AZStorageAccount", "AZAutomationAccount", "AZLogicApp",
    "AZFunctionApp", "AZWebApp", "AZManagedCluster", "AZContainerRegistry",
    "AZVMScaleSet",
}

# Node types whose props are retained for phase-2 synthesis (role-template
# matching needs AZRole.templateId).
_AZ_PROPS_RETAINED = {"AZRole", "AZTenant"}

# Resource-plane container-id field per resource-type stem, used by the
# "<Stem>Owner" / "<Stem>Contributor" / "<Stem>UserAccessAdmin" collectors.
# "Subscription" and "VM" are confirmed (recon: real AZSubscriptionOwner data;
# AZVMContributor's nesting confirmed against BloodHound's convertor source).
# The rest follow the same naming convention, unverified against a live resource.
_AZ_RESOURCE_ID_FIELD = {
    "Subscription": "subscriptionId",
    "ResourceGroup": "resourceGroupId",
    "ManagementGroup": "managementGroupId",
    "VM": "virtualMachineId",
    "KeyVault": "keyVaultId",
    "AutomationAccount": "automationAccountId",
    "LogicApp": "logicAppId",
    "FunctionApp": "functionAppId",
    "WebApp": "webAppId",
    "ManagedCluster": "managedClusterId",
    "ContainerRegistry": "containerRegistryId",
    "StorageAccount": "storageAccountId",
}

_NAME_FIELDS = ("displayName", "userPrincipalName", "appDisplayName", "subscriptionId")


def _az_name(data: dict, oid: str) -> str:
    for f in _NAME_FIELDS:
        v = data.get(f)
        if v:
            return str(v).upper()
    return oid


def is_azurehound_doc(doc: Any) -> bool:
    """True for the `azurehound list -o` envelope (distinct from a BHCE export)."""
    return (
        isinstance(doc, dict)
        and isinstance(doc.get("meta"), dict)
        and doc["meta"].get("type") == "azure"
        and isinstance(doc.get("data"), list)
    )


def _add_az_node(g: nx.DiGraph, kind: str, data: dict) -> None:
    oid = data.get("id")
    if not oid:
        return
    _add_node(g, oid, kind, data if kind in _AZ_PROPS_RETAINED else None)
    g.nodes[oid]["name"] = _az_name(data, oid)
    if kind in _AZ_PROPS_RETAINED:
        g.nodes[oid]["props"] = {str(k): v for k, v in data.items()}


def _handle_role_assignment(g: nx.DiGraph, data: dict) -> None:
    """AZRoleAssignment -> AZHasRole (directory-plane role holder -> role)."""
    for ra in data.get("roleAssignments", []) or []:
        principal = ra.get("principalId")
        role = ra.get("roleDefinitionId")
        if principal and role:
            _add_node(g, role, "AZRole")
            _add_edge(g, principal, role, "AZHasRole")


def _handle_group_member(g: nx.DiGraph, data: dict) -> None:
    """AZGroupMember -> AZMemberOf (member -> group)."""
    group = data.get("groupId")
    if not group:
        return
    for m in data.get("members", []) or []:
        member = (m.get("member") or {}).get("id")
        if member:
            _add_edge(g, member, group, "AZMemberOf")


# Directory-plane "<X>Owner" collectors: container id field per stem. Only
# directory object kinds - resource-plane kinds (VM, Subscription, ...) always
# go through the ARM-nested resource-role handler instead, even for "Owner".
_AZ_DIR_OWNER_ID_FIELD = {
    "App": "appId",
    "ServicePrincipal": "servicePrincipalId",
    "Group": "groupId",
}


def _owner_principal_id(entry: Any) -> str | None:
    if not isinstance(entry, dict):
        return None
    if entry.get("id"):  # flat shape (assumed; not real-sampled - see module docstring)
        return entry["id"]
    owner = entry.get("owner")  # resource-plane nested shape, as a fallback
    if isinstance(owner, dict):
        return (owner.get("properties") or {}).get("principalId") or owner.get("id")
    return None


def _handle_directory_owner(g: nx.DiGraph, stem: str, data: dict) -> None:
    field = _AZ_DIR_OWNER_ID_FIELD.get(stem)
    container = data.get(field) if field else None
    if not container:
        return
    for entry in data.get("owners") or []:
        pid = _owner_principal_id(entry)
        if pid:
            _add_edge(g, pid, container, "AZOwns")


def _handle_resource_role(g: nx.DiGraph, stem: str, role_kind: str, data: dict) -> None:
    """"<Stem>Owner" / "<Stem>Contributor" / "<Stem>UserAccessAdmin" resource-plane
    collectors: {"<list_key>": [{"<role_key>": {"properties": {"principalId": ..}}}],
    "<container>Id": ...}."""
    field = _AZ_RESOURCE_ID_FIELD.get(stem)
    container = data.get(field) if field else None
    if not container:
        return
    list_key, role_key, edge_type = {
        "Owner": ("owners", "owner", "AZOwns"),
        "Contributor": ("contributors", "contributor", "AZVMContributor" if stem == "VM" else "AZ%sContributor" % stem),
        "UserAccessAdmin": ("userAccessAdmins", "userAccessAdmin", "AZUserAccessAdministrator"),
    }[role_kind]
    for entry in data.get(list_key) or []:
        role_obj = (entry or {}).get(role_key) or {}
        pid = (role_obj.get("properties") or {}).get("principalId")
        if pid:
            _add_edge(g, pid, container, edge_type)


def _dispatch_edge_kind(g: nx.DiGraph, kind: str, data: dict) -> None:
    if kind == "AZRoleAssignment":
        _handle_role_assignment(g, data)
        return
    if kind == "AZGroupMember":
        _handle_group_member(g, data)
        return
    for role_kind in ("Owner", "Contributor", "UserAccessAdmin"):
        if kind.startswith("AZ") and kind.endswith(role_kind):
            stem = kind[len("AZ"):-len(role_kind)]
            # Resource-plane (ARM-nested) takes priority - Contributor/UserAccessAdmin
            # only exist on the resource plane, and a stem present in both tables
            # (there are none today) would be an ARM resource, not a directory object.
            if stem in _AZ_RESOURCE_ID_FIELD:
                _handle_resource_role(g, stem, role_kind, data)
            elif role_kind == "Owner" and stem in _AZ_DIR_OWNER_ID_FIELD:
                _handle_directory_owner(g, stem, data)
            return
    # AZAppRoleAssignment and other collectors not yet wired feed future corpus
    # expansion (AZMG* family) - silently skipped rather than guessed.


def parse_azurehound_doc(g: nx.DiGraph, doc: dict) -> None:
    """Ingest one `azurehound list -o` envelope into the graph in place."""
    for el in doc.get("data", []) or []:
        kind = el.get("kind")
        data = el.get("data")
        if not kind or not isinstance(data, dict):
            continue
        if kind in _AZ_NODE_KINDS:
            _add_az_node(g, kind, data)
        else:
            _dispatch_edge_kind(g, kind, data)
