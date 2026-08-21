# AzureHound-native ingest

Reads `azurehound list -o` output directly - no BloodHound CE required as an
intermediary for Azure/Entra data. Implemented as two phases, mirroring how
`adcs.py` handles the equivalent ADCS ESC gap for SharpHound:

- **Phase 1** (`azure_ingest.py`) - raw ingest: nodes and the structural edges
  AzureHound's own collectors emit (`AZHasRole`, `AZMemberOf`, `AZOwns`, plus
  the resource-plane `AZ*Contributor`/`AZ*UserAccessAdmin` collectors).
- **Phase 2** (`azure_synthesis.py`) - post-processing synthesis: derives the
  edges BloodHound's *backend* computes and that raw AzureHound output never
  carries (`AZGlobalAdmin`, `AZPrivilegedRoleAdmin`, `AZAddMembers`,
  `AZAddSecret`, `AZResetPassword`), from `AZHasRole` + directory role-template
  matching.

`ingest.py` detects the format automatically (`meta.type == "azure"`) and runs
both phases; `load_graph()` works the same way for a BHCE zip, a normalised
fixture, or a raw `azurehound list -o` file.

## Why both phases matter (grounded finding, not a hypothesis)

Confirmed against a real `azurehound v3.1.0-rc1 list -o` collection (DreadHost
tenant, 2026-08-16 recon - see `samples/azurehound_native.example.json` for
the trimmed real records): **only 4 of the current 13 corpus `AZ*` edges are
in raw AzureHound output at all** (`AZHasRole`, `AZRunsAs`, `AZVMContributor`,
`AZOwns`). The other 9 - most of what the corpus is calibrated against - are
computed by BloodHound's backend from directory-role holdings and never appear
in the raw collection. Phase 1 alone would silently score almost nothing;
the same shape of gap the live-Bolt fix closed for ADCS.

## Schema grounding

- **Wrapper**: a single envelope, `{"meta": {"type": "azure", ...}, "data":
  [{"kind": "<Kind>", "data": {...}}, ...]}` - each element carries its own
  `kind`; this is the on-disk `list -o` file shape, *not* the streaming
  `IngestRequest{Meta,Data}` wrapper AzureHound's source docs describe (an
  early source-only inference in this doc's history got that wrong - the real
  collection run corrected it).
- **IDs are UPPERCASED** on output.
- **Directory-plane edges** (`AZRoleAssignment`, `AZGroupMember`, ...): a flat
  `principalId`/`member.id` reference.
- **Resource-plane edges** (`AZ*Owner`/`AZ*Contributor`/`AZ*UserAccessAdmin`
  on ARM resources) use a **different, ARM-nested shape** -
  `<role>s[].<role>.properties.principalId`, container id `/SUBSCRIPTIONS/...`
  etc. - confirmed by adding a real subscription to the recon tenant and
  re-collecting. A naive single handler for both would silently miss the
  resource plane.
- **Role-template GUIDs** (Global Administrator, Application Administrator,
  ...) are stable, tenant-independent Entra constants - sourced from
  BloodHound's `graphschema/azure` via the recon, not guessed.

Full sourcing, the per-collector data shapes, and the `post.go` resolution
logic per edge are in the 2026-08-19/20 recon (`RECON_REPORT.md`, folded into
this implementation) - see the module docstrings in `azure_ingest.py` /
`azure_synthesis.py` for the exact citations kept alongside the code.

## Known gaps / simplifications (documented in the code, repeated here for visibility)

- **`AZAddMembers`'s "non-role-assignable groups only" restriction is not
  applied.** The `isAssignableToRole` group property wasn't in the recon
  sample; the affected roles (Groups/User/Intune Administrator) currently
  target *all* groups rather than risk an unconfirmed property name. Fail-safe
  over-report, same convention as ESC9a/10b.
- **`PartnerTier2Support` and `KnowledgeAdministrator`** (mentioned
  qualitatively in `post.go`'s target rules) have no sourced role-template
  GUID and are not synthesised.
- **`AZUserAccessAdministrator` is intentionally not in phase-2 synthesis** -
  the recon found it's not in `post.go` at all; it's an Azure RBAC
  resource-plane edge that phase-1's resource-role handler already emits
  directly from the `*UserAccessAdmin` collectors.
- **`AZRunsAs`'s exact collector/data shape was never resolved** - not
  synthesised or ingested; a real gap, not a guess.
- Directory-plane `*Owner` collectors' populated entry shape (vs. the
  confirmed resource-plane nesting) wasn't in the recon sample (both examples
  collected were `owners: null`) - assumed flat, with a fallback to the
  resource-plane shape. Unconfirmed against real populated data.
- Resource-plane container-id field names beyond `subscriptionId` (confirmed)
  and `virtualMachineId` (confirmed via source) follow the same naming
  convention by inference, not individually real-sampled.

## Status

Built and tested (`test_azure_ingest_real_sample_grounds_phase1_and_phase2`
against the real trimmed fixture; `test_azure_synthesis_addmembers_addsecret_resetpassword`
against a synthetic fixture covering the tiering logic the real sample doesn't
reach). Not yet validated against a full, non-trimmed real collection or a
second tenant - the gaps above are exactly where that would matter most.
