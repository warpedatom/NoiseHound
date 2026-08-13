# AzureHound-native ingest - scoping

`docs/AZURE.md` currently claims Azure data is "scored automatically" once it
reaches NoiseHound. That's true only for the synthetic flat-graph fixture
(`samples/sample_azure.json`, `{"nodes": [...], "edges": [...]}`). The real
BloodHound-zip parser (`ingest.py:_BH_TYPE_BY_META`) has **no Azure entries at
all** - any Azure node in a real BHCE export currently falls through to the
generic `"Base"` type. There is no verified ingest path for real Azure data
yet, native or via BHCE. This doc scopes closing that gap.

## What we know from AzureHound's public source (ungrounded - see below)

AzureHound's raw output wraps records the same way SharpHound does:

```go
type IngestRequest struct {
    Meta Meta        `json:"meta"`   // {Type, Version, Count}
    Data interface{} `json:"data"`
}
```

That's the same `{"meta": {"type", ...}, "data": [...]}` shape
`_parse_bh_file` already dispatches on - the extension point is adding Azure
`meta.type` strings to `_BH_TYPE_BY_META`, not a new parser.

Node kinds (a sample of the ~50+): `AZUser`, `AZGroup`, `AZServicePrincipal`,
`AZApp`, `AZDevice`, `AZTenant`, `AZRole`, `AZKeyVault`, `AZVM`,
`AZSubscription`, `AZResourceGroup`, `AZManagementGroup`, `AZAutomationAccount`,
`AZLogicApp`, `AZFunctionApp`, `AZWebApp`, `AZManagedCluster`,
`AZStorageAccount`, `AZContainerRegistry`.

Unlike on-prem (control edges derived from ACEs embedded on the target node),
Azure edges arrive as their **own typed records** - `AZMemberOf`, `AZOwner`,
`AZHasRole`, `AZRunsAs`, `AZContains`, `AZContributor`, `AZGetSecrets`,
`AZGetKeys`, `AZGetCertificates`, `AZVMContributor`, `AZAvereContributor` -
each presumably `{source, target, ...}` in `Data`, not a node.

## The real finding: raw collection != what the corpus scores

AzureHound's Kind list splits cleanly into two groups, and the split matters:

**Raw / collection-time** (present in AzureHound's own output): `AZHasRole`,
`AZMemberOf`, `AZOwner`, `AZRunsAs`, `AZContains`, `AZContributor`,
`AZGetSecrets`, `AZGetKeys`, `AZGetCertificates`, `AZVMContributor`,
`AZAvereContributor`.

**Post-processed** (BloodHound's backend computes these from the raw edges -
explicitly labelled "Post-processed relationships" in AzureHound's source):
`AZGlobalAdmin`, `AZPrivilegedRoleAdmin`, `AZAddMembers`, `AZAddSecret`,
`AZExecuteCommand`, `AZGrant`, `AZGrantSelf`, `AZResetPassword`,
`AZUserAccessAdministrator`.

The current 13-edge starter set (`docs/AZURE.md`) is mostly the **second**
group. This is the same shape of gap the Bolt-ingest fix
(`neo4j_ingest.py`, landed alongside ESC9/10/13) just closed for ADCS: BHCE's
post-processing computes edges that raw collection doesn't carry, and a
"native ingest" path that skips BHCE entirely will silently under-report most
of what the corpus currently scores, not just miss a nice-to-have.

## What native ingest requires - two phases

1. **Raw ingest**: extend `_BH_TYPE_BY_META` for Azure node kinds; handle
   edge-typed records (`AZMemberOf`/`AZOwner`/`AZHasRole`/`AZRunsAs`/...)
   directly rather than deriving them from a node's `Aces`, since Azure's
   collection model doesn't embed ACEs on target nodes the way SharpHound does.
2. **Azure post-processing synthesis** (new `noisehound/azure_synthesis.py`,
   same shape as `adcs.py`): reimplement the role/membership resolution
   BloodHound's backend performs, to recover `AZGlobalAdmin` /
   `AZPrivilegedRoleAdmin` / `AZAddMembers` / `AZAddSecret` / `AZResetPassword`
   / `AZUserAccessAdministrator` from the raw structural edges. Without this,
   phase 1 alone ingests real data but scores almost nothing the current
   corpus edges are calibrated against.

## Grounding gap

Everything above comes from AzureHound's public Go source (`pkg.go.dev`,
`github.com/SpecterOps/AzureHound`), not a real collection - unlike the
ESC9/10/13 work, which was grounded against the real `sevenkingdoms` SharpHound
JSON before any code was written. Needed before writing ingest code:

- A real AzureHound raw output file (`azurehound list ... -o out.json` against
  a lab/dev tenant), to confirm exact `meta.type` strings and the `Data` shape
  for a representative node kind and a representative edge kind.
- The same tenant imported into BHCE, to diff raw AzureHound output against
  BHCE's post-processed graph and confirm exactly which of the 13 starter
  edges are backend-computed vs. already present raw (the source-level split
  above is a starting hypothesis, not confirmed against real data).
- If a real tenant isn't available, the fallback is reading AzureHound's
  actual Go source for the post-processing analysis logic (SpecterOps/BloodHound
  `cmd/api/src/analysis/azure` or similar) rather than guessing the resolution
  rules from edge names alone.

## Roadmap status

Not started. Blocked on grounding data above. Unblocks fully once batch 1's
Azure foundation (13 AZ* edges, corpus, `sample_azure.json`) is merged, since
this phase replaces the ingest side while reusing that corpus work unchanged.
