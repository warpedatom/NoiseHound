# Azure / Entra ID coverage

NoiseHound scores Entra ID (Azure AD) attack paths the same way it scores on-prem
AD: a corpus of `AZ*` edges, each mapped to its detection surface and a noise
score, re-solved for the quietest route to an objective (e.g. **Global
Administrator**). Two ingest paths: via BloodHound CE (ingestion reads edge
types generically, so **Azure data collected into BHCE with AzureHound is
scored automatically** once the `AZ*` edges exist in the corpus), or
**natively from `azurehound list -o` output directly** - see
`docs/AZUREHOUND_NATIVE_INGEST.md` for the format and what it took to get
right (raw AzureHound output alone under-reports most of the 13-edge starter
set; a synthesis pass recovers the rest, the same shape of gap ADCS ESC9/10/13
closed for SharpHound).

```bash
# Collect with AzureHound -> import to BloodHound CE -> export or read over Bolt:
noisehound -i azure_export.zip -s "analyst@contoso.onmicrosoft.com" -o "Global Administrator"
# or read azurehound's own `list -o` output directly, no BHCE required:
noisehound -i az_out.json -s "analyst@contoso.onmicrosoft.com" -o "Global Administrator"
# or try the bundled synthetic graph:
noisehound -i samples/sample_azure.json -s "analyst@contoso.onmicrosoft.com" -o "Global Administrator"
```

## The model is different from on-prem (and that matters)

On-prem, an edge is often **silent by default** - DCSync's 4662 needs object
auditing (a SACL) that ships OFF, so the noise score turns on *whether auditing is
enabled*. Entra flips this:

> **Entra audit + sign-in logging is default-ON.** Almost every control-plane
> action (add a service-principal credential, assign a role, reset a password,
> add a group member) is **logged** in the tenant. What varies is whether it is
> **alerted** - which depends on Defender for Cloud Apps (MDCA), Entra ID
> Protection, or a SIEM/Sentinel rule.

So Azure edges start from a "you were logged" floor rather than "you were
invisible." The static scores reflect *logged-but-not-necessarily-alerted*;
tenants running MDCA / ID Protection / Sentinel push the loud edges higher (a
future Entra posture profile, below).

## Detection sources (schema)

| Source | What it is |
|--------|------------|
| `entra_audit` | Entra ID audit logs - directory control-plane operations (default-on) |
| `entra_signin` | Entra ID sign-in logs - interactive + service-principal sign-ins |
| `entra_id_protection` | Entra ID Protection risk detections |
| `azure_activity` | Azure Activity / resource-plane (ARM role assignments, VM run-command, Key Vault) |
| `mdca` | Microsoft Defender for Cloud Apps activity/anomaly policies |
| `defender_for_cloud` | Microsoft Defender for Cloud (CSPM + workload protection) - resource-plane **threat alerts** on ARM operations. The alert-tier counterpart to `azure_activity`, the way `entra_id_protection` is to `entra_audit`. Needs the paid Defender plans + an onboarded resource; sits on the resource-plane edges (`AZVMContributor`/`AZUserAccessAdministrator`/`AZRunsAs`). |

Entra sources use activity **names** (in `detail`), not numeric event IDs, so
`event_id` is `null` for them. The directory-plane abuse edges additionally carry
a machine-matchable `activity` list (+ `category`) on their `entra_audit`
telemetry - the exact `activityDisplayName`s their abuse writes to the audit log -
which the measured tier (`noisehound-entra`, below) matches against a real audit
export.

## Measured Azure tier (`noisehound-entra`)

The on-prem tiers are *measured*, not estimated: trigger each abuse in a lab and
count what fired. The same loop works for a lab tenant, with Entra directory
audits standing in for Windows event logs. `noisehound-entra` is the counter:

```bash
# 1. In a lab tenant, trigger the AZ* abuses and record what/when in a manifest
#    (samples/entra_runs.example.json). 2. Export the audit trail:
#    Entra admin center > Monitoring > Audit logs > Download (JSON), or Graph
#    GET /auditLogs/directoryAudits. 3. Count + calibrate:
noisehound-entra -a directoryAudits.json -m entra_runs.json \
    --profile-out profiles/lab-tenant-azure.json
# -> a MEASURED Azure profile; drop it into any scoring run:
noisehound -i azure-export.zip -s analyst@contoso -o "Global Administrator" \
    -e profiles/lab-tenant-azure.json
```

It matches each exercised edge's audit `activity` signature within the run window,
emits `{runs, detections}` observations, and reuses `noisehound-calibrate`'s
shrinkage math. Holding-only edges (`AZHasRole`, `AZOwns`) and resource-plane
edges (`AZUserAccessAdministrator`, `AZVMContributor`, `AZRunsAs`) carry no
directory-audit signature and are reported as *not audit-measurable* rather than
scored from nothing - their noise surfaces through the concrete follow-on abuse
(a secret add / member add) or Azure Activity, not directory audits. Optional
`--risk-detections` (Graph `/identityProtection/riskDetections`) raises matched
edges to the alert tier. See `docs/AZURE_CALIBRATION.md` for the full recipe.

## The starter edge set (14)

- **Roles / privilege escalation:** `AZGlobalAdmin`, `AZPrivilegedRoleAdmin`,
  `AZAppAdmin`, `AZCloudAppAdmin`, `AZUserAccessAdministrator`, `AZHasRole`.
- **App / service-principal credential abuse:** `AZAddSecret`, `AZMGAddSecret`
  (MS Graph app-role), `AZAddOwner`, `AZOwns`.
- **Account / group takeover:** `AZResetPassword`, `AZAddMembers`.
- **Resource-plane execution:** `AZVMContributor` (run-command), `AZRunsAs`
  (managed-identity / SP a resource runs as).

Passive rights (`AZOwns`, `AZHasRole`) score low - the follow-on *action* is what
generates noise, mirroring how `AdminTo` is scored on-prem.

## What's next (roadmap)

- ~~AzureHound-native ingestion~~ - **shipped**, see `docs/AZUREHOUND_NATIVE_INGEST.md`.
  Reads `azurehound list -o` output directly (nodes + raw structural edges,
  plus a post-processing pass for the edges only BHCE's backend used to
  compute). Not yet validated against a full, non-trimmed real collection.
- **Entra posture profiles** - environment flags (`mdca`, `entra_id_protection`,
  `sentinel`) that raise the alert-tier edges, like the on-prem posture flags do.
- **Hybrid edges** (Entra Connect / PHS-PTA / seamless SSO) so **Defender for
  Identity** contributes across the on-prem/cloud boundary.
- **Calibration in a lab tenant** - *tooling shipped* (`noisehound-entra`, above,
  measures the Entra audit tier). Remaining: run it against a live lab tenant to
  produce the first measured `profiles/lab-tenant-azure.json`, and extend the
  counter to the alert tier (ID Protection / Sentinel incidents) beyond the audit
  signal.
- **More edges** - Key Vault, Automation/Logic Apps, dynamic-group abuse,
  cross-tenant / B2B, the rest of the AzureHound schema.
