# Azure / Entra ID coverage

NoiseHound scores Entra ID (Azure AD) attack paths the same way it scores on-prem
AD: a corpus of `AZ*` edges, each mapped to its detection surface and a noise
score, re-solved for the quietest route to an objective (e.g. **Global
Administrator**). Because ingestion reads edge types generically, **Azure data
collected into BloodHound CE with AzureHound is scored automatically** once the
`AZ*` edges exist in the corpus.

```bash
# Collect with AzureHound -> import to BloodHound CE -> export or read over Bolt:
noisehound -i azure_export.zip -s "analyst@contoso.onmicrosoft.com" -o "Global Administrator"
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

Entra sources use activity **names** (in `detail`), not numeric event IDs, so
`event_id` is `null` for them.

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

- **AzureHound-native ingestion** of the raw collector JSON (today Azure comes in
  via BloodHound CE).
- **Entra posture profiles** - environment flags (`mdca`, `entra_id_protection`,
  `sentinel`) that raise the alert-tier edges, like the on-prem posture flags do.
- **Hybrid edges** (Entra Connect / PHS-PTA / seamless SSO) so **Defender for
  Identity** contributes across the on-prem/cloud boundary.
- **Calibration in a lab tenant** - measure what actually fires (MDCA/ID
  Protection/Sentinel) for a measured Azure tier, the way the on-prem tiers were done.
- **More edges** - Key Vault, Automation/Logic Apps, dynamic-group abuse,
  cross-tenant / B2B, the rest of the AzureHound schema.
