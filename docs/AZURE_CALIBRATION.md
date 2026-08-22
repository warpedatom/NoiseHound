# Measured Azure tier - lab-tenant calibration recipe

How to produce the first measured `profiles/lab-tenant-azure.json`, the way the
on-prem tiers were measured. You trigger each `AZ*` abuse in a **throwaway lab
tenant**, export the Entra audit trail, and let `noisehound-entra` count what
fired and `noisehound-calibrate` turn it into a profile.

> Do this only in a lab tenant you own. Every action below is a real directory
> change; none touch a production tenant. NoiseHound never authenticates - you run
> the triggers and the export; the tool only reads the resulting JSON files.

## 0. Prerequisites

- A disposable Entra tenant (e.g. an M365 developer tenant) with a couple of test
  users, a test group, and one app registration + service principal.
- Directory audit logging is **on by default** - no config needed.
- Roles you'll activate: Global Administrator (or Privileged Role Admin) for the
  role/credential edges. Use PIM eligibility if you want the `Add eligible member`
  variant too.

## 1. Trigger each edge and note the time

Run the abuses back to back and record a start/end window (UTC). Each edge maps to
the audit `activityDisplayName` NoiseHound matches (the corpus signature):

| Edge | Lab trigger (example) | Audit activity it writes |
|------|-----------------------|--------------------------|
| `AZGlobalAdmin` / `AZPrivilegedRoleAdmin` | Add a user to the Global Administrator (or another privileged) role; or PIM-activate | `Add member to role`, `Add eligible member to role` |
| `AZAddMembers` | Add a member to a group (`New-MgGroupMember`) | `Add member to group` |
| `AZAddSecret` / `AZMGAddSecret` | Add a client secret/cert to a service principal (`Add-MgServicePrincipalPassword`) | `Add service principal credentials` |
| `AZAppAdmin` / `AZCloudAppAdmin` | Add a secret via the app's Certificates & secrets blade / `Update-MgApplication` | `Add service principal credentials`, `Update application - Certificates and secrets management` |
| `AZAddOwner` | Add an owner to an app or service principal | `Add owner to application`, `Add owner to service principal` |
| `AZResetPassword` | Admin-reset a test user's password (`Reset-MgUserAuthenticationMethodPassword`) | `Reset password (by admin)`, `Reset user password` |

Edges **not** measured by directory audits (declare them in the manifest if you
like - they'll be reported as not-measurable, not scored from nothing):

- `AZHasRole`, `AZOwns` - holding a role/ownership logs nothing; the follow-on
  abuse (a secret/member add) is what records, and is already covered above.
- `AZUserAccessAdministrator`, `AZVMContributor`, `AZRunsAs` - resource-plane
  (ARM). These surface in **Azure Activity logs**, a separate export; a future
  `azure_activity` counter will measure them.

## 2. Export the audit trail

- **Portal:** Entra admin center → **Monitoring & health → Audit logs** → set the
  date filter to your window → **Download → JSON**.
- **Graph:** `GET https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=activityDateTime ge <start>` (save the whole response; the tool reads `value[]`).
- *(Optional, alert tier)* `GET /identityProtection/riskDetections` → pass with `--risk-detections`.

## 3. Write the run manifest

Copy `samples/entra_runs.example.json` and fill in the edges you exercised, the
run count, and the window:

```json
{
  "environment": "lab-tenant-azure",
  "observations": [
    {"edge_type": "AZGlobalAdmin", "runs": 3, "start": "2026-08-20T00:00:00Z", "end": "2026-08-20T00:30:00Z"},
    {"edge_type": "AZAddSecret",   "runs": 3, "start": "2026-08-20T00:30:00Z", "end": "2026-08-20T01:00:00Z"}
  ]
}
```

`runs` is how many times you performed the abuse; `detections` is derived (matching
audit records in-window, capped at `runs`), so a partial rate is honest about
records that didn't land.

## 4. Count and calibrate

```bash
noisehound-entra -a directoryAudits.json -m entra_runs.json \
    --out lab_detections_azure.json \
    --profile-out profiles/lab-tenant-azure.json
```

- `lab_detections_azure.json` is the observations file (same shape as the on-prem
  `lab_detections.json`) - keep it as evidence.
- `profiles/lab-tenant-azure.json` is the measured profile. Sanity-check it, then
  score with it:

```bash
noisehound -i azure-export.zip -s analyst@contoso -o "Global Administrator" \
    -e profiles/lab-tenant-azure.json
```

## 5. What "measured" means here (honest scope)

The Entra **audit** signal is nearly always on, so most directory-plane edges will
measure as *logged* (high detection rate) - that is the point: in the cloud the
control-plane is well-instrumented by default, unlike on-prem where auditing is
frequently off. The interesting deltas are (a) edges whose abuse is **not** logged
by default (resource-plane), and (b) the **alert** tier - whether ID Protection /
Sentinel actually *raised* something, not just logged it. Treat the first audit
profile as the "logged" floor and layer the alert tier on top as you collect
`riskDetections` / Sentinel incidents.
