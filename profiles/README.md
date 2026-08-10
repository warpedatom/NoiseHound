# Measured calibration profiles

These are **lab-measured** environment profiles - the calibrated counterpart to
the corpus's expert estimates. Pass one with `-e`:

```bash
noisehound -i export.zip -s alice -o "Domain Admins" -e profiles/vulnad-hyperv-audit.json
```

Each `adjustments` value is an edge's noise score as **measured** on the lab
(detections / runs blended with the corpus prior via `noisehound-calibrate`'s
shrinkage estimator), not estimated. Applying a profile changes real path
rankings - e.g. on the bundled sample the audit profile flips the quietest path
from a 4-hop session-hijack chain to a 1-hop ADCS ESC1 (see `docs/VALIDATION.md`).

## The three tiers

| Profile | Tier | Edges | What it models |
|---------|------|-------|----------------|
| `vulnad-hyperv-audit.json`   | Audit only | 30 | Full DC audit policy + Sysmon, no EDR. Tool-agnostic technique signals (4662/4769/5136/4886...). |
| `vulnad-hyperv-edr.json`     | Alert / EDR | 30 | Above + a Microsoft Defender for Endpoint severity pass on edges that raised named alerts. |
| `vulnad-hyperv-elastic.json` | Elastic SIEM | 10 | Open/free Elasticsearch + Kibana with prebuilt rules. Caught SQLAdmin (64) and DCSync (85) at HIGH - free rules matching/beating the commercial EDR. |

## How they were measured

A Hyper-V Vulnerable-AD range: Server 2022 DC (`sevenkingdoms.local`) + a member
server, full auditing + Sysmon, objects/SACLs built by the `lab/` scripts. Each
edge's abuse was run 4x in a clean window; detections were auto-counted from the
Security/System/Sysmon logs by `lab/Invoke-NoiseHoundCalibration.ps1`, then
scored by `noisehound-calibrate`. Full methodology: `docs/CALIBRATION.md`,
`docs/ELASTIC_TIER.md`, `docs/TOOLING_AXIS.md`.

## Honest scope + caveats

- **30 of 57 corpus edges** are measured (the DC-local + lateral subset a single
  DC + member server exposes). The rest still carry corpus estimates. Coercion/
  relay, the remaining ADCS ESC2-13, and AllExtendedRights are unmeasured.
- **Single lab.** One audit baseline, one EDR (MDE), one SIEM (Elastic). Treat the
  numbers as a well-grounded reference point, not a universal constant - recalibrate
  for your environment with the harness.
- **EDR tier assumes off-the-shelf tools run on-host** (the noisiest case). Remote/
  native tradecraft (Impacket from Linux, native cmdlets) is far quieter at the
  endpoint for the same edge - the whole point of the audit/identity tier. See
  `docs/TOOLING_AXIS.md`.
- **MDI alert tier is not included here.** MDI *posture* (ISPM) corroborated these
  edges from the directory side, but the runtime alert path was dark on Hyper-V
  (capture-path limitation, not learning-period). A bare-metal/Ludus redo is on the
  roadmap. The EDR profile is the runtime alert-tier deliverable for now.
