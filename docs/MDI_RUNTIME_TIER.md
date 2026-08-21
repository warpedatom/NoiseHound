# MDI runtime-alert tier — measured (2026-08-20)

The fourth measured detection tier: **Microsoft Defender for Identity runtime
alerts**. `profiles/vulnad-hyperv-mdi.json`.

## Headline: the "MDI is dark" verdict was a sensor limitation, not the environment

Earlier calibration (v1.0.0) reported MDI's *posture/ISPM* engine working and
corroborating the corpus, but its **runtime alert path dark** on the Hyper-V lab —
even a network DCSync via Impacket produced zero Identity-source alerts. That was
attributed to a capture-path limit and deferred to a bare-metal rebuild.

Re-testing overturned it. The blocker was the **classic MDI sensor** (npcap
deep-packet capture, `AATPSensor` 2.x). Switching to the **new v3 Defender for
Identity sensor** — ETW-based, deployed through the DC's existing Defender for
Endpoint agent (portal → Settings → Identities → On-premises → **Activation** →
*Activate sensor v3.x*) — MDI runtime alerts fire correctly on this same Hyper-V
DC. No bare-metal required. Prerequisite: the DC's OS had to be patched to the new
sensor's baseline (Server 2022 `20348.587` → `20348.5499`); the classic sensor was
removed first (they cannot coexist).

## What fired (measured)

Triggers were run **over the wire from Kali** (Impacket + bloodyAD + Certipy),
Kerberos-authenticated, so this is the tool-agnostic identity tier — not endpoint
signatures.

| NoiseHound edge | MDI alert(s) | Severity | Calibrated |
|---|---|---|---|
| **Kerberoast** | Suspected Kerberos SPN exposure; Possible Kerberoasting attack | High | 52 |
| **ASREPRoast** | AS-REP roasting | High | 52 |
| **AllowedToAct** (RBCD) | Suspicious resource-based constrained delegation | Medium | 54 |

Bonus signals (not core corpus attack edges, so not scored): MDI also raised
**Active Directory reconnaissance** (Medium) on the Certipy LDAP sweep and
**Suspicious Kerberos authentication** (Medium) on the ticket activity.

## What did NOT fire (honest gaps)

- **DCSync** — no MDI Identity alert, because **Defender XDR Attack Disruption
  actively blocked the DRSUAPI replication** (`rpc_s_access_denied`) before MDI's
  replication detection engaged, and raised its own "RPC blocked" disruption
  alerts. Notable in itself: in this posture DCSync is **prevented**, not merely
  detected. Not scored in the MDI tier (no MDI alert), but the loudest possible
  real-world outcome.
- **AddMember** (sensitive-group modification) and **AddKeyCredentialLink**
  (shadow credentials) — no MDI alert. Most likely because each abuse was
  **added and immediately reverted** (a clean-up step, seconds apart); a
  persistent change may alert where a transient one did not. Worth a re-test
  leaving the change in place.
- **ADCS ESC1** (Certipy request with spoofed UPN, cert issued) — no MDI runtime
  alert on the *request* alone. MDI's AD CS detections may key on the certificate
  being *used* for authentication (PKINIT), which the follow-on step did not
  complete here.

## Scope + caveats

- **Single lab, small samples** (1–2 runs/edge): the shrinkage estimator keeps
  Kerberoast/ASREPRoast at 52 rather than the raw 85 high-loudness — a floor, not
  a ceiling. More runs would raise the confidence weight.
- **Overlay tier.** Like the EDR/Elastic tiers, this profile only *raises* the
  edges MDI alerts on; it is not a full re-score. Compose it with the audit tier
  for the tool-agnostic base.
- The AddMember/ShadowCreds transient-vs-persistent question and a leave-it-in-place
  DCSync (Attack Disruption disabled) are the obvious next measurements.

## Reproduce

Runbook: `_lab_prep/MDI_UNIFIED_SENSOR_RUNBOOK.md` (sensor swap + triggers).
Raw observations: `_lab_prep/lab_detections_mdi.json` → `noisehound-calibrate`.
