# Calibrating NoiseHound: lab build + measurement playbook

The corpus ships expert-estimated noise scores. This guide walks through
standing up a detection lab, exercising each BloodHound edge, recording what
fires, and feeding the results to `noisehound-calibrate` to produce a measured
environment profile.

> Lab only. Everything here runs against an isolated, disposable AD you own.
> Never point these techniques at production or any system you are not
> explicitly authorized to test.

---

## 0. Approach: which lab, and why

Two ways to generate calibration data. They are complementary:

- **Edge-exercise lab (recommended for coverage).** Directly run the abuse
  primitive for each corpus edge and record the telemetry. This is the only way
  to calibrate *all* 43 edges, because a single adversary emulation only touches
  a handful of them. The corpus itself is your runbook - every entry already
  carries `abuse_primitive` (what to run) and `telemetry` (what to watch).
- **APT29 adversary emulation (realistic subset).** MITRE's APT29 plan, run via
  Caldera, exercises a believable kill chain end to end and is great for
  validating that your *detections* work under realistic conditions. It covers a
  subset of edges well (DCSync, credential access, some lateral movement) and
  leaves most ACL/ADCS/delegation edges untouched.

Do the edge-exercise pass for breadth; layer APT29 on top for a realism check.
Both feed the same `lab_detections.json`.

Generate your worksheet listing every edge to test:

```bash
noisehound-calibrate --template -o lab_detections.json
```

---

## 1. Lab topology

A minimal but representative single-forest lab:

| Host | Role | Notes |
|------|------|-------|
| `DC01` | Domain controller, DNS | Where most AD auditing and MDI live |
| `CA01` | AD CS enterprise CA | Needed for the ADCS ESC edges |
| `WS01`, `WS02` | Domain-joined workstations | For sessions, AdminTo, lateral movement |
| `ATTACK` | Kali/CObalt Strike/operator box | Runs the abuse tooling |

Seed the domain so the edges actually exist to exercise:

- Tiered accounts: a low-priv user, a helpdesk group, service accounts with
  SPNs (Kerberoast), an account without pre-auth (AS-REP), a Domain Admin.
- ACL misconfigurations: grant a test principal `GenericAll` / `GenericWrite` /
  `WriteDacl` / `ForceChangePassword` / `AddKeyCredentialLink` over other
  objects (PowerView `Add-DomainObjectAcl` makes this quick).
- Sessions: log a privileged user onto `WS01` so a `HasSession` edge exists.
- Delegation: configure one constrained-delegation and one RBCD scenario.
- AD CS: publish a deliberately vulnerable template (ESC1: enrollee supplies
  subject + client-auth EKU, no manager approval) and, separately, enable
  `EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA (ESC6) and web enrollment (ESC8).

Run SharpHound/BOFHound afterwards so you have a BloodHound export that NoiseHound
can path over while you calibrate.

---

## 2. Detection instrumentation

Calibration is only meaningful if the lab can actually *see* the techniques.
Turn on the telemetry the corpus references.

### 2.1 Windows advanced audit policy (the event IDs the corpus keys off)

Enable via GPO (`Computer Config > Policies > Windows Settings > Security
Settings > Advanced Audit Policy`) or `auditpol`. The high-value subcategories:

| Subcategory | Key event IDs | Edges it lights up |
|-------------|---------------|--------------------|
| DS Access > Directory Service Access | 4662 | DCSync, LAPS/gMSA reads, extended-right abuse |
| DS Access > Directory Service Changes | 5136, 5137 | WriteDacl, RBCD, shadow creds, WriteGPLink |
| Account Management > User/Security Group | 4720, 4724, 4728/4732/4756, 4738, 4765 | password reset, group add, UAC, SID history |
| Logon/Logoff > Logon | 4624, 4648 | lateral movement, RDP (type 10), make_token |
| Account Logon > Kerberos | 4768, 4769, 4771 | Kerberoast, AS-REP, delegation, PKINIT |
| Account Logon > Credential Validation | 4776 | NTLM / PtH |
| System > Security System Extension | 7045 | service creation (PsExec) |

Critically, **DS Access auditing is OFF by default** - that is exactly why the
corpus marks those signals `high_if_auditing_enabled`. Calibrate once with it
off (matches most real targets) and once with it on, and keep both profiles.

### 2.2 Sysmon

Deploy Sysmon with a maintained config (SwiftOnSecurity or Olaf Hartong's
modular config) on every host. Confirm you are capturing:

- **1** process create, **3** network connect, **7** image load,
  **8** CreateRemoteThread, **10** process access (LSASS!), **11** file create,
  **12/13** registry, **17/18** named pipe.

Sysmon 10 (LSASS access) is the high-fidelity signal behind `HasSession`'s loud
variant - make sure it is on before you score credential dumping.

### 2.3 EDR / ITDR (optional but high-value)

- **Microsoft Defender for Identity (MDI)** sensor on `DC01` gives you the
  identity-layer detections (DCSync, shadow creds, delegation abuse) that the
  corpus attributes to `product_class: MDI`. If you calibrate with MDI present,
  set `"edr": "MDI"` in the profile header.
- **Defender for Endpoint** (or any EDR) on the hosts for the host-based
  behavioural detections.

### 2.4 Getting at the results

You do not need a full SIEM. Options, easiest first: query the Security/Sysmon
logs directly on each host with `Get-WinEvent`; forward everything to one
collector with Windows Event Forwarding; or ship to Elastic/Splunk/Sentinel if
you have it. MDI/MDE alerts show in their respective portals.

---

## 3. Exercising the edges

For each edge in your worksheet, run its abuse primitive N times (N = 3-5 is a
good balance) and record how many runs produced an alert. **The corpus is your
runbook** - `abuse_primitive` tells you what to run and `telemetry` tells you
what to look for:

```bash
python -c "import json; e=json.load(open('edge_mappings/DCSync.json')); \
  print(e['abuse_primitive']); [print(' -', t.get('source'), t.get('event_id'), '-', t['detail']) for t in e['telemetry']]"
```

Standard tooling per edge family:

| Edge family | Typical tooling |
|-------------|-----------------|
| ACL abuse (GenericAll/Write, WriteDacl, ForceChangePassword, shadow creds) | PowerView, Whisker/Certipy, Impacket `dacledit` |
| DCSync | Mimikatz `lsadump::dcsync`, Impacket `secretsdump` |
| Kerberos (Kerberoast, AS-REP, delegation, RBCD) | Rubeus, Impacket `getST`/`GetUserSPNs` |
| Sessions / lateral (AdminTo, HasSession, CanRDP/PSRemote, DCOM) | Impacket `psexec`/`wmiexec`/`smbexec`, Evil-WinRM, Mimikatz |
| AD CS (ESC1-8) | Certify, Certipy |
| LAPS/gMSA | `Get-LAPSADPassword`, GMSAPasswordReader |

Note **runs** and **detections** honestly. A technique that fired 2 of 5 runs is
genuinely a coin toss and should score that way - the shrinkage estimator relies
on your run counts being real.

---

## 4. APT29 emulation via Caldera (realism layer)

To add a realistic end-to-end pass:

1. Stand up a Caldera server on `ATTACK` (`git clone` the MITRE Caldera repo,
   `pip install -r requirements.txt`, `python server.py --insecure`).
2. Install the **emu** plugin (the Adversary Emulation Library), which includes
   the APT29 plan, and enable it in Caldera's config.
3. Deploy the Caldera agent (Sandcat) to `WS01`/`WS02` and run the APT29
   adversary profile.
4. Watch the same telemetry pipeline. The APT29 plan maps cleanly onto a subset
   of corpus edges - record those observations alongside the edge-exercise ones:

| APT29 activity | Corpus edge(s) |
|----------------|----------------|
| Credential dumping / replication | `DCSync` |
| LSASS / session cred theft | `HasSession` |
| Lateral movement (WMI/WinRM/SMB) | `AdminTo`, `CanPSRemote`, `ExecuteDCOM` |
| Kerberoasting | (Kerberoast edge - add to corpus if you path on it) |
| Scheduled task / service persistence | not a BloodHound edge; ignore for calibration |

Everything APT29 does not touch (most ACL and all ADCS edges) still needs the
Section 3 direct pass. That is expected - emulation is for realism, the
edge-exercise pass is for coverage.

---

## 5. Scoring rubric

Fill each worksheet row:

- `runs` / `detections`: integers from Section 3. This is the detection rate.
- `severity`: how loud the SOC response is *when it fires* -
  - `info` (~20): an event exists but no rule would alert
  - `low` (~40): a raw event a hunter could find, no standing alert
  - `medium` (~65): a correlation rule or medium-confidence alert fires
  - `high` (~85): a named, high-confidence alert (e.g. "MDI: Suspected DCSync")
  - `critical` (~95): an alert that pages someone
- `signals`: free-text list of what actually fired (event IDs, alert names) -
  documentation for the next operator.

Then calibrate:

```bash
noisehound-calibrate -i lab_detections.json -o env.APT29-range.json
# use it:
python -m noisehound -i export.zip -s jdoe -o "Domain Admins" -e env.APT29-range.json
```

The tool prints a summary showing, per edge, how far the measured score moved
from the static estimate. Re-run as you gather more data; more runs give the
lab more weight over the corpus (the `--smoothing` knob controls how fast).

---

## 6. Iterating

- Keep one profile per lab posture (`env.no-auditing.json`,
  `env.full-auditing-mdi.json`). Real engagements pick the closest match.
- Feed strong lab numbers back into the **corpus** itself via a PR (see
  [CONTRIBUTING](../CONTRIBUTING.md)) so the community baseline improves, and
  keep target-specific tuning in environment profiles.
- Where you trust the lab completely, promote calibrated values from profile
  `adjustments` toward being the new corpus `static_noise_score` with a note
  citing the lab run.
