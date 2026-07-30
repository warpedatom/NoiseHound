# NoiseHound lab kit

Tooling to stand up the **detection instrumentation** needed to calibrate the
corpus. It deliberately does *not* reimplement vulnerable-AD seeding - mature
projects already do that better. Use one of those for the domain, this kit for
the telemetry, and [`../docs/CALIBRATION.md`](../docs/CALIBRATION.md) for the
measurement workflow.

> LAB USE ONLY. Everything here targets an isolated, disposable AD you own and
> are authorized to test. Snapshot before running. The PowerShell scripts are
> provided as-is for lab use and have not been validated against every
> Windows/AD version - review them before running.

## The workflow

1. **Get a vulnerable domain** (so the edges NoiseHound scores actually exist):
   - [GOAD](https://github.com/Orange-Cyberdefense/GOAD) - the most complete AD
     attack range (ACLs, delegation, ADCS, trusts). Best coverage.
   - [Vulnerable-AD](https://github.com/WazeHell/vulnerable-AD) - lighter, script
     that randomly injects common misconfigurations.
   - Your **CRTP/CRTO course lab** - already a real, misconfigured AD you can run
     SharpHound against today.

2. **Instrument detection** on the DC and each member host:
   ```powershell
   .\Enable-Telemetry.ps1 -EnableDCSyncAudit -SysmonPath C:\Tools\Sysmon64.exe -SysmonConfig C:\Tools\sysmonconfig.xml
   ```
   Enables the advanced audit-policy subcategories, PowerShell script-block
   logging, optional DCSync SACL, and Sysmon that make the corpus's event IDs
   fire. Calibrate once with `-EnableDCSyncAudit` and once without to produce a
   "default auditing" profile and an "auditing on" profile.

3. **Confirm the parser handles your export.** Collect BloodHound data
   (SharpHound / BOFHound) and inspect it before pathing:
   ```bash
   noisehound-inspect -i export.zip
   ```
   Check the node/edge histograms and corpus coverage look sane, and note any
   unknown edge types to add to the corpus.

4. **Generate the worksheet and exercise the edges:**
   ```bash
   noisehound-calibrate --template -o lab_detections.json
   ```
   For each edge, run its `abuse_primitive` (the corpus entry tells you what to
   run and what to watch), then tally what fired:
   ```powershell
   .\Collect-Detections.ps1 -Start (Get-Date).AddMinutes(-10) -IncludeSysmon
   ```
   Cross-check your EDR/MDI portal for named alerts, then fill in
   `runs` / `detections` / `severity` in `lab_detections.json`.

5. **Calibrate and use:**
   ```bash
   noisehound-calibrate -i lab_detections.json -o env.mylab.json
   python -m noisehound -i export.zip -s jdoe -o "Domain Admins" -e env.mylab.json
   ```

## Scripts

| Script | Purpose |
|--------|---------|
| `Enable-Telemetry.ps1` | Turn on audit policy, script-block logging, DCSync SACL, Sysmon |
| `Collect-Detections.ps1` | Tally relevant Security/Sysmon events in a time window (read-only) |

Both are read-through-first, snapshot-first lab tools. See
[`../docs/CALIBRATION.md`](../docs/CALIBRATION.md) for the full playbook including
the audit-subcategory-to-event-ID mapping and the per-edge exercise runbook.
