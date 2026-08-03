# Calibration lab: GOAD on Proxmox via Ludus

The smoothest way to stand up a vulnerable AD range for calibration. Ludus
(https://ludus.cloud) automates the whole GOAD deploy on Proxmox - no Vagrant,
no VMware plugin, and it's a separate box so it never fights the Hyper-V/Docker
your BloodHound uses. A Claude Code session on the Proxmox box (or one that can
SSH to it) can drive every step here.

> Authorized lab only. This deliberately builds a vulnerable AD for detection
> testing on hardware you own.

## Hardware (the separate box)

- CPU with VT-x/AMD-V (bare metal strongly preferred; nested virt is slow).
- **Full GOAD (5 Windows VMs):** ~64 GB RAM ideal (32 GB tight), ~400-500 GB SSD.
- **GOAD-Light (2-3 VMs):** ~24-32 GB RAM, ~200 GB - fine for calibration and
  what I'd pick if RAM is limited.

## Step 1 - Install Proxmox VE

Install Proxmox VE 8 on the box (ISO from proxmox.com). Give it a static IP.
SSH in as root for the rest.

## Step 2 - Install Ludus

On the Proxmox host (see https://docs.ludus.cloud for the current one-liner):
```bash
curl -s https://ludus.cloud/install | bash
# follow the installer; it reboots Proxmox once to reconfigure networking
ludus-install-status          # wait until it reports ready
```
Create your admin user and grab the API key it prints:
```bash
ludus user add --name "jared" --admin
# set LUDUS_API_KEY per the docs so the `ludus` CLI authenticates
```

## Step 3 - Build the base OS templates

Ludus builds Windows Server / Windows 10-11 / Kali templates once (this is the
long pole - can take a couple hours):
```bash
ludus templates build
ludus templates list          # wait for all to show built
```

## Step 4 - Deploy the GOAD range

Ludus ships a GOAD blueprint (the Bad Sectors `ludus_goad` roles). Set your range
config to the GOAD (or GOAD-Light) template and deploy:
```bash
# get the GOAD range config from the Ludus docs / badsectorlabs examples,
# save as goad.yml, then:
ludus range config set -f goad.yml
ludus range deploy
ludus range status            # watch it build the domain(s)
```
When it finishes you'll have the full EvilCorp/GOAD forest with the ACL,
delegation, ADCS, Kerberos, and session misconfigs the corpus scores.

## Step 5 - Instrument detection

On the DCs and member hosts (RDP in via the Ludus range access / WireGuard):

1. **Audit policy + Sysmon** - run `Enable-Telemetry.ps1` from `NoiseHound/lab/`:
   ```powershell
   .\Enable-Telemetry.ps1 -EnableDCSyncAudit -SysmonPath .\Sysmon64.exe -SysmonConfig .\sysmonconfig.xml
   ```
   Do this first - it's free and lets calibration start immediately.
2. **Microsoft Defender for Identity (MDI)** - install the sensor on the DCs
   (needs an M365/Defender tenant). Adds the "named alert / high severity" tier.
3. **Defender for Endpoint** - onboard the member workstations. Adds host EDR
   alerts. MDI + EDR can be added *after* a first audit-only calibration pass;
   we just re-run the harness and the alert-tier data lights up.

## Step 6 - Collect + signal ready

Run SharpHound against the range (`-c All,LoggedOn` while a privileged user is
logged into a workstation) to produce the BloodHound graph NoiseHound will path
over, and confirm detection is live (`Collect-Detections.ps1` shows events after
a test technique).

## Step 7 - Run the automated calibration harness

From `NoiseHound/lab/` on the attacking host:

```powershell
# 1. emit the plan (per-edge detection event IDs, from the corpus)
noisehound-calibrate --plan -o plan.json

# 2. fill in the abuse commands for YOUR objects, then enable them
#    (copy the template, adjust GOAD user/computer/domain names + tool paths,
#     set "enabled": true on each edge you've set up)
copy calibration-commands.template.json calibration-commands.json

# 3. run it - executes each enabled edge N times, auto-counts the plan's
#    detect_events in the Security/Sysmon logs, scores detected/runs
.\Invoke-NoiseHoundCalibration.ps1 -Runs 4 -Sysmon -Edr none -Auditing4662 -Out lab_detections.json

# 4. quick severity pass: bump edges where MDI/EDR raised a NAMED alert to
#    high/critical in lab_detections.json, then produce the measured profile
noisehound-calibrate -i lab_detections.json -o profiles/goad-measured.json
```

The harness automates the tedious part (running + counting). That measured
profile is what we commit and ship in the calibrated release - re-run after
adding MDI/EDR to light up the alert tier.
