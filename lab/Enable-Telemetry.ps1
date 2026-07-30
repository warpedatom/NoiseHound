#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Turn on the Windows telemetry NoiseHound's corpus references, so a lab can
    actually detect the techniques you calibrate against.

.DESCRIPTION
    Enables the advanced audit policy subcategories, PowerShell script-block
    logging, and (optionally) Sysmon that make the corpus's event IDs fire.
    Run it on the domain controller and on each member host you will exercise
    techniques against, or adapt it into a GPO for fleet-wide application.

    This is calibration instrumentation. It is the piece GOAD / Vulnerable-AD do
    not set up for you. It does NOT create the vulnerable objects themselves -
    stand those up with GOAD, Vulnerable-AD, or your own course lab first (see
    lab/README.md).

.PARAMETER EnableDCSyncAudit
    Also place a SACL on the domain head auditing the replication extended
    rights, so DCSync generates event 4662. Domain-controller only; requires
    Domain Admin and the ActiveDirectory module. Advanced - verify afterwards.

.PARAMETER SysmonPath
    Path to Sysmon64.exe. If given, Sysmon is installed (or its config updated).

.PARAMETER SysmonConfig
    Path to a Sysmon configuration XML (e.g. SwiftOnSecurity or Olaf Hartong's
    modular config). Used with -SysmonPath.

.NOTES
    LAB USE ONLY. Run against isolated, disposable systems you own and have
    authorization to test. Snapshot first. Provided as-is; not validated against
    every Windows/AD version - review before running.

.EXAMPLE
    .\Enable-Telemetry.ps1
.EXAMPLE
    .\Enable-Telemetry.ps1 -EnableDCSyncAudit -SysmonPath C:\Tools\Sysmon64.exe -SysmonConfig C:\Tools\sysmonconfig.xml
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$EnableDCSyncAudit,
    [string]$SysmonPath,
    [string]$SysmonConfig
)

$ErrorActionPreference = 'Stop'

Write-Host "NoiseHound telemetry enablement - LAB USE ONLY" -ForegroundColor Cyan
Write-Host "Snapshot the system before proceeding.`n" -ForegroundColor Yellow

# Advanced audit policy subcategories that light up the corpus's event IDs.
# Names are en-US; on localized systems substitute the stable GUIDs shown.
$subcategories = @(
    @{ Name = 'Directory Service Access';            Guid = '{0CCE923B-69AE-11D9-BED3-505054503030}'; Note = '4662 (DCSync, LAPS/gMSA reads)' }
    @{ Name = 'Directory Service Changes';           Guid = '{0CCE923C-69AE-11D9-BED3-505054503030}'; Note = '5136/5137 (WriteDacl, RBCD, shadow creds, GPLink)' }
    @{ Name = 'Security Group Management';           Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Note = '4728/4732/4756 (AddMember/AddSelf)' }
    @{ Name = 'User Account Management';             Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Note = '4720/4724/4738/4765 (reset, UAC, SID history)' }
    @{ Name = 'Computer Account Management';         Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; Note = 'computer object changes' }
    @{ Name = 'Kerberos Authentication Service';     Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Note = '4768/4771 (AS-REP, roasting sources)' }
    @{ Name = 'Kerberos Service Ticket Operations';  Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Note = '4769 (Kerberoast, delegation)' }
    @{ Name = 'Credential Validation';               Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Note = '4776 (NTLM / PtH)' }
    @{ Name = 'Logon';                               Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Note = '4624 (lateral movement, RDP type 10)' }
    @{ Name = 'Special Logon';                       Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Note = '4672 (privileged logon)' }
    @{ Name = 'Security System Extension';           Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Note = 'service/driver load' }
)

Write-Host "Enabling advanced audit policy subcategories..." -ForegroundColor Green
foreach ($sc in $subcategories) {
    if ($PSCmdlet.ShouldProcess($sc.Name, "auditpol enable success+failure")) {
        # Use the GUID for locale independence.
        & auditpol.exe /set /subcategory:"$($sc.Guid)" /success:enable /failure:enable | Out-Null
        Write-Host ("  [+] {0,-34} {1}" -f $sc.Name, $sc.Note)
    }
}

# PowerShell script-block logging (event 4104) - exposes PowerShell-borne
# techniques (CanPSRemote, delegation tooling, etc.).
Write-Host "`nEnabling PowerShell script-block logging (4104)..." -ForegroundColor Green
$sbl = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
if ($PSCmdlet.ShouldProcess($sbl, 'Enable script-block logging')) {
    New-Item -Path $sbl -Force | Out-Null
    New-ItemProperty -Path $sbl -Name 'EnableScriptBlockLogging' -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Host "  [+] EnableScriptBlockLogging = 1"
}

# Optional: SACL on the domain head so DCSync generates 4662.
if ($EnableDCSyncAudit) {
    Write-Host "`nPlacing replication-rights SACL on the domain head (DCSync -> 4662)..." -ForegroundColor Green
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $dn = (Get-ADDomain).DistinguishedName
        $path = "AD:\$dn"
        $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
        # Replicating Directory Changes (All) and Get Changes extended-right GUIDs.
        $replGuids = @(
            [Guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',  # Replicating Directory Changes All
            [Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'   # Replicating Directory Changes
        )
        if ($PSCmdlet.ShouldProcess($dn, 'Add replication audit ACEs')) {
            $acl = Get-Acl -Path $path -Audit
            foreach ($g in $replGuids) {
                $rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
                    $everyone, 'ExtendedRight', 'Success', $g)
                $acl.AddAuditRule($rule)
            }
            Set-Acl -Path $path -AclObject $acl
            Write-Host "  [+] Replication audit ACEs added. Verify with: dsacls `"$dn`""
        }
    }
    catch {
        Write-Warning "DCSync SACL step failed (needs DC + Domain Admin + SeSecurityPrivilege): $($_.Exception.Message)"
    }
}

# Optional: Sysmon (host-based signals - Sysmon 10 LSASS access etc.).
if ($SysmonPath) {
    Write-Host "`nConfiguring Sysmon..." -ForegroundColor Green
    if (-not (Test-Path -LiteralPath $SysmonPath)) {
        Write-Warning "SysmonPath not found: $SysmonPath (download Sysmon from Sysinternals)."
    }
    elseif ($PSCmdlet.ShouldProcess($SysmonPath, 'Install/update Sysmon')) {
        $installed = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue
        if ($installed) {
            if ($SysmonConfig) {
                & $SysmonPath -c $SysmonConfig
                Write-Host "  [+] Sysmon config updated."
            }
            else {
                Write-Host "  [i] Sysmon already installed; no -SysmonConfig given, left as-is."
            }
        }
        elseif ($SysmonConfig) {
            & $SysmonPath -accepteula -i $SysmonConfig
            Write-Host "  [+] Sysmon installed with config. Ensure Event ID 10 (ProcessAccess) is captured."
        }
        else {
            & $SysmonPath -accepteula -i
            Write-Host "  [+] Sysmon installed (default config). A tuned config is strongly recommended."
        }
    }
}
else {
    Write-Host "`nSysmon not configured (no -SysmonPath). Recommended for host signals" -ForegroundColor DarkYellow
    Write-Host "  (Sysmon 10 = LSASS access, the high-fidelity signal behind HasSession)."
}

Write-Host "`nDone. Verify current policy with:  auditpol /get /category:*" -ForegroundColor Cyan
Write-Host "Then exercise techniques and collect with Collect-Detections.ps1." -ForegroundColor Cyan
