#Requires -Version 5.1
<#
.SYNOPSIS
    Tally the security and Sysmon events generated during a technique-exercise
    window, to help fill in the NoiseHound calibration worksheet.

.DESCRIPTION
    After running an edge's abuse primitive, point this at the time window and it
    reports which relevant event IDs fired and how many times, grouped by the
    edge family they inform. It does NOT decide "detected" for you - a raw event
    is not the same as an alert. Use it to see what host/AD telemetry fired, then
    combine with your EDR/MDI portal to judge severity and set detected/runs in
    lab_detections.json.

.PARAMETER Start
    Start of the window (e.g. (Get-Date).AddMinutes(-15)). Required.

.PARAMETER End
    End of the window. Default: now.

.PARAMETER IncludeSysmon
    Also query the Sysmon Operational log (host-based signals).

.NOTES
    LAB USE ONLY. Read-only: it queries event logs, changes nothing. EDR/MDI
    alerts are not in the Windows event log - check those portals separately.

.EXAMPLE
    .\Collect-Detections.ps1 -Start (Get-Date).AddMinutes(-10) -IncludeSysmon
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][datetime]$Start,
    [datetime]$End = (Get-Date),
    [switch]$IncludeSysmon
)

$ErrorActionPreference = 'SilentlyContinue'

# Security-log event IDs the corpus cares about, grouped by edge family.
$securityMap = @(
    @{ Id = 4662; Family = 'DCSync / LAPS-gMSA read (DS access)' }
    @{ Id = 5136; Family = 'WriteDacl / RBCD / shadow creds / GPLink (DS change)' }
    @{ Id = 5137; Family = 'New DS object (GPLink, etc.)' }
    @{ Id = 4724; Family = 'ForceChangePassword (reset)' }
    @{ Id = 4728; Family = 'AddMember (global group)' }
    @{ Id = 4732; Family = 'AddMember (local group)' }
    @{ Id = 4756; Family = 'AddMember (universal group)' }
    @{ Id = 4738; Family = 'WriteAccountRestrictions (UAC change)' }
    @{ Id = 4765; Family = 'HasSIDHistory (SID history added)' }
    @{ Id = 4768; Family = 'Kerberos AS (AS-REP, PKINIT)' }
    @{ Id = 4769; Family = 'Kerberos TGS (Kerberoast, delegation)' }
    @{ Id = 4771; Family = 'Kerberos pre-auth failure (AS-REP targets)' }
    @{ Id = 4776; Family = 'NTLM validation (PtH)' }
    @{ Id = 4624; Family = 'Logon (lateral movement / RDP type 10)' }
    @{ Id = 4648; Family = 'Explicit creds (make_token / runas)' }
    @{ Id = 4886; Family = 'ADCS: certificate requested' }
    @{ Id = 4887; Family = 'ADCS: certificate issued' }
    @{ Id = 7045; Family = 'Service installed (PsExec)' }
)

# Sysmon Operational event IDs.
$sysmonMap = @(
    @{ Id = 1;  Family = 'Process create' }
    @{ Id = 3;  Family = 'Network connect' }
    @{ Id = 7;  Family = 'Image load (CLR / execute-assembly)' }
    @{ Id = 8;  Family = 'CreateRemoteThread (injection)' }
    @{ Id = 10; Family = 'ProcessAccess (LSASS -> HasSession)' }
    @{ Id = 11; Family = 'File create (payload staging)' }
    @{ Id = 17; Family = 'Named pipe created' }
    @{ Id = 18; Family = 'Named pipe connected' }
)

function Get-EventCounts {
    param([string]$LogName, [array]$Map)
    $ids = $Map | ForEach-Object { $_.Id }
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = $LogName
        Id        = $ids
        StartTime = $Start
        EndTime   = $End
    } -ErrorAction SilentlyContinue

    $byId = $events | Group-Object Id -AsHashTable -AsString
    foreach ($m in $Map) {
        $count = 0
        if ($byId -and $byId.ContainsKey([string]$m.Id)) {
            $count = @($byId[[string]$m.Id]).Count
        }
        [pscustomobject]@{
            Log    = $LogName
            EventId = $m.Id
            Count  = $count
            Family = $m.Family
        }
    }
}

Write-Host ("NoiseHound detection collection  {0:u} -> {1:u}`n" -f $Start, $End) -ForegroundColor Cyan

$results = Get-EventCounts -LogName 'Security' -Map $securityMap
if ($IncludeSysmon) {
    $results += Get-EventCounts -LogName 'Microsoft-Windows-Sysmon/Operational' -Map $sysmonMap
}

$results |
    Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, 'EventId' |
    Format-Table -AutoSize @{ L = 'Log'; E = { $_.Log.Split('-')[-1] } },
        EventId, Count, Family

$fired = @($results | Where-Object { $_.Count -gt 0 })
Write-Host ("`n{0} of {1} monitored event types fired in this window." -f $fired.Count, $results.Count)
Write-Host "Reminder: an event firing is not an alert. Cross-check EDR/MDI portals" -ForegroundColor Yellow
Write-Host "to set 'severity', then record runs/detections in lab_detections.json." -ForegroundColor Yellow
