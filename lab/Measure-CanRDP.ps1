#Requires -Version 5.1
<#
.SYNOPSIS
    Measure the CanRDP edge (interactive RDP -> 4624 type-10 + 4778) on the TARGET
    host, and emit a lab_detections snippet for noisehound-calibrate.

.DESCRIPTION
    CanRDP is an interactive logon, so it doesn't fit the Invoke-Expression harness.
    Run it like the lateral edges were measured:
      1. On the RDP TARGET (e.g. NH-WS01), note the start time and run this with -Arm.
         (Or just pass -Since with a timestamp.)
      2. From the source context, RDP into the target -Runs times, logging OFF between
         each (a clean logon per run). cmdkey + mstsc works, or the console.
      3. Re-run this on the target WITHOUT -Arm to count 4624 (LogonType=10) + 4778
         since the start time and write the snippet.

    Then fold it into a shipped profile:
      noisehound-calibrate -i canrdp_detections.json --merge profiles/vulnad-hyperv-audit.json -o profiles/vulnad-hyperv-audit.json

.NOTES
    LAB USE ONLY. Run on the target host (that's where the logon events land).
#>
[CmdletBinding()]
param(
    [int]$Runs = 4,
    [datetime]$Since,
    [switch]$Arm,
    [ValidateSet("none", "MDI", "EDR")][string]$Edr = "none",
    [string]$Out = ".\canrdp_detections.json"
)

$stamp = ".\.canrdp_since.txt"
if ($Arm) {
    (Get-Date).ToString("o") | Set-Content -Encoding ascii $stamp
    Write-Host "Armed at $(Get-Date). Now RDP into this host $Runs times (log off between), then re-run without -Arm." -ForegroundColor Cyan
    return
}
if (-not $Since) {
    if (Test-Path $stamp) { $Since = [datetime]::Parse((Get-Content -Raw $stamp)) }
    else { throw "No start time: pass -Since '<timestamp>' or run with -Arm first." }
}

# 4624 with LogonType 10 (RemoteInteractive) is the deterministic RDP tell; 4778 = reconnect.
$logons = @(Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4624; StartTime = $Since } -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[8].Value -eq 10 })
$reconnects = @(Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4778; StartTime = $Since } -ErrorAction SilentlyContinue)

$detections = [Math]::Min($Runs, $logons.Count)
$signals = @()
if ($logons.Count -gt 0)     { $signals += ("windows_security 4624(type10) x{0}" -f $logons.Count) }
if ($reconnects.Count -gt 0) { $signals += ("windows_security 4778 x{0}" -f $reconnects.Count) }

$severity = if ($detections -gt 0) { if ($Edr -eq "none") { "low" } else { "medium" } } else { "info" }
$result = [ordered]@{
    _comment    = "CanRDP measured on the target host. Merge with: noisehound-calibrate -i $Out --merge profiles/vulnad-hyperv-audit.json -o profiles/vulnad-hyperv-audit.json"
    environment = "vulnad-hyperv"
    edr         = $Edr
    sysmon      = $true
    object_auditing_4662 = $true
    observations = @([ordered]@{ edge_type = "CanRDP"; runs = $Runs; detections = $detections; severity = $severity; signals = $signals })
}
$outPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Out)
[System.IO.File]::WriteAllText($outPath, ($result | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("CanRDP: {0}/{1} detected  [{2}]  -> {3}" -f $detections, $Runs, ($signals -join ", "), $Out) -ForegroundColor Green
