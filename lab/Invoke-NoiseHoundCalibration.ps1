#Requires -Version 5.1
<#
.SYNOPSIS
    Automated NoiseHound calibration: run each corpus edge's abuse N times in a
    clean window, auto-count the detection events from the logs, and emit
    lab_detections.json - ready for `noisehound-calibrate`.

.DESCRIPTION
    Reads the calibration PLAN (`noisehound-calibrate --plan -o plan.json`) for
    the per-edge event IDs that count as detection, and a COMMANDS file mapping
    each edge to the abuse command to run in your lab. For each enabled edge it
    runs the command N times; after each run it counts the plan's detect_events
    in the Security (and Sysmon) logs since the run started, and scores
    detected/runs. It automates the tedious part - running and counting.

    Severity is auto-seeded (logged-but-not-alerted = low in an audit-only lab,
    medium if you have an alerting stack). Do a quick manual pass afterward:
    bump edges where MDI/EDR raised a NAMED alert to high/critical and add the
    alert name to `signals`. Then feed the file to `noisehound-calibrate`.

.NOTES
    LAB USE ONLY. Authorized, isolated range you own. Commands run via
    Invoke-Expression on the attacking host - point it only at your own lab.

.EXAMPLE
    noisehound-calibrate --plan -o plan.json
    .\Invoke-NoiseHoundCalibration.ps1 -Runs 4 -Sysmon -Edr none -Out lab_detections.json
#>
[CmdletBinding()]
param(
    [string]$Plan = ".\plan.json",
    [string]$Commands = ".\calibration-commands.json",
    [int]$Runs = 4,
    [int]$SettleSeconds = 25,
    [string]$Environment = "goad-lab",
    [ValidateSet("none", "MDI", "EDR")][string]$Edr = "none",
    [switch]$Sysmon,
    [switch]$Auditing4662,
    [string]$Out = ".\lab_detections.json"
)

$ErrorActionPreference = "Stop"
Write-Host "NoiseHound automated calibration - LAB USE ONLY`n" -ForegroundColor Cyan

# NOTE: the internal variable must NOT be named $plan. PowerShell variable names
# are case-insensitive, so $plan would alias the [string]$Plan parameter, whose
# type constraint coerces the parsed JSON back into a string - making .edges null
# and silently skipping every edge. Use a distinct name.
$planData = Get-Content -Raw $Plan | ConvertFrom-Json
$cmds = Get-Content -Raw $Commands | ConvertFrom-Json

$planByEdge = @{}
foreach ($e in $planData.edges) { $planByEdge[$e.edge_type] = $e }
if ($planByEdge.Count -eq 0) {
    throw "plan parse failed: no edges found in '$Plan'. Regenerate it with 'noisehound-calibrate --plan -o plan.json'."
}

# NOTE (known limitation): this counts ANY matching event ID in the post-run
# window, not only events the abuse itself caused - a busy or shared DC can yield
# a false "detected" from background activity. Causal correlation (filter by the
# target DN / SPN we touched) and idle-baseline subtraction are on the roadmap.
function Get-DetectHits($detectEvents, $start) {
    $hits = @()
    foreach ($d in $detectEvents) {
        if ($d.source -eq "sysmon" -and -not $Sysmon) { continue }
        # Resolve the correct event log per source. Service-install 7045 and other
        # SCM events live in System, not Security - a Security-only lookup misses them.
        $log = switch ($d.source) {
            "sysmon"         { "Microsoft-Windows-Sysmon/Operational" }
            "windows_system" { "System" }
            default          { "Security" }
        }
        try {
            $n = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = [int]$d.event_id; StartTime = $start } -ErrorAction SilentlyContinue).Count
        } catch { $n = 0 }
        if ($n -gt 0) { $hits += ("{0} {1} x{2}" -f $d.source, $d.event_id, $n) }
    }
    return $hits
}

$sevBase = if ($Edr -eq "none") { "low" } else { "medium" }
$observations = @()

foreach ($prop in $cmds.PSObject.Properties) {
    $edge = $prop.Name
    if ($edge -like "_*") { continue }   # skip _comment
    $entry = $prop.Value
    $command = if ($entry -is [string]) { $entry } else { $entry.command }
    $enabled = if ($entry -is [string]) { $true } else { [bool]$entry.enabled }
    if (-not $enabled -or [string]::IsNullOrWhiteSpace($command)) { continue }
    if (-not $planByEdge.ContainsKey($edge)) { Write-Warning "no plan entry for '$edge' - skipping"; continue }

    $de = $planByEdge[$edge].detect_events
    Write-Host ("[{0}] running {1}x ..." -f $edge, $Runs) -ForegroundColor Green
    $detections = 0
    $signals = @{}
    for ($i = 1; $i -le $Runs; $i++) {
        $start = Get-Date
        try { Invoke-Expression $command | Out-Null }
        catch { Write-Warning "  run $i command error: $($_.Exception.Message)" }
        Start-Sleep -Seconds $SettleSeconds
        $hits = Get-DetectHits $de $start
        if ($hits.Count -gt 0) { $detections++; foreach ($h in $hits) { $signals[$h] = $true } }
    }
    $severity = if ($detections -gt 0) { $sevBase } else { "info" }
    $observations += [ordered]@{
        edge_type  = $edge
        runs       = $Runs
        detections = $detections
        severity   = $severity
        signals    = @($signals.Keys)
    }
    Write-Host ("   -> {0}/{1} detected  [{2}]" -f $detections, $Runs, (($signals.Keys) -join ", "))
}

$result = [ordered]@{
    _comment = "Auto-generated by Invoke-NoiseHoundCalibration.ps1. REVIEW severity before calibrating: bump edges where MDI/EDR raised a NAMED alert to high/critical and add the alert name to signals. Then: noisehound-calibrate -i lab_detections.json -o env.json"
    environment = $Environment
    edr = $Edr
    sysmon = [bool]$Sysmon
    object_auditing_4662 = [bool]$Auditing4662
    observations = $observations
}
# Write UTF-8 WITHOUT a BOM. PS 5.1 'Set-Content -Encoding UTF8' prepends a BOM
# that noisehound-calibrate's strict UTF-8 reader rejects ("Unexpected UTF-8 BOM").
$outPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Out)
[System.IO.File]::WriteAllText($outPath, ($result | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("`nWrote {0} ({1} edges tested). Do the severity pass, then run noisehound-calibrate." -f $Out, $observations.Count) -ForegroundColor Cyan
