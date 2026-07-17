# Collect-EventLogs.ps1 - event-log inventory + capped recent high-signal events (as JSON).
# ATT&CK: T1059.001 (PowerShell), plus general execution/telemetry. Raw .evtx export is a
# Phase 1.x enhancement (needs an evidence-file sink); Phase 1 parses key events to records.

function Collect-EventLogs {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    # --- Inventory: logs that actually hold records ---
    try {
        Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordCount -gt 0 } | ForEach-Object {
                $records.Add((New-EvidenceRecord -ArtifactType 'eventlog_inventory' -Collector 'Collect-EventLogs' `
                    -Source 'Get-WinEvent -ListLog' -Context $Context -Data @{
                        log_name      = $_.LogName
                        record_count  = $_.RecordCount
                        file_size     = $_.FileSize
                        is_enabled    = [bool]$_.IsEnabled
                        log_mode      = [string]$_.LogMode
                        last_write_utc= if ($_.LastWriteTime) { $_.LastWriteTime.ToUniversalTime().ToString('o') } else { $null }
                    }))
            }
    } catch { }

    # --- Curated recent events (time-bounded + capped per source) ---
    $since = (Get-Date).AddDays(-3)
    $sources = @(
        @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4103, 4104); Cap = 500; Attack = @('T1059.001') },
        @{ Log = 'Microsoft-Windows-Sysmon/Operational';     Ids = @();           Cap = 500; Attack = @() },
        @{ Log = 'System';                                    Ids = @();           Cap = 300; Attack = @(); Level = @(1,2) }
    )

    foreach ($src in $sources) {
        $filter = @{ LogName = $src.Log; StartTime = $since }
        if ($src.Ids.Count -gt 0)   { $filter.Id = $src.Ids }
        if ($src.ContainsKey('Level')) { $filter.Level = $src.Level }
        $evts = $null
        try { $evts = Get-WinEvent -FilterHashtable $filter -MaxEvents $src.Cap -ErrorAction Stop } catch { continue }

        foreach ($e in $evts) {
            $msg = $null
            try { $msg = ($e.Message -split "`r?`n" | Select-Object -First 1) } catch { }
            $records.Add((New-EvidenceRecord -ArtifactType 'event' -Collector 'Collect-EventLogs' `
                -Source $src.Log -Attack $src.Attack -Context $Context -Data @{
                    log          = $src.Log
                    event_id     = $e.Id
                    level        = [string]$e.LevelDisplayName
                    provider     = $e.ProviderName
                    time_utc     = $e.TimeCreated.ToUniversalTime().ToString('o')
                    message_head = $msg
                }))
        }
    }

    # --- Raw EVTX export (deep profile only; large, and needs elevation for Security) ---
    # Full logs go into the bundle's evidence-file sink for offline analysis, hashed into the
    # manifest. Gated to 'deep' so quick/standard bundles stay small.
    if ($Context.Profile -eq 'deep') {
        $rawLogs = @(
            'Security', 'System', 'Application',
            'Microsoft-Windows-PowerShell/Operational',
            'Microsoft-Windows-Sysmon/Operational',
            'Microsoft-Windows-TaskScheduler/Operational',
            'Microsoft-Windows-Windows Defender/Operational',
            'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        )
        foreach ($log in $rawLogs) {
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ("hh_evtx_" + [guid]::NewGuid().ToString('N') + '.evtx')
            try {
                & wevtutil epl "$log" "$tmp" /ow:true 2>$null
                if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $tmp)) {
                    $safeName = ($log -replace '[\\/]', '_') + '.evtx'
                    $added = Add-EvidenceFile -SourcePath $tmp -Category 'evtx' -Name $safeName
                    if ($added) {
                        $records.Add((New-EvidenceRecord -ArtifactType 'evtx_export' -Collector 'Collect-EventLogs' `
                            -Source "wevtutil epl $log" -Context $Context -Data @{
                                log = $log; file = $added.file; size = $added.size; sha256 = $added.sha256
                            }))
                    }
                }
            } catch { }
            finally { if (Test-Path -LiteralPath $tmp -ErrorAction SilentlyContinue) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
        }
    }

    return $records.ToArray()
}
