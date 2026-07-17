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

    return $records.ToArray()
}
