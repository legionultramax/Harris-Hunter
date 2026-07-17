# Collect-AuthLogs.ps1 (Linux) - recent authentication events (capped/time-bounded).
# ATT&CK: T1078 (valid accounts), T1110 (brute force), T1548.003 (sudo). Prefers journald,
# falls back to /var/log/auth.log (Debian) or /var/log/secure (RHEL).

function Collect-AuthLogs {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()
    $cap = 1500

    $lines = @()
    $source = $null
    if (Test-HHCommand 'journalctl') {
        try {
            $lines = @(& journalctl SYSLOG_FACILITY=10 --no-pager -n $cap --since '7 days ago' 2>$null)
            if ($lines.Count -gt 0) { $source = 'journalctl (authpriv)' }
        } catch { }
    }
    if ($lines.Count -eq 0) {
        foreach ($log in '/var/log/auth.log', '/var/log/secure') {
            try {
                if (Test-Path -LiteralPath $log) {
                    $lines = @(Get-Content -LiteralPath $log -Tail $cap -ErrorAction Stop)
                    $source = $log
                    break
                }
            } catch { }
        }
    }

    if (-not $source) {
        $records.Add((New-EvidenceRecord -ArtifactType 'auth_log_note' -Collector 'Collect-AuthLogs' `
            -Source 'auth logs' -Context $Context -Data @{ collected = $false; reason = 'no journald authpriv and no readable auth.log/secure (needs root)' }))
        return $records.ToArray()
    }

    foreach ($line in $lines) {
        if (-not $line -or -not $line.Trim()) { continue }
        $attack = @()
        if ($line -match '(?i)failed password|authentication failure|invalid user') { $attack += 'T1110' }
        elseif ($line -match '(?i)accepted (password|publickey)') { $attack += 'T1078' }
        elseif ($line -match '(?i)\bsudo\b.*COMMAND=') { $attack += 'T1548.003' }
        # Only keep security-relevant lines to bound size.
        if ($attack.Count -eq 0) { continue }
        $records.Add((New-EvidenceRecord -ArtifactType 'auth_event' -Collector 'Collect-AuthLogs' `
            -Source $source -Attack $attack -Context $Context -Data @{ line = $line.Trim() }))
    }

    if ($records.Count -eq 0) {
        $records.Add((New-EvidenceRecord -ArtifactType 'auth_log_note' -Collector 'Collect-AuthLogs' `
            -Source $source -Context $Context -Data @{ collected = $true; relevant_events = 0 }))
    }
    return $records.ToArray()
}
