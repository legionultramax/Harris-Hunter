# Collect-SystemLogs.ps1 (Linux) - LNX-LOGS: bounded system-log extraction, journald export,
# wtmp/btmp/lastlog raw copies for offline parsing, and log truncation/gap detection.
# Complements Collect-AuthLogs (which parses auth events); this one preserves the raw logs and
# flags tampering with the logging surface itself.
# ATT&CK: T1070.002 (clear Linux logs), T1562.006 (indicator blocking / logging disabled).

function Collect-SystemLogs {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    # Copy the last N lines of a text log into the bundle as a bounded evidence file (never the
    # whole file - logs can be multi-GB). Returns the evidence-file record or $null.
    function Export-HHBoundedTail {
        param([string]$Path, [int]$MaxLines, [string]$Category)
        try {
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue)) { return $null }
            $tmp = [System.IO.Path]::GetTempFileName()
            try {
                Get-Content -LiteralPath $Path -Tail $MaxLines -ErrorAction Stop | Set-Content -LiteralPath $tmp -ErrorAction Stop
                if (Get-Command -Name Add-EvidenceFile -ErrorAction SilentlyContinue) {
                    return Add-EvidenceFile -SourcePath $tmp -Category $Category -Name ((Split-Path -Leaf $Path) + '.tail')
                }
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        } catch { }
        return $null
    }

    # --- System log files: metadata + bounded raw export + truncation detection ---
    $sysLogs = @(
        @{ path = '/var/log/syslog';           cat = 'linux_logs' },
        @{ path = '/var/log/messages';         cat = 'linux_logs' },
        @{ path = '/var/log/kern.log';         cat = 'linux_logs' },
        @{ path = '/var/log/audit/audit.log';  cat = 'linux_logs' },
        @{ path = '/var/log/cron';             cat = 'linux_logs' }
    )
    foreach ($lg in $sysLogs) {
        try {
            if (-not (Test-Path -LiteralPath $lg.path -PathType Leaf -ErrorAction SilentlyContinue)) { continue }
            $fi = Get-Item -LiteralPath $lg.path -Force -ErrorAction Stop
            # Truncation heuristic: a zero-byte security-relevant log on a running host is a
            # classic "> logfile" wipe. Flag it (and any log whose mtime is in the future).
            $truncated = ($fi.Length -eq 0)
            $attack = @()
            if ($truncated) { $attack += 'T1070.002' }

            $exported = Export-HHBoundedTail -Path $lg.path -MaxLines 5000 -Category $lg.cat
            $records.Add((New-EvidenceRecord -ArtifactType 'system_log' -Collector 'Collect-SystemLogs' `
                -Source $lg.path -Attack $attack -Context $Context -Data @{
                    path           = $lg.path
                    size           = $fi.Length
                    mtime_utc      = $fi.LastWriteTimeUtc.ToString('o')
                    truncated_hint = $truncated
                    evidence_file  = if ($exported) { $exported.file } else { $null }
                    sha256         = if ($exported) { $exported.sha256 } else { $null }
                }))
        } catch { }
    }

    # --- Raw login-record binaries (wtmp/btmp/lastlog) for offline `last`/`lastb` parsing ---
    foreach ($bin in '/var/log/wtmp', '/var/log/btmp', '/var/log/lastlog') {
        try {
            if (-not (Test-Path -LiteralPath $bin -PathType Leaf -ErrorAction SilentlyContinue)) { continue }
            $rec = $null
            if (Get-Command -Name Add-EvidenceFile -ErrorAction SilentlyContinue) {
                $rec = Add-EvidenceFile -SourcePath $bin -Category 'linux_logs'
            }
            $fi = Get-Item -LiteralPath $bin -Force -ErrorAction SilentlyContinue
            $records.Add((New-EvidenceRecord -ArtifactType 'login_record_binary' -Collector 'Collect-SystemLogs' `
                -Source $bin -Context $Context -Data @{
                    path          = $bin
                    size          = if ($fi) { $fi.Length } else { $null }
                    captured      = [bool]$rec
                    evidence_file = if ($rec) { $rec.file } else { $null }
                    sha256        = if ($rec) { $rec.sha256 } else { $null }
                    note          = if (-not $rec) { 'not captured (needs root, esp. btmp 0600)' } else { $null }
                }))
        } catch { }
    }

    # --- journald: bounded export + persistence/gap posture ---
    if (Test-HHCommand 'journalctl') {
        # Persistent journal? If /var/log/journal is absent, journald is volatile (RAM-only) and
        # logs are lost on reboot - a logging-visibility gap worth flagging.
        $persistent = (Test-Path -LiteralPath '/var/log/journal' -ErrorAction SilentlyContinue)
        $attack = @(); if (-not $persistent) { $attack += 'T1562.006' }

        $exportRec = $null
        try {
            $tmp = [System.IO.Path]::GetTempFileName()
            try {
                & journalctl --no-pager --since '7 days ago' -p warning -n 5000 2>$null | Set-Content -LiteralPath $tmp -ErrorAction Stop
                if ((Get-Command -Name Add-EvidenceFile -ErrorAction SilentlyContinue) -and ((Get-Item -LiteralPath $tmp).Length -gt 0)) {
                    $exportRec = Add-EvidenceFile -SourcePath $tmp -Category 'linux_logs' -Name 'journald-warn-7d.txt'
                }
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        } catch { }

        # Boot continuity: fewer/again-numbered boots than expected can indicate log vacuuming.
        $boots = $null
        try { $boots = @(& journalctl --list-boots --no-pager 2>$null).Count } catch { }

        $records.Add((New-EvidenceRecord -ArtifactType 'journald_state' -Collector 'Collect-SystemLogs' `
            -Source 'journalctl' -Attack $attack -Context $Context -Data @{
                persistent    = [bool]$persistent
                boot_count    = $boots
                evidence_file = if ($exportRec) { $exportRec.file } else { $null }
                sha256        = if ($exportRec) { $exportRec.sha256 } else { $null }
                note          = if (-not $persistent) { 'journald is volatile (no /var/log/journal) - logs lost on reboot' } else { $null }
            }))
    }

    # --- auditd posture (its absence/inactivity is itself a detection gap) ---
    $auditdActive = $null
    if (Test-HHCommand 'systemctl') {
        try { $auditdActive = ((& systemctl is-active auditd 2>$null) -join '').Trim() } catch { }
    }
    $records.Add((New-EvidenceRecord -ArtifactType 'auditd_state' -Collector 'Collect-SystemLogs' `
        -Source 'systemctl is-active auditd' -Context $Context -Data @{
            auditd_active = $auditdActive
            audit_log     = (Test-Path -LiteralPath '/var/log/audit/audit.log' -ErrorAction SilentlyContinue)
        }))

    if ($records.Count -eq 0) {
        $records.Add((New-EvidenceRecord -ArtifactType 'system_log_note' -Collector 'Collect-SystemLogs' `
            -Source 'system logs' -Context $Context -Data @{ collected = $false; reason = 'no readable system logs (needs root)' }))
    }
    return $records.ToArray()
}
