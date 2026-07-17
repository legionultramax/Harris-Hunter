# Collect-Cron.ps1 (Linux) - system and per-user cron jobs. ATT&CK: T1053.003 (cron).

function Collect-Cron {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    $addFile = {
        param($path, $scope)
        try {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $ev = Get-HHLinuxFileEvidence -Path $path
                $lines = @(Get-Content -LiteralPath $path -ErrorAction Stop | Where-Object { $_ -and $_ -notmatch '^\s*#' })
                $records.Add((New-EvidenceRecord -ArtifactType 'cron_job' -Collector 'Collect-Cron' `
                    -Source $path -Attack @('T1053.003') -Context $Context -Data @{
                        path = $path; scope = $scope; entries = $lines; sha256 = $ev.sha256; owner = $ev.owner
                    }))
            }
        } catch { }
    }

    # System crontab + drop-in dirs.
    & $addFile '/etc/crontab' 'system'
    foreach ($dir in '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly') {
        try {
            if (Test-Path -LiteralPath $dir) {
                Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | ForEach-Object { & $addFile $_.FullName "system:$($dir | Split-Path -Leaf)" }
            }
        } catch { }
    }

    # Per-user crontabs (Debian: crontabs/, RHEL: cron/). Needs root.
    foreach ($spool in '/var/spool/cron/crontabs', '/var/spool/cron') {
        try {
            if (Test-Path -LiteralPath $spool) {
                Get-ChildItem -LiteralPath $spool -File -ErrorAction SilentlyContinue | ForEach-Object { & $addFile $_.FullName "user:$($_.Name)" }
            }
        } catch { }
    }

    if ($records.Count -eq 0) {
        $records.Add((New-EvidenceRecord -ArtifactType 'cron_note' -Collector 'Collect-Cron' -Source 'cron' -Context $Context -Data @{ collected = $true; jobs_found = 0 }))
    }
    return $records.ToArray()
}
