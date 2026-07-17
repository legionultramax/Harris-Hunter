# Collect-Filesystem.ps1 (Linux) - drop-site + suspicious-file triage.
# ATT&CK: T1204 (user execution), T1222 (permissions). Focuses on common staging locations
# and world-writable files rather than walking the whole filesystem.

function Collect-Filesystem {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()
    $cap = 500

    # Files staged in world-writable/tmp locations (classic payload drop sites).
    $count = 0
    foreach ($dir in '/tmp', '/var/tmp', '/dev/shm') {
        if ($count -ge $cap) { break }
        try {
            if (Test-Path -LiteralPath $dir) {
                Get-ChildItem -LiteralPath $dir -Recurse -File -Force -ErrorAction SilentlyContinue |
                    Select-Object -First ($cap - $count) | ForEach-Object {
                        $count++
                        $ev = Get-HHLinuxFileEvidence -Path $_.FullName
                        $records.Add((New-EvidenceRecord -ArtifactType 'tmp_file' -Collector 'Collect-Filesystem' `
                            -Source $dir -Attack @('T1204') -Context $Context -Data @{
                                path = $_.FullName; size = $ev.size; mode = $ev.mode; owner = $ev.owner
                                mtime_utc = $ev.mtime_utc; sha256 = $ev.sha256
                            }))
                    }
            }
        } catch { }
    }

    # World-writable files under system dirs (excluding the tmp dirs above).
    if (Test-HHCommand 'find') {
        try {
            $ww = & find /etc /usr /bin /sbin /opt /var -xdev -type f -perm -0002 2>$null | Select-Object -First $cap
            foreach ($path in $ww) {
                if (-not $path) { continue }
                $ev = Get-HHLinuxFileEvidence -Path $path
                $records.Add((New-EvidenceRecord -ArtifactType 'world_writable_file' -Collector 'Collect-Filesystem' `
                    -Source 'find -perm -0002' -Attack @('T1222.002') -Context $Context -Data @{
                        path = $path; mode = $ev.mode; owner = $ev.owner; sha256 = $ev.sha256
                    }))
            }
        } catch { }
    }

    return $records.ToArray()
}
