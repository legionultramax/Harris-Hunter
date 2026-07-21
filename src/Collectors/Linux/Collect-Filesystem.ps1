# Collect-Filesystem.ps1 (Linux) - drop-site + suspicious-file triage.
# ATT&CK: T1204 (user execution), T1222 (permissions). Focuses on common staging locations
# and world-writable files rather than walking the whole filesystem.
#
# Every walk goes through Invoke-HHBoundedFind (-xdev + timeout), so a slow/huge/remote mount is
# bounded and can never hang the run (the same guard the SUID/capability collector uses).

function Collect-Filesystem {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()
    $cap = 500

    if (-not (Test-HHCommand 'find')) {
        return $records.ToArray()
    }

    # Files staged in world-writable/tmp locations (classic payload drop sites). -xdev keeps each
    # walk on that one (small, local) tmpfs; the timeout bounds a pathological case.
    $count = 0
    foreach ($dir in '/tmp', '/var/tmp', '/dev/shm') {
        if ($count -ge $cap) { break }
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        $r = Invoke-HHBoundedFind -Root $dir -Predicate @('-type', 'f') -TimeoutSec 60
        foreach ($path in @($r.Files | Select-Object -First ($cap - $count))) {
            $count++
            $ev = Get-HHLinuxFileEvidence -Path $path
            $records.Add((New-EvidenceRecord -ArtifactType 'tmp_file' -Collector 'Collect-Filesystem' `
                -Source $dir -Attack @('T1204') -Context $Context -Data @{
                    path = $path; size = $ev.size; mode = $ev.mode; owner = $ev.owner
                    mtime_utc = $ev.mtime_utc; sha256 = $ev.sha256
                }))
            if ($count -ge $cap) { break }
        }
    }

    # World-writable files under system dirs. Each root walked with -xdev (stays on its filesystem)
    # under a timeout, so a large /var or /usr degrades gracefully instead of stalling the run.
    $wwCount = 0
    foreach ($root in '/etc', '/usr', '/bin', '/sbin', '/opt', '/var') {
        if ($wwCount -ge $cap) { break }
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $r = Invoke-HHBoundedFind -Root $root -Predicate @('-type', 'f', '-perm', '-0002') -TimeoutSec 120
        foreach ($path in @($r.Files | Select-Object -First ($cap - $wwCount))) {
            $wwCount++
            $ev = Get-HHLinuxFileEvidence -Path $path
            $records.Add((New-EvidenceRecord -ArtifactType 'world_writable_file' -Collector 'Collect-Filesystem' `
                -Source 'find -xdev -perm -0002' -Attack @('T1222.002') -Context $Context -Data @{
                    path = $path; mode = $ev.mode; owner = $ev.owner; sha256 = $ev.sha256
                }))
            if ($wwCount -ge $cap) { break }
        }
    }

    return $records.ToArray()
}
