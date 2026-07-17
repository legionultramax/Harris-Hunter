# Collect-SuidSgid.ps1 (Linux) - setuid/setgid binaries + file capabilities.
# ATT&CK: T1548.001 (setuid/setgid). Attacker-planted setuid roots are a persistence/escalation.

function Collect-SuidSgid {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()
    $cap = 1000

    if (Test-HHCommand 'find') {
        foreach ($spec in @(@{perm='-4000'; kind='suid'}, @{perm='-2000'; kind='sgid'})) {
            try {
                $found = & find / -xdev -type f -perm $spec.perm 2>$null | Select-Object -First $cap
                foreach ($path in $found) {
                    if (-not $path) { continue }
                    $ev = Get-HHLinuxFileEvidence -Path $path
                    $records.Add((New-EvidenceRecord -ArtifactType 'suid_sgid_file' -Collector 'Collect-SuidSgid' `
                        -Source "find -perm $($spec.perm)" -Attack @('T1548.001') -Context $Context -Data @{
                            path = $path; kind = $spec.kind; mode = $ev.mode; owner = $ev.owner; group = $ev.group; sha256 = $ev.sha256
                        }))
                }
            } catch { }
        }
    }

    # File capabilities (getcap) - cap_setuid/cap_net_raw etc. can grant escalation.
    if (Test-HHCommand 'getcap') {
        try {
            foreach ($line in (& getcap -r / 2>$null | Select-Object -First $cap)) {
                if (-not $line.Trim()) { continue }
                $records.Add((New-EvidenceRecord -ArtifactType 'file_capability' -Collector 'Collect-SuidSgid' `
                    -Source 'getcap -r /' -Attack @('T1548.001') -Context $Context -Data @{ raw = $line.Trim() }))
            }
        } catch { }
    }

    return $records.ToArray()
}
