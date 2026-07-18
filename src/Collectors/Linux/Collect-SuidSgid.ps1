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

    # File capabilities (getcap) - cap_setuid/cap_net_raw etc. can grant escalation. Parse the
    # path + capability set and flag dangerous capabilities so downstream detection can act on
    # structured fields, not just a raw line. Handles both `path caps` and `path = caps` formats.
    if (Test-HHCommand 'getcap') {
        try {
            foreach ($line in (& getcap -r / 2>$null | Select-Object -First $cap)) {
                $t = if ($line) { $line.Trim() } else { '' }
                if (-not $t) { continue }
                $capPath = $null; $caps = $null
                $m = [regex]::Match($t, '^(?<p>\S+)\s*=?\s*(?<c>.+)$')
                if ($m.Success) { $capPath = $m.Groups['p'].Value; $caps = $m.Groups['c'].Value.Trim() }
                $dangerous = ($caps -match '(?i)cap_(setuid|setgid|sys_admin|dac_override|dac_read_search|sys_ptrace|sys_module)')
                $ev = if ($capPath) { Get-HHLinuxFileEvidence -Path $capPath } else { $null }
                $records.Add((New-EvidenceRecord -ArtifactType 'file_capability' -Collector 'Collect-SuidSgid' `
                    -Source 'getcap -r /' -Attack @('T1548.001') -Context $Context -Data @{
                        path         = $capPath
                        capabilities = $caps
                        dangerous    = $dangerous
                        owner        = if ($ev) { $ev.owner } else { $null }
                        sha256       = if ($ev) { $ev.sha256 } else { $null }
                        raw          = $t
                    }))
            }
        } catch { }
    }

    return $records.ToArray()
}
