# Collect-Accounts.ps1 (Linux) - users, groups, and shadow METADATA (never the hash).
# ATT&CK: T1136 (create account), T1078 (valid accounts). Honors data minimization: password
# hashes from /etc/shadow are NOT collected - only status/aging metadata.

function Collect-Accounts {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    # Users from /etc/passwd (flag non-root UID 0 accounts - a classic backdoor).
    foreach ($u in (Get-HHLinuxUsers)) {
        $attack = @()
        if ($u.uid -eq '0' -and $u.name -ne 'root') { $attack += 'T1136.001' }
        $records.Add((New-EvidenceRecord -ArtifactType 'local_user' -Collector 'Collect-Accounts' `
            -Source '/etc/passwd' -Attack $attack -Context $Context -Data @{
                name = $u.name; uid = $u.uid; gid = $u.gid; home = $u.home; shell = $u.shell
                uid0_non_root = ($u.uid -eq '0' -and $u.name -ne 'root')
            }))
    }

    # Groups.
    try {
        foreach ($l in (Get-Content -LiteralPath '/etc/group' -ErrorAction Stop)) {
            if (-not $l -or $l.StartsWith('#')) { continue }
            $p = $l -split ':'
            if ($p.Count -ge 4) {
                $members = @($p[3] -split ',' | Where-Object { $_ })
                $attack = if ($p[0] -in 'sudo','wheel','root','adm','docker') { @('T1098') } else { @() }
                $records.Add((New-EvidenceRecord -ArtifactType 'local_group' -Collector 'Collect-Accounts' `
                    -Source '/etc/group' -Attack $attack -Context $Context -Data @{ name = $p[0]; gid = $p[2]; members = $members }))
            }
        }
    } catch { }

    # Shadow METADATA only (requires root). Never emit the hash itself.
    try {
        foreach ($l in (Get-Content -LiteralPath '/etc/shadow' -ErrorAction Stop)) {
            if (-not $l -or $l.StartsWith('#')) { continue }
            $p = $l -split ':'
            if ($p.Count -lt 2) { continue }
            $hash = $p[1]
            $status = if ($hash -eq '') { 'empty_no_password' }
                      elseif ($hash -like '!*' -or $hash -like '*') { 'locked' }
                      else { 'set' }
            $attack = if ($status -eq 'empty_no_password') { @('T1078') } else { @() }
            $records.Add((New-EvidenceRecord -ArtifactType 'shadow_meta' -Collector 'Collect-Accounts' `
                -Source '/etc/shadow (metadata only)' -Attack $attack -Context $Context -Data @{
                    name            = $p[0]
                    password_status = $status
                    last_change     = if ($p.Count -gt 2) { $p[2] } else { $null }
                    max_age         = if ($p.Count -gt 4) { $p[4] } else { $null }
                    expire          = if ($p.Count -gt 7) { $p[7] } else { $null }
                }))
        }
    } catch { }

    return $records.ToArray()
}
