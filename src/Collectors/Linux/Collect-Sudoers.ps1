# Collect-Sudoers.ps1 (Linux) - sudo configuration. ATT&CK: T1548.003 (sudo/sudo caching).
# NOPASSWD rules are flagged (privilege escalation / persistence). Requires root to read.

function Collect-Sudoers {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    $files = @('/etc/sudoers')
    try { if (Test-Path -LiteralPath '/etc/sudoers.d') { $files += (Get-ChildItem -LiteralPath '/etc/sudoers.d' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName) } } catch { }

    foreach ($path in $files) {
        try {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
            $ev = Get-HHLinuxFileEvidence -Path $path
            $rules = @(Get-Content -LiteralPath $path -ErrorAction Stop | Where-Object { $_ -and $_ -notmatch '^\s*#' -and $_.Trim() })
            $nopasswd = @($rules | Where-Object { $_ -match 'NOPASSWD' })
            $attack = if ($nopasswd.Count -gt 0) { @('T1548.003') } else { @() }
            $records.Add((New-EvidenceRecord -ArtifactType 'sudoers' -Collector 'Collect-Sudoers' `
                -Source $path -Attack $attack -Context $Context -Data @{
                    path = $path; rules = $rules; nopasswd_rules = $nopasswd; sha256 = $ev.sha256; owner = $ev.owner
                }))
        } catch { }
    }

    if ($records.Count -eq 0) {
        $records.Add((New-EvidenceRecord -ArtifactType 'sudoers_note' -Collector 'Collect-Sudoers' `
            -Source '/etc/sudoers' -Context $Context -Data @{ collected = $false; reason = 'unreadable (needs root) or absent' }))
    }
    return $records.ToArray()
}
