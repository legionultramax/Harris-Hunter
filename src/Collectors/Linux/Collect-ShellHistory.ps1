# Collect-ShellHistory.ps1 (Linux) - per-user shell history (capped).
# ATT&CK: T1552.003 (bash history). User content, so it runs ONLY in 'full' mode.

function Collect-ShellHistory {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    if ($Context.CollectionMode -ne 'full') {
        $records.Add((New-EvidenceRecord -ArtifactType 'shell_history_note' -Collector 'Collect-ShellHistory' `
            -Source 'collection_mode' -Context $Context -Data @{
                collected = $false
                reason    = "collection_mode is '$($Context.CollectionMode)'; shell history is user content, collected only in 'full' mode."
            }))
        return $records.ToArray()
    }

    $capPerFile = 2000
    foreach ($u in (Get-HHLinuxUsers)) {
        if (-not $u.home -or -not (Test-Path -LiteralPath $u.home -ErrorAction SilentlyContinue)) { continue }
        foreach ($hf in '.bash_history', '.zsh_history', '.sh_history', '.python_history') {
            $path = Join-Path $u.home $hf
            try {
                if (Test-Path -LiteralPath $path -PathType Leaf) {
                    $ev = Get-HHLinuxFileEvidence -Path $path
                    $lines = @(Get-Content -LiteralPath $path -Tail $capPerFile -ErrorAction Stop | Where-Object { $_ -and $_.Trim() })
                    $records.Add((New-EvidenceRecord -ArtifactType 'shell_history' -Collector 'Collect-ShellHistory' `
                        -Source $path -Attack @('T1552.003') -Context $Context -Data @{
                            user = $u.name; file = $path; shell_file = $hf; line_count = $lines.Count
                            commands = $lines; sha256 = $ev.sha256
                        }))
                }
            } catch { }
        }
    }

    if ($records.Count -eq 0) {
        $records.Add((New-EvidenceRecord -ArtifactType 'shell_history_note' -Collector 'Collect-ShellHistory' `
            -Source 'shell history' -Context $Context -Data @{ collected = $true; histories_found = 0 }))
    }
    return $records.ToArray()
}
