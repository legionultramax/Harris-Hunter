# Collect-MemoryHints.ps1 (Linux) - memory-relevant config pointers (NOT a memory capture).
# Records where volatile evidence lives so responders can target full-capture tooling next.

function Collect-MemoryHints {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    $mem = @{}
    try {
        foreach ($line in (Get-Content -LiteralPath '/proc/meminfo' -ErrorAction Stop)) {
            if ($line -match '^(MemTotal|MemFree|MemAvailable|SwapTotal|SwapFree):\s*(\d+)\s*kB') {
                $mem[$Matches[1]] = [long]$Matches[2]
            }
        }
    } catch { }

    $swaps = @()
    try {
        if (Test-Path -LiteralPath '/proc/swaps') {
            $swaps = @(Get-Content -LiteralPath '/proc/swaps' -ErrorAction Stop | Select-Object -Skip 1 | Where-Object { $_.Trim() })
        }
    } catch { }

    $kcore = $false
    try { $kcore = (Test-Path -LiteralPath '/proc/kcore' -ErrorAction SilentlyContinue) } catch { }

    $records.Add((New-EvidenceRecord -ArtifactType 'memory_summary' -Collector 'Collect-MemoryHints' `
        -Source '/proc/meminfo, /proc/swaps, /proc/kcore' -Context $Context -Data @{
            mem_total_kb   = $mem['MemTotal']
            mem_free_kb    = $mem['MemFree']
            swap_total_kb  = $mem['SwapTotal']
            swap_devices   = $swaps
            kcore_present  = $kcore
            note           = 'Pointers only; use dedicated tooling (e.g. AVML/LiME) for a full memory capture.'
        }))

    return $records.ToArray()
}
