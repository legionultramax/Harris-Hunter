# Collect-KernelModules.ps1 (Linux) - loaded kernel modules + taint state.
# ATT&CK: T1547.006 (kernel modules / LKM rootkits).

function Collect-KernelModules {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    # Taint flag - a non-zero value can indicate out-of-tree / unsigned modules.
    try {
        if (Test-Path -LiteralPath '/proc/sys/kernel/tainted') {
            $tainted = (Get-Content -LiteralPath '/proc/sys/kernel/tainted' -Raw -ErrorAction Stop).Trim()
            $records.Add((New-EvidenceRecord -ArtifactType 'kernel_taint' -Collector 'Collect-KernelModules' `
                -Source '/proc/sys/kernel/tainted' -Context $Context -Data @{ tainted = $tainted }))
        }
    } catch { }

    # Loaded modules from /proc/modules (name size refcount used_by address).
    try {
        foreach ($line in (Get-Content -LiteralPath '/proc/modules' -ErrorAction Stop)) {
            if (-not $line.Trim()) { continue }
            $f = $line -split '\s+'
            $records.Add((New-EvidenceRecord -ArtifactType 'kernel_module' -Collector 'Collect-KernelModules' `
                -Source '/proc/modules' -Attack @('T1547.006') -Context $Context -Data @{
                    name = $f[0]; size = if ($f.Count -gt 1) { $f[1] } else { $null }
                    refcount = if ($f.Count -gt 2) { $f[2] } else { $null }
                    used_by = if ($f.Count -gt 3 -and $f[3] -ne '-') { $f[3] } else { $null }
                }))
        }
    } catch {
        if (Test-HHCommand 'lsmod') {
            try {
                & lsmod 2>$null | Select-Object -Skip 1 | ForEach-Object {
                    $f = $_ -split '\s+'
                    $records.Add((New-EvidenceRecord -ArtifactType 'kernel_module' -Collector 'Collect-KernelModules' `
                        -Source 'lsmod' -Attack @('T1547.006') -Context $Context -Data @{ name = $f[0]; size = $f[1] }))
                }
            } catch { }
        }
    }

    return $records.ToArray()
}
