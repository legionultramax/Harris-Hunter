# Collect-SuidSgid.ps1 (Linux) - setuid/setgid binaries + file capabilities.
# ATT&CK: T1548.001 (setuid/setgid). Attacker-planted setuid roots are a persistence/escalation.
#
# Scope is LOCAL real filesystems + high-risk volatile dirs (Get-HHLocalScanRoots) - never
# network/remote or drvfs/9p mounts. Every walk goes through Invoke-HHBoundedFind (-xdev + timeout),
# so a large or slow mount degrades gracefully instead of hanging. Capabilities are read by feeding
# the mount-bounded file list to `getcap <files>` (explicit args, NOT `getcap -r /`, which has no
# mount boundary and would recurse into every mounted filesystem).

function Collect-SuidSgid {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()
    $cap = 1000
    $capBudgetSec = 300  # overall wall-clock budget for the capability sweep
    $truncated = $false

    if (-not (Test-HHCommand 'find')) {
        $records.Add((New-EvidenceRecord -ArtifactType 'suid_sgid_scan_summary' -Collector 'Collect-SuidSgid' `
            -Source 'find' -Attack @() -Context $Context -Data @{ status = 'find_unavailable' }))
        return $records.ToArray()
    }

    $roots = @(Get-HHLocalScanRoots)

    # --- 1. SUID / SGID inventory across all local roots (deduped by path) ------------------
    $seenSuid = @{}
    foreach ($spec in @(@{ perm = '-4000'; kind = 'suid' }, @{ perm = '-2000'; kind = 'sgid' })) {
        foreach ($root in $roots) {
            if ($records.Count -ge $cap) { break }
            $r = Invoke-HHBoundedFind -Root $root -Predicate @('-type', 'f', '-perm', $spec.perm)
            if ($r.Truncated) { $truncated = $true }
            foreach ($path in $r.Files) {
                if ($seenSuid.ContainsKey($path)) { continue }
                $seenSuid[$path] = $true
                $ev = Get-HHLinuxFileEvidence -Path $path
                $records.Add((New-EvidenceRecord -ArtifactType 'suid_sgid_file' -Collector 'Collect-SuidSgid' `
                    -Source "find -xdev -perm $($spec.perm)" -Attack @('T1548.001') -Context $Context -Data @{
                        path = $path; kind = $spec.kind; mode = $ev.mode; owner = $ev.owner; group = $ev.group; sha256 = $ev.sha256
                    }))
                if ($records.Count -ge $cap) { break }
            }
        }
    }

    # --- 2. File capabilities on the SAME local roots --------------------------------------
    # Enumerate files with Invoke-HHBoundedFind (mount-bounded), then read caps in batches via
    # `getcap <files>` with explicit path args - never -r, so it cannot cross a filesystem boundary.
    if (Test-HHCommand 'getcap') {
        $seenCap = @{}
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        foreach ($root in $roots) {
            if ($sw.Elapsed.TotalSeconds -ge $capBudgetSec) { $truncated = $true; break }
            $r = Invoke-HHBoundedFind -Root $root -Predicate @('-type', 'f')
            if ($r.Truncated) { $truncated = $true }
            $files = $r.Files
            for ($i = 0; $i -lt $files.Count; $i += 500) {
                if ($sw.Elapsed.TotalSeconds -ge $capBudgetSec) { $truncated = $true; break }
                if ($records.Count -ge ($cap * 2)) { break }
                $batch = @($files[$i..([math]::Min($i + 499, $files.Count - 1))] | Where-Object { $_ })
                if ($batch.Count -eq 0) { continue }
                $capLines = @()
                try { $capLines = @(& getcap @batch 2>$null) } catch { }
                foreach ($line in $capLines) {
                    $t = if ($line) { $line.Trim() } else { '' }
                    if (-not $t) { continue }
                    $m = [regex]::Match($t, '^(?<p>\S+)\s*=?\s*(?<c>.+)$')
                    if (-not $m.Success) { continue }
                    $capPath = $m.Groups['p'].Value
                    if ($seenCap.ContainsKey($capPath)) { continue }
                    $seenCap[$capPath] = $true
                    $caps = $m.Groups['c'].Value.Trim()
                    $dangerous = ($caps -match '(?i)cap_(setuid|setgid|sys_admin|dac_override|dac_read_search|sys_ptrace|sys_module)')
                    $ev = Get-HHLinuxFileEvidence -Path $capPath
                    $records.Add((New-EvidenceRecord -ArtifactType 'file_capability' -Collector 'Collect-SuidSgid' `
                        -Source 'find -xdev | getcap' -Attack @('T1548.001') -Context $Context -Data @{
                            path         = $capPath
                            capabilities = $caps
                            dangerous    = $dangerous
                            owner        = if ($ev) { $ev.owner } else { $null }
                            sha256       = if ($ev) { $ev.sha256 } else { $null }
                            raw          = $t
                        }))
                }
            }
        }
    }

    # --- 3. Scope summary (honest coverage disclosure) -------------------------------------
    $records.Add((New-EvidenceRecord -ArtifactType 'suid_sgid_scan_summary' -Collector 'Collect-SuidSgid' `
        -Source 'find -xdev' -Attack @() -Context $Context -Data @{
            status          = 'completed'
            scan_roots      = $roots
            suid_sgid_count = $seenSuid.Count
            truncated       = $truncated
            note            = 'Scanned local filesystems + high-risk volatile dirs only; network/drvfs/pseudo mounts excluded by design.'
        }))

    return $records.ToArray()
}
