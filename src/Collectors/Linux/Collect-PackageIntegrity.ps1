# Collect-PackageIntegrity.ps1 (Linux) - package manager verification of on-disk files.
# ATT&CK: T1565.001 (stored data manipulation) / trojanized system binaries. Reports files
# that differ from what the package manager installed. Can be slow; output is capped.

function Collect-PackageIntegrity {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()
    $cap = 1000

    if (Test-HHCommand 'rpm') {
        try {
            $out = & rpm -Va 2>$null | Select-Object -First $cap
            foreach ($line in $out) {
                if (-not $line.Trim()) { continue }
                # Format: "SM5DLUGT c /path" - '5' means MD5/content differs.
                $records.Add((New-EvidenceRecord -ArtifactType 'package_verify' -Collector 'Collect-PackageIntegrity' `
                    -Source 'rpm -Va' -Attack @('T1565.001') -Context $Context -Data @{ manager = 'rpm'; entry = $line.Trim() }))
            }
            return $records.ToArray()
        } catch { }
    }

    if (Test-HHCommand 'debsums') {
        try {
            $out = & debsums -c 2>$null | Select-Object -First $cap   # -c lists only changed files
            foreach ($line in $out) {
                if (-not $line.Trim()) { continue }
                $records.Add((New-EvidenceRecord -ArtifactType 'package_verify' -Collector 'Collect-PackageIntegrity' `
                    -Source 'debsums -c' -Attack @('T1565.001') -Context $Context -Data @{ manager = 'debsums'; entry = $line.Trim() }))
            }
            return $records.ToArray()
        } catch { }
    }

    if (Test-HHCommand 'dpkg') {
        try {
            $out = & dpkg --verify 2>$null | Select-Object -First $cap
            foreach ($line in $out) {
                if (-not $line.Trim()) { continue }
                $records.Add((New-EvidenceRecord -ArtifactType 'package_verify' -Collector 'Collect-PackageIntegrity' `
                    -Source 'dpkg --verify' -Attack @('T1565.001') -Context $Context -Data @{ manager = 'dpkg'; entry = $line.Trim() }))
            }
            return $records.ToArray()
        } catch { }
    }

    $records.Add((New-EvidenceRecord -ArtifactType 'package_verify_note' -Collector 'Collect-PackageIntegrity' `
        -Source 'package manager' -Context $Context -Data @{ collected = $false; reason = 'no rpm/debsums/dpkg verification available' }))
    return $records.ToArray()
}
