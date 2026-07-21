# Collect-PackageIntegrity.ps1 (Linux) - package manager verification of on-disk files.
# ATT&CK: T1565.001 (stored data manipulation) / trojanized system binaries. Reports files
# that differ from what the package manager installed.
#
# rpm -Va / debsums -c / dpkg --verify re-hash every packaged file and can run for minutes, so each
# runs through Invoke-HHBoundedTool (hard timeout) - a package-heavy host degrades gracefully with a
# truncated flag instead of stalling the whole collection.

function Collect-PackageIntegrity {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()
    $cap = 1000
    $verifyTimeout = 300

    $tools = @(
        @{ cmd = 'rpm';     args = @('-Va');      manager = 'rpm';     source = 'rpm -Va' }
        @{ cmd = 'debsums'; args = @('-c');       manager = 'debsums'; source = 'debsums -c' }  # -c: changed files only
        @{ cmd = 'dpkg';    args = @('--verify'); manager = 'dpkg';    source = 'dpkg --verify' }
    )

    foreach ($tool in $tools) {
        if (-not (Test-HHCommand $tool.cmd)) { continue }
        $r = Invoke-HHBoundedTool -Command $tool.cmd -Arguments $tool.args -TimeoutSec $verifyTimeout -Max $cap
        foreach ($line in $r.Lines) {
            if (-not $line.Trim()) { continue }
            # rpm format: "SM5DLUGT c /path" - '5' means MD5/content differs.
            $records.Add((New-EvidenceRecord -ArtifactType 'package_verify' -Collector 'Collect-PackageIntegrity' `
                -Source $tool.source -Attack @('T1565.001') -Context $Context -Data @{ manager = $tool.manager; entry = $line.Trim() }))
        }
        if ($r.Truncated) {
            $records.Add((New-EvidenceRecord -ArtifactType 'package_verify_note' -Collector 'Collect-PackageIntegrity' `
                -Source $tool.source -Context $Context -Data @{
                    collected = $true; truncated = $true
                    reason = "$($tool.source) exceeded ${verifyTimeout}s and was bounded; results are partial." }))
        }
        return $records.ToArray()   # first available verifier wins
    }

    $records.Add((New-EvidenceRecord -ArtifactType 'package_verify_note' -Collector 'Collect-PackageIntegrity' `
        -Source 'package manager' -Context $Context -Data @{ collected = $false; reason = 'no rpm/debsums/dpkg verification available' }))
    return $records.ToArray()
}
