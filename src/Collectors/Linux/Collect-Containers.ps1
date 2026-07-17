# Collect-Containers.ps1 (Linux) - running containers (docker/podman).
# ATT&CK: T1610 (deploy container), T1611 (escape to host).

function Collect-Containers {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()
    $found = $false

    foreach ($engine in 'docker', 'podman') {
        if (-not (Test-HHCommand $engine)) { continue }
        try {
            # Tab-separated: id, image, command, status, names.
            $fmt = '{{.ID}}\t{{.Image}}\t{{.Command}}\t{{.Status}}\t{{.Names}}'
            $out = & $engine ps -a --no-trunc --format $fmt 2>$null
            foreach ($line in $out) {
                if (-not $line.Trim()) { continue }
                $found = $true
                $f = $line -split "`t"
                $records.Add((New-EvidenceRecord -ArtifactType 'container' -Collector 'Collect-Containers' `
                    -Source "$engine ps" -Attack @('T1610') -Context $Context -Data @{
                        engine  = $engine
                        id      = $f[0]
                        image   = if ($f.Count -gt 1) { $f[1] } else { $null }
                        command = if ($f.Count -gt 2) { $f[2] } else { $null }
                        status  = if ($f.Count -gt 3) { $f[3] } else { $null }
                        name    = if ($f.Count -gt 4) { $f[4] } else { $null }
                    }))
            }
        } catch { }
    }

    if (-not $found) {
        $records.Add((New-EvidenceRecord -ArtifactType 'container_note' -Collector 'Collect-Containers' `
            -Source 'docker/podman' -Context $Context -Data @{ collected = $true; containers_found = 0 }))
    }
    return $records.ToArray()
}
