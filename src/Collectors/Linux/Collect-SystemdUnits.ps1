# Collect-SystemdUnits.ps1 (Linux) - systemd services + timers.
# ATT&CK: T1543.002 (systemd service), T1053.006 (systemd timer).

function Collect-SystemdUnits {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()
    if (-not (Test-HHCommand 'systemctl')) {
        $records.Add((New-EvidenceRecord -ArtifactType 'systemd_note' -Collector 'Collect-SystemdUnits' `
            -Source 'systemctl' -Context $Context -Data @{ collected = $false; reason = 'systemctl not available' }))
        return $records.ToArray()
    }

    # Service unit files + enable state.
    try {
        foreach ($line in (& systemctl list-unit-files --type=service --no-legend --no-pager 2>$null)) {
            $f = $line -split '\s+' | Where-Object { $_ }
            if ($f.Count -ge 2) {
                $records.Add((New-EvidenceRecord -ArtifactType 'systemd_service' -Collector 'Collect-SystemdUnits' `
                    -Source 'systemctl list-unit-files' -Attack @('T1543.002') -Context $Context -Data @{
                        unit = $f[0]; state = $f[1]
                    }))
            }
        }
    } catch { }

    # Timers (scheduled execution).
    try {
        foreach ($line in (& systemctl list-timers --all --no-legend --no-pager 2>$null)) {
            if ($line.Trim()) {
                $records.Add((New-EvidenceRecord -ArtifactType 'systemd_timer' -Collector 'Collect-SystemdUnits' `
                    -Source 'systemctl list-timers' -Attack @('T1053.006') -Context $Context -Data @{ raw = $line.Trim() }))
            }
        }
    } catch { }

    # Admin-added unit files under /etc/systemd/system are high-value: capture + hash.
    foreach ($dir in '/etc/systemd/system', '/run/systemd/system') {
        try {
            if (Test-Path -LiteralPath $dir) {
                Get-ChildItem -LiteralPath $dir -Recurse -File -Include '*.service','*.timer' -ErrorAction SilentlyContinue |
                    Select-Object -First 200 | ForEach-Object {
                        $ev = Get-HHLinuxFileEvidence -Path $_.FullName
                        $records.Add((New-EvidenceRecord -ArtifactType 'systemd_unit_file' -Collector 'Collect-SystemdUnits' `
                            -Source $dir -Attack @('T1543.002') -Context $Context -Data @{
                                path = $_.FullName; sha256 = $ev.sha256; owner = $ev.owner; mtime_utc = $ev.mtime_utc
                            }))
                    }
            }
        } catch { }
    }

    return $records.ToArray()
}
