# Collect-System.ps1 (Linux) - OS, kernel, uptime, boot time.

function Collect-System {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    $osRelease = @{}
    try {
        if (Test-Path -LiteralPath '/etc/os-release') {
            foreach ($line in (Get-Content -LiteralPath '/etc/os-release' -ErrorAction Stop)) {
                if ($line -match '^([A-Z_]+)="?(.*?)"?$') { $osRelease[$Matches[1]] = $Matches[2] }
            }
        }
    } catch { }

    $uname = $null
    try { $uname = (& uname -a 2>$null); if ($uname) { $uname = $uname.Trim() } } catch { }

    $bootUtc = $null
    try {
        $b = (& uptime -s 2>$null)   # "2026-07-01 08:15:00" (local)
        if ($b) { $bootUtc = ([datetime]::Parse($b.Trim())).ToUniversalTime().ToString('o') }
    } catch { }

    $uptimeSeconds = $null
    try {
        if (Test-Path -LiteralPath '/proc/uptime') {
            $uptimeSeconds = [double](((Get-Content -LiteralPath '/proc/uptime' -Raw) -split '\s+')[0])
        }
    } catch { }

    $kernel = $null; try { $kernel = (& uname -r 2>$null); if ($kernel) { $kernel = $kernel.Trim() } } catch { }
    $arch   = $null; try { $arch   = (& uname -m 2>$null); if ($arch)   { $arch   = $arch.Trim() } } catch { }

    $records.Add((New-EvidenceRecord -ArtifactType 'os_info' -Collector 'Collect-System' `
        -Source '/etc/os-release, uname, /proc/uptime' -Context $Context -Data @{
            distro         = $osRelease['PRETTY_NAME']
            id             = $osRelease['ID']
            version_id     = $osRelease['VERSION_ID']
            kernel         = $kernel
            arch           = $arch
            uname          = $uname
            boot_time_utc  = $bootUtc
            uptime_seconds = $uptimeSeconds
        }))

    return $records.ToArray()
}
