# Statistics.ps1 - host metadata (reused on every record) and run statistics.

function Get-HostMetadata {
    <#
    .SYNOPSIS
        Stable identity + OS facts for the host under examination. Embedded in every
        evidence record and the manifest so provenance survives outside the bundle.
    #>
    [CmdletBinding()]
    param()

    $hostname = try { [System.Net.Dns]::GetHostName() } catch { $env:COMPUTERNAME }

    $fqdn = $hostname
    try {
        $entry = [System.Net.Dns]::GetHostEntry($hostname)
        if ($entry.HostName) { $fqdn = $entry.HostName }
    } catch { }

    $hostId = $null
    try {
        $hostId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    } catch { }

    $os = $null; $cs = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { }
    try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem   -ErrorAction Stop } catch { }

    $ips = @()
    try {
        $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -and $_.IPAddress -ne '127.0.0.1' } |
            Select-Object -ExpandProperty IPAddress -Unique)
    } catch {
        try {
            $ips = @([System.Net.Dns]::GetHostAddresses($hostname) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' -and $_.ToString() -ne '127.0.0.1' } |
                ForEach-Object { $_.ToString() } | Select-Object -Unique)
        } catch { }
    }

    [ordered]@{
        hostname         = $hostname
        fqdn             = $fqdn
        host_id          = $hostId
        os               = if ($os) { $os.Caption } else { [System.Environment]::OSVersion.VersionString }
        os_version       = if ($os) { $os.Version } else { [System.Environment]::OSVersion.Version.ToString() }
        os_build         = if ($os) { $os.BuildNumber } else { $null }
        domain           = if ($cs) { $cs.Domain } else { $env:USERDNSDOMAIN }
        is_domain_joined = if ($cs) { [bool]$cs.PartOfDomain } else { $null }
        ips              = $ips
        collected_at_utc = [DateTime]::UtcNow.ToString('o')
    }
}

function New-HHRunStats {
    <#
    .SYNOPSIS
        Fresh run-statistics accumulator the orchestrator updates as collectors run.
    #>
    [pscustomobject]@{
        StartedUtc         = [DateTime]::UtcNow
        FinishedUtc        = $null
        CollectorsRun      = 0
        CollectorsFailed   = 0
        CollectorsSkipped  = 0
        TotalRecords       = 0
        PerCollector       = [ordered]@{}
    }
}

function Add-HHCollectorStat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Stats,
        [Parameter(Mandatory)][string]$Collector,
        [int]$Records = 0,
        [double]$DurationMs = 0,
        [ValidateSet('ok', 'failed', 'skipped')][string]$Status = 'ok'
    )
    $Stats.PerCollector[$Collector] = [ordered]@{
        records     = $Records
        duration_ms = [math]::Round($DurationMs, 1)
        status      = $Status
    }
    switch ($Status) {
        'ok'      { $Stats.CollectorsRun++;     $Stats.TotalRecords += $Records }
        'failed'  { $Stats.CollectorsFailed++ }
        'skipped' { $Stats.CollectorsSkipped++ }
    }
}
