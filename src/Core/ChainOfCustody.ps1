# ChainOfCustody.ps1 - append-only, hash-chained custody ledger + time integrity.
# Each ledger entry embeds the previous entry's hash, so any later edit/removal breaks
# the chain and is detectable by Test-ChainOfCustody. This is tamper-evidence for the
# sequence of collection events; per-artifact file hashes in the manifest cover content.

$script:HHCocPath     = $null
$script:HHCocSeq      = 0
$script:HHCocGenesis  = ('0' * 64)
$script:HHCocPrevHash = $script:HHCocGenesis

function ConvertTo-HHCocCanonical {
    # Produce the canonical JSON string that the entry hash is computed over, IDENTICALLY on the
    # write and the verify side. PowerShell 7's ConvertFrom-Json auto-converts ISO-8601 strings to
    # [datetime] (5.1 leaves them as [string]), and re-serializing a [datetime] drops trailing
    # fractional-second zeros (.9235900Z -> .92359Z) - which silently broke the hash on PS7. We
    # normalize every [datetime]/[datetimeoffset] back to its round-trip 'o' string (which pads to a
    # fixed 7 fractional digits and matches the write-side ToString('o')), so the canonical form is
    # independent of PowerShell version and locale. Recursive so nested details are covered too.
    param($Value)
    if ($Value -is [datetime])        { return ([datetime]$Value).ToString('o') }
    if ($Value -is [datetimeoffset])  { return ([datetimeoffset]$Value).ToString('o') }
    if ($Value -is [string])          { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $Value.Keys) { $o[[string]$k] = ConvertTo-HHCocCanonical $Value[$k] }
        return $o
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $o = [ordered]@{}
        foreach ($p in $Value.PSObject.Properties) { $o[$p.Name] = ConvertTo-HHCocCanonical $p.Value }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return @(foreach ($item in $Value) { ConvertTo-HHCocCanonical $item })
    }
    return $Value
}

function Get-HHCocEntryHash {
    # Deterministic entry hash: prev_hash + canonical-JSON of the 5 hashed fields.
    param([string]$PrevHash, $Entry)
    $canonical = (ConvertTo-HHCocCanonical $Entry) | ConvertTo-Json -Depth 12 -Compress
    return Get-HHStringHash -InputString ($PrevHash + $canonical)
}

function Initialize-ChainOfCustody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$CocFile = 'coc.jsonl'
    )
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $script:HHCocPath     = Join-Path $OutputPath $CocFile
    $script:HHCocSeq      = 0
    $script:HHCocPrevHash = $script:HHCocGenesis
    Set-Content -LiteralPath $script:HHCocPath -Value $null -Encoding utf8
}

function Add-CocEvent {
    <#
    .SYNOPSIS
        Append one hash-chained event to the custody ledger.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EventType,
        [hashtable]$Details = @{}
    )
    if (-not $script:HHCocPath) { throw 'Chain of custody not initialized. Call Initialize-ChainOfCustody first.' }

    $script:HHCocSeq++
    $entry = [ordered]@{
        seq       = $script:HHCocSeq
        ts_utc    = [DateTime]::UtcNow.ToString('o')
        event     = $EventType
        details   = $Details
        prev_hash = $script:HHCocPrevHash
    }

    $entryHash = Get-HHCocEntryHash -PrevHash $script:HHCocPrevHash -Entry $entry
    $entry['entry_hash'] = $entryHash
    $script:HHCocPrevHash = $entryHash

    ($entry | ConvertTo-Json -Depth 12 -Compress) | Add-Content -LiteralPath $script:HHCocPath -Encoding utf8
}

function Test-ChainOfCustody {
    <#
    .SYNOPSIS
        Re-walk a custody ledger and confirm the hash chain is intact.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $prev     = $script:HHCocGenesis
    $seq      = 0
    $problems = [System.Collections.Generic.List[string]]::new()

    foreach ($line in Get-Content -LiteralPath $Path) {
        if (-not $line.Trim()) { continue }
        $obj = $line | ConvertFrom-Json
        $seq++

        if ($obj.seq -ne $seq)          { $problems.Add("sequence gap at line $seq (recorded seq $($obj.seq))") }
        if ($obj.prev_hash -ne $prev)   { $problems.Add("broken chain at seq $($obj.seq): prev_hash does not match previous entry_hash") }

        $recon = [ordered]@{
            seq       = $obj.seq
            ts_utc    = $obj.ts_utc
            event     = $obj.event
            details   = $obj.details
            prev_hash = $obj.prev_hash
        }
        $expected = Get-HHCocEntryHash -PrevHash ([string]$obj.prev_hash) -Entry $recon
        if ($expected -ne $obj.entry_hash) { $problems.Add("entry_hash mismatch at seq $($obj.seq) (content altered)") }

        $prev = $obj.entry_hash
    }

    [pscustomobject]@{
        Valid    = ($problems.Count -eq 0)
        Entries  = $seq
        Problems = $problems.ToArray()
    }
}

function Get-TimeIntegrity {
    <#
    .SYNOPSIS
        Capture the host clock context and, best-effort, its skew from an NTP source.
        Skew matters for correlating this host's timeline against others in an incident.
    #>
    [CmdletBinding()]
    param(
        [string]$NtpServer = 'time.windows.com',
        [int]$TimeoutSeconds = 10
    )

    $now = [DateTimeOffset]::Now
    $tzId = try { (Get-TimeZone).Id } catch { [System.TimeZoneInfo]::Local.Id }
    $result = [ordered]@{
        utc              = $now.UtcDateTime.ToString('o')
        local            = $now.ToString('o')
        timezone         = $tzId
        utc_offset       = [System.TimeZoneInfo]::Local.GetUtcOffset($now.DateTime).ToString()
        ntp_server       = $NtpServer
        ntp_skew_seconds = $null
        ntp_status       = 'not_checked'
    }

    if ($script:HHIsLinux) {
        # Linux: prefer chrony's measured offset, then timedatectl's sync status.
        try {
            if (Test-HHCommand 'chronyc') {
                $tr = & chronyc tracking 2>$null | Out-String
                $m = [regex]::Match($tr, 'System time\s*:\s*([0-9.]+)\s*seconds\s*(fast|slow)')
                if ($m.Success) {
                    $val = [double]$m.Groups[1].Value
                    if ($m.Groups[2].Value -eq 'slow') { $val = -$val }
                    $result.ntp_skew_seconds = $val
                    $result.ntp_status = 'measured'
                }
            }
            if ($result.ntp_status -eq 'not_checked' -and (Test-HHCommand 'timedatectl')) {
                $sync = & timedatectl show -p NTPSynchronized --value 2>$null
                if ($sync) { $result.ntp_status = "ntp_synchronized=$($sync.Trim())" }
            }
        } catch { $result.ntp_status = "error: $($_.Exception.Message)" }
        return $result
    }

    # Windows: measure skew against an NTP source via w32tm (in a timeout-guarded job).
    try {
        $job = Start-Job -ScriptBlock {
            param($srv)
            & w32tm /stripchart /computer:$srv /samples:1 /dataonly 2>$null
        } -ArgumentList $NtpServer

        if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
            $out = Receive-Job -Job $job
            $text = ($out | Out-String)
            $m = [regex]::Match($text, '([+-]\d+(?:\.\d+)?)\s*s')
            if ($m.Success) {
                $result.ntp_skew_seconds = [double]$m.Groups[1].Value
                $result.ntp_status       = 'measured'
            }
            else {
                $result.ntp_status = 'unreachable_or_unparsed'
            }
        }
        else {
            $result.ntp_status = 'timeout'
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    catch {
        $result.ntp_status = "error: $($_.Exception.Message)"
    }

    return $result
}
