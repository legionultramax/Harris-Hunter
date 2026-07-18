# RiskScore.ps1 - ATT&CK mapping + two-level risk scoring (blueprint §13, §14, §28.6).
# score_finding = base_severity x confidence_factor + bounded context modifiers.
# score_host    = max finding score + ATT&CK-tactic breadth bonus + recency bonus (capped 100).
# Every score stores its computation breakdown for analyst transparency. Pure - no I/O except
# Get-HHAttackMap which reads the data-driven technique->tactic table.

$script:HHScoreBase = @{ critical = 90; high = 70; medium = 45; low = 20; informational = 5 }
$script:HHScoreConf = @{ confirmed = 1.0; high = 0.9; medium = 0.7; low = 0.5 }

$script:HHRiskBands = @(
    @{ min = 0;  max = 24;  band = 'clean' },
    @{ min = 25; max = 49;  band = 'low' },
    @{ min = 50; max = 69;  band = 'suspicious' },
    @{ min = 70; max = 89;  band = 'likely_compromise' },
    @{ min = 90; max = 100; band = 'confirmed_critical' }
)

function Get-HHRiskBand {
    param([int]$Score)
    foreach ($b in $script:HHRiskBands) { if ($Score -ge $b.min -and $Score -le $b.max) { return $b.band } }
    return 'unknown'
}

$script:HHAttackMapCache = $null
function Get-HHAttackMap {
    # Load the technique->{tactic,name} table (cached). Returns a hashtable.
    [CmdletBinding()]
    param([string]$Path)
    if (-not $Path) {
        $root = if ($script:HHModuleRoot) { $script:HHModuleRoot } else { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
        $Path = Join-Path $root 'config/detection/attack-map.json'
    }
    $map = @{}
    try {
        $obj = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
        foreach ($p in $obj.PSObject.Properties) {
            if ($p.Name -eq '_comment') { continue }
            $map[$p.Name] = @{ tactic = $p.Value.tactic; name = $p.Value.name }
        }
    } catch { }
    return $map
}

function Resolve-HHFindingAttack {
    # Fill the tactic (and technique name) on each finding.detection.mitre_attack entry from the
    # map, and return the finding's distinct tactic list.
    param([Parameter(Mandatory)]$Finding, $Map)
    if (-not $Map) { $Map = Get-HHAttackMap }
    $tactics = [System.Collections.Generic.List[string]]::new()
    $det = $Finding['detection']
    if ($det -and $det['mitre_attack']) {
        foreach ($e in @($det['mitre_attack'])) {
            $tech = [string](Get-HHField $e 'technique')
            if ($tech -and $Map.ContainsKey($tech)) {
                $tac = $Map[$tech].tactic
                if ($e -is [System.Collections.IDictionary]) {
                    $e['tactic'] = $tac
                    if (-not $e.Contains('technique_name')) { $e['technique_name'] = $Map[$tech].name }
                }
                if ($tac -and -not $tactics.Contains($tac)) { $tactics.Add($tac) }
            }
        }
    }
    return $tactics.ToArray()
}

function Get-HHRiskScore {
    <#
    .SYNOPSIS
        Compute a finding's risk score (0-100), store it + a computation breakdown on the finding,
        and return the finding. Context flags come from the finding itself:
        host.asset_criticality, corroborated, internet_exposed, exception_matched.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Finding, $Map)

    $sev  = [string]$Finding['severity']
    $conf = [string]$Finding['confidence']
    $base = if ($script:HHScoreBase.ContainsKey($sev))  { $script:HHScoreBase[$sev] }  else { 5 }
    $cf   = if ($script:HHScoreConf.ContainsKey($conf)) { $script:HHScoreConf[$conf] } else { 0.5 }

    $breakdown = [ordered]@{
        base_severity     = $base
        confidence_factor = $cf
        subtotal          = [math]::Round($base * $cf, 2)
        modifiers         = [System.Collections.Generic.List[object]]::new()
    }
    $score = $base * $cf

    $crit = [string](Get-HHField $Finding['host'] 'asset_criticality')
    if ($crit -eq 'crown_jewel') { $score += 10; $breakdown.modifiers.Add(@{ name = 'crown_jewel_asset'; delta = 10 }) }
    if ($Finding.Contains('corroborated') -and $Finding['corroborated']) { $score += 10; $breakdown.modifiers.Add(@{ name = 'corroborated'; delta = 10 }) }
    if ($Finding.Contains('internet_exposed') -and $Finding['internet_exposed']) { $score += 5; $breakdown.modifiers.Add(@{ name = 'internet_exposed'; delta = 5 }) }
    if ($Finding.Contains('exception_matched') -and $Finding['exception_matched']) { $score -= 10; $breakdown.modifiers.Add(@{ name = 'approved_exception'; delta = -10 }) }

    $final = [int][math]::Max(0, [math]::Min(100, [math]::Round($score)))
    $breakdown.final = $final
    $Finding['risk_score']    = $final
    $Finding['risk_breakdown'] = $breakdown
    return $Finding
}

function Get-HHHostScore {
    <#
    .SYNOPSIS
        Aggregate findings for one host into a host score (0-100) + band. Rewards kill-chain
        breadth: max finding score + 5 per extra ATT&CK tactic (cap 25) + 5 if any artifact < 7d old.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings, $Map, [datetime]$Now = ([DateTime]::UtcNow))
    if (-not $Map) { $Map = Get-HHAttackMap }
    if ($Findings.Count -eq 0) {
        return [ordered]@{ score = 0; band = 'clean'; max_finding = 0; tactics = @(); recency_bonus = 0; breadth_bonus = 0 }
    }

    $max = 0
    $tactics = [System.Collections.Generic.List[string]]::new()
    $recent = $false
    foreach ($f in $Findings) {
        $rs = if ($null -ne $f['risk_score']) { [int]$f['risk_score'] } else { 0 }
        if ($rs -gt $max) { $max = $rs }
        foreach ($t in (Resolve-HHFindingAttack -Finding $f -Map $Map)) { if (-not $tactics.Contains($t)) { $tactics.Add($t) } }
        $obs = [datetime]::MinValue
        if ($f['observed_at'] -and [datetime]::TryParse([string]$f['observed_at'], [ref]$obs)) {
            if (($Now - $obs.ToUniversalTime()).TotalDays -lt 7) { $recent = $true }
        }
    }

    $breadth = [math]::Min(25, 5 * [math]::Max(0, $tactics.Count - 1))
    $recencyBonus = if ($recent) { 5 } else { 0 }
    $score = [int][math]::Min(100, $max + $breadth + $recencyBonus)

    [ordered]@{
        score         = $score
        band          = Get-HHRiskBand -Score $score
        max_finding   = $max
        tactics       = $tactics.ToArray()
        breadth_bonus = $breadth
        recency_bonus = $recencyBonus
    }
}
