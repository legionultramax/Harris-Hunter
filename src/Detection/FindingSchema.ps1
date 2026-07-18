# FindingSchema.ps1 - the finding.v1 output contract (blueprint CGD-CA-DESIGN-001 §24).
# Every detection engine (Sigma now; IOC/native/behavioral later) emits findings ONLY through
# New-Finding, so the output is uniform and plugs straight into the future central platform.
# Depends on Core (Get-HHStringHash) and Normalize (Get-HHField). Pure - no I/O.

$script:HHFindingSchemaVersion = '1.0'
$script:HHFindingSeverities  = @('informational','low','medium','high','critical')
$script:HHFindingConfidences = @('low','medium','high','confirmed')
$script:HHFindingEngines     = @('clamav','yara','sigma','native','ioc','behavioral')

function New-HHFindingHost {
    # Map a collection host block -> finding.v1 host object.
    param($EventHost)
    $osRaw = [string](Get-HHField $EventHost 'os')
    $osFamily = if ($osRaw -match '(?i)win') { 'windows' } elseif ($osRaw -match '(?i)lin|mac|darwin') { 'linux' } else { $osRaw }
    [ordered]@{
        host_id           = Get-HHFirst @((Get-HHField $EventHost 'host_id'), (Get-HHField $EventHost 'hostname'))
        hostname          = Get-HHField $EventHost 'hostname'
        fqdn              = Get-HHField $EventHost 'fqdn'
        os_family         = $osFamily
        os_version        = Get-HHField $EventHost 'os_version'
        ip_addresses      = @(Get-HHField $EventHost 'ip_addresses')
        asset_criticality = Get-HHFirst @((Get-HHField $EventHost 'asset_criticality'), 'standard')
    }
}

function Get-HHFindingIdentity {
    # The stable, volatility-free identity of what a finding is ABOUT (not pid/time), used for
    # dedup. Kind-specific so the same artifact re-detected collapses to one finding.
    param([string]$Kind, $Artifact)
    switch ($Kind) {
        'persistence' { return (@((Get-HHField $Artifact 'mechanism'), (Get-HHField $Artifact 'value')) -join '|') }
        'process'     { return (@((Get-HHField $Artifact 'image_path'), (Get-HHField $Artifact 'image_sha256')) -join '|') }
        'network'     { return (@((Get-HHField $Artifact 'remote_addr'), (Get-HHField $Artifact 'remote_port'), (Get-HHField $Artifact 'process')) -join '|') }
        'file'        { return (@((Get-HHField $Artifact 'path'), (Get-HHField $Artifact 'sha256')) -join '|') }
        'auth_event'  { return (@((Get-HHField $Artifact 'event_type'), (Get-HHField $Artifact 'username'), (Get-HHField $Artifact 'source_ip')) -join '|') }
        default       { if ($null -ne $Artifact) { return ($Artifact | ConvertTo-Json -Compress -Depth 6) } else { return '' } }
    }
}

function New-Finding {
    <#
    .SYNOPSIS
        Build one finding.v1 record from a normalized event + rule/engine metadata.
    .PARAMETER Event
        A normalized event from ConvertTo-HHNormalizedEvent (carries host, times, artifact).
    .PARAMETER Attack
        ATT&CK technique IDs (e.g. 'T1053.003'); tactics are filled later from the ATT&CK map.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Event,
        [Parameter(Mandatory)][string]$FindingType,
        [Parameter(Mandatory)][ValidateSet('informational','low','medium','high','critical')][string]$Severity,
        [Parameter(Mandatory)][ValidateSet('low','medium','high','confirmed')][string]$Confidence,
        [Parameter(Mandatory)][ValidateSet('clamav','yara','sigma','native','ioc','behavioral')][string]$Engine,
        [string]$RuleId, [string]$RuleTitle, [string]$RuleVersion,
        [string]$IocId, [string]$IocSource,
        [string[]]$Attack = @(),
        [string]$TenantId = 'default', [string]$CampaignId, [string]$ScanId,
        [string]$EngagementId,
        [string]$BundleId, [string]$BundleSha256
    )

    $kind     = [string](Get-HHField $Event 'artifact_kind')
    $artifact = if ($kind) { Get-HHField $Event $kind } else { $null }
    $engId    = Get-HHFirst @($EngagementId, (Get-HHField $Event 'engagement_id'))
    $hostObj  = New-HHFindingHost -EventHost (Get-HHField $Event 'host')

    # mitre_attack: normalize technique IDs into {tactic,technique}; tactic filled by the map later.
    $mitre = @()
    foreach ($t in $Attack) { if ($t) { $mitre += [ordered]@{ tactic = $null; technique = [string]$t } } }

    # dedup_key: same finding_type + host + artifact identity => same logical finding.
    $identity = Get-HHFindingIdentity -Kind $kind -Artifact $artifact
    $dedupSeed = @($hostObj.host_id, $FindingType, $identity) -join '||'
    $dedupKey  = Get-HHStringHash -InputString $dedupSeed

    $observed  = Get-HHField $Event 'observed_at'
    $collected = Get-HHField $Event 'collected_at'

    $evidenceRefs = @()
    if ($BundleId -or $BundleSha256) {
        $evidenceRefs += [ordered]@{
            bundle_id  = $BundleId
            object_key = "artifacts/$([string](Get-HHField $Event 'artifact_type')).json"
            sha256     = $BundleSha256
        }
    }

    [ordered]@{
        finding_id     = [guid]::NewGuid().ToString()
        schema_version = $script:HHFindingSchemaVersion
        tenant_id      = $TenantId
        engagement_id  = $engId
        campaign_id    = $CampaignId
        scan_id        = $ScanId
        host           = $hostObj
        finding_type   = $FindingType
        severity       = $Severity
        confidence     = $Confidence
        risk_score     = $null          # filled by Get-HHRiskScore (B5)
        observed_at    = $observed
        collected_at   = $collected
        detection      = [ordered]@{
            rule_id      = $RuleId
            rule_title   = $RuleTitle
            rule_version = $RuleVersion
            ioc_id       = $IocId
            ioc_source   = $IocSource
            engine       = $Engine
            mitre_attack = $mitre
        }
        artifact       = [ordered]@{ $kind = $artifact }
        evidence_refs  = $evidenceRefs
        dedup_key      = $dedupKey
        first_seen     = $observed
        last_seen      = $observed
        occurrences    = 1
        disposition    = 'undetermined'
        remediation_status  = 'n/a'
        client_report_status = 'not_reported'
    }
}

function Test-Finding {
    <#
    .SYNOPSIS
        Validate a finding against finding.v1 required keys + enums. Returns $true/$false, or the
        problem list with -Detailed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Finding, [switch]$Detailed)
    $problems = [System.Collections.Generic.List[string]]::new()

    if ($Finding -isnot [System.Collections.IDictionary]) {
        $problems.Add('finding is not a dictionary')
    } else {
        $required = @('finding_id','schema_version','tenant_id','engagement_id','host',
                      'finding_type','severity','confidence','observed_at','collected_at',
                      'detection','artifact','dedup_key')
        foreach ($k in $required) { if (-not $Finding.Contains($k)) { $problems.Add("missing required key: $k") } }

        if ($Finding.Contains('severity') -and $Finding['severity'] -notin $script:HHFindingSeverities) {
            $problems.Add("invalid severity: $($Finding['severity'])")
        }
        if ($Finding.Contains('confidence') -and $Finding['confidence'] -notin $script:HHFindingConfidences) {
            $problems.Add("invalid confidence: $($Finding['confidence'])")
        }
        if ($Finding.Contains('detection')) {
            $eng = Get-HHField $Finding['detection'] 'engine'
            if ($eng -notin $script:HHFindingEngines) { $problems.Add("invalid detection.engine: $eng") }
        }
        if ($Finding.Contains('risk_score')) {
            $rs = $Finding['risk_score']
            if ($null -ne $rs -and ($rs -lt 0 -or $rs -gt 100)) { $problems.Add("risk_score out of range: $rs") }
        }
    }

    if ($Detailed) { return $problems.ToArray() }
    return ($problems.Count -eq 0)
}

function Merge-HHFindings {
    <#
    .SYNOPSIS
        Collapse findings sharing a dedup_key into one, tallying occurrences and widening the
        first_seen/last_seen window. Keeps the highest-severity representative.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings)
    $sevRank = @{ informational=0; low=1; medium=2; high=3; critical=4 }
    $byKey = [ordered]@{}

    foreach ($f in $Findings) {
        $key = [string]$f['dedup_key']
        if (-not $byKey.Contains($key)) {
            $byKey[$key] = $f
            continue
        }
        $keep = $byKey[$key]
        # Prefer the higher-severity representative.
        if ($sevRank[[string]$f['severity']] -gt $sevRank[[string]$keep['severity']]) {
            # carry the accumulated counters onto the new representative
            $f['occurrences'] = [int]$keep['occurrences'] + [int]$f['occurrences']
            $f['first_seen']  = Get-HHMinTime $keep['first_seen'] $f['first_seen']
            $f['last_seen']   = Get-HHMaxTime $keep['last_seen']  $f['last_seen']
            $byKey[$key] = $f
        } else {
            $keep['occurrences'] = [int]$keep['occurrences'] + [int]$f['occurrences']
            $keep['first_seen']  = Get-HHMinTime $keep['first_seen'] $f['first_seen']
            $keep['last_seen']   = Get-HHMaxTime $keep['last_seen']  $f['last_seen']
        }
    }
    return @($byKey.Values)
}

function Get-HHMinTime { param($A, $B) return (Compare-HHTime $A $B -Want 'min') }
function Get-HHMaxTime { param($A, $B) return (Compare-HHTime $A $B -Want 'max') }
function Compare-HHTime {
    param($A, $B, [ValidateSet('min','max')][string]$Want)
    $da = [datetime]::MinValue; $db = [datetime]::MinValue
    $oka = $A -and [datetime]::TryParse($A, [ref]$da)
    $okb = $B -and [datetime]::TryParse($B, [ref]$db)
    if (-not $oka) { return $B }
    if (-not $okb) { return $A }
    if ($Want -eq 'min') { if ($da -le $db) { return $A } else { return $B } }
    else                 { if ($da -ge $db) { return $A } else { return $B } }
}
