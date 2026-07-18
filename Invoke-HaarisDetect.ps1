# Invoke-HaarisDetect.ps1 - Phase 2 detection orchestrator.
# Consumes a SEALED evidence bundle (produced by Invoke-HaarisHunter), verifies its integrity,
# normalizes the evidence, runs the detection engines (Sigma now; more later via pluggable
# dispatch), scores findings + the host, and writes findings.json + host-summary.json + an
# HTML report. It NEVER modifies the evidence bundle - outputs go to a separate detection/ dir,
# and analysis events are logged to a separate detect.jsonl (never the evidence coc.jsonl).

function Get-HHDetectRoot {
    if ($script:HHModuleRoot) { return $script:HHModuleRoot }
    return $PSScriptRoot
}

function Set-HHCorroboration {
    # Mark findings corroborated when >=2 DISTINCT rules flag the same artifact on the same host
    # (independent support raises confidence per §14). Identity ignores finding_type on purpose.
    param([object[]]$Findings)
    $groups = @{}
    foreach ($f in $Findings) {
        $kind = @(Get-HHKeys $f['artifact'])[0]
        $obj  = if ($kind) { $f['artifact'][$kind] } else { $null }
        $idty = @($f['host']['host_id'], $kind, (Get-HHFindingIdentity -Kind $kind -Artifact $obj)) -join '||'
        if (-not $groups.ContainsKey($idty)) { $groups[$idty] = [System.Collections.Generic.List[object]]::new() }
        $groups[$idty].Add($f)
    }
    foreach ($g in $groups.Values) {
        $rules = @($g | ForEach-Object { [string]$_['detection']['rule_id'] } | Sort-Object -Unique)
        if ($rules.Count -ge 2) { foreach ($f in $g) { $f['corroborated'] = $true } }
    }
}

function Invoke-HaarisDetect {
    <#
    .SYNOPSIS
        Run the detection engine over a sealed HAARIS-HUNTER evidence bundle.
    .PARAMETER BundlePath
        Path to a sealed bundle directory (contains manifest.json + artifacts/ + coc.jsonl).
    .PARAMETER RulePath
        Directory of compiled Sigma rules. Default: config/detection/rules/compiled.
    .PARAMETER OutputPath
        Where to write findings/report. Default: <BundlePath>/detection.
    .PARAMETER Force
        Analyze even if the bundle fails integrity verification (flagged in the summary).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BundlePath,
        [string]$RulePath,
        [string]$AttackMap,
        [string]$OutputPath,
        [datetime]$ScanWindowStart,
        [datetime]$ScanWindowEnd,
        [string]$TenantId = 'default',
        [switch]$Force
    )
    $started = [DateTime]::UtcNow
    $root = Get-HHDetectRoot
    if (-not $RulePath)   { $RulePath   = Join-Path $root 'config/detection/rules/compiled' }
    if (-not $AttackMap)  { $AttackMap  = Join-Path $root 'config/detection/attack-map.json' }
    if (-not $OutputPath) { $OutputPath = Join-Path $BundlePath 'detection' }

    if (-not (Test-Path -LiteralPath (Join-Path $BundlePath 'manifest.json'))) {
        throw "No manifest.json in bundle path: $BundlePath"
    }

    # 1. Integrity - verify before trusting a single byte of evidence.
    $bundleCheck = Test-EvidenceBundle -BundlePath $BundlePath
    $cocPath = Join-Path $BundlePath 'coc.jsonl'
    $cocCheck = if (Test-Path -LiteralPath $cocPath) { Test-ChainOfCustody -Path $cocPath } else { [pscustomobject]@{ Valid = $false; Problems = @('coc.jsonl missing') } }
    if (-not $bundleCheck.Valid -and -not $Force) {
        throw "Bundle failed integrity verification (use -Force to analyze anyway): $($bundleCheck.Problems -join '; ')"
    }

    # 2. Load manifest + all artifact records.
    $manifest = Get-Content -LiteralPath (Join-Path $BundlePath 'manifest.json') -Raw | ConvertFrom-Json
    $records = [System.Collections.Generic.List[object]]::new()
    $artifactsDir = Join-Path $BundlePath 'artifacts'
    if (Test-Path -LiteralPath $artifactsDir) {
        foreach ($af in (Get-ChildItem -LiteralPath $artifactsDir -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
            try {
                # Two-step read: piping Get-Content -Raw straight into ConvertFrom-Json can deliver
                # the parsed array as a single un-enumerated object under StrictMode (collapsing a
                # multi-record artifact file into one merged object). Read to a variable, parse, then
                # enumerate explicitly so every record is added individually.
                $txt = Get-Content -LiteralPath $af.FullName -Raw
                $parsed = ConvertFrom-Json $txt
                if ($parsed -is [System.Array]) { foreach ($r in $parsed) { if ($r) { $records.Add($r) } } }
                elseif ($parsed) { $records.Add($parsed) }
            } catch { }
        }
    }

    # Scan window defaults from the collection time (recency/timeframe rules resolve against these).
    $collUtc = [DateTime]::UtcNow
    [void][datetime]::TryParse([string]$manifest.created_utc, [ref]$collUtc)
    if (-not $PSBoundParameters.ContainsKey('ScanWindowStart')) { $ScanWindowStart = $collUtc.AddDays(-7) }
    if (-not $PSBoundParameters.ContainsKey('ScanWindowEnd'))   { $ScanWindowEnd   = $collUtc }

    # 3. Normalize.
    $events = @(ConvertTo-HHNormalizedEvents -Records $records.ToArray())

    # 4. Detect. Pluggable dispatch - Sigma today; IOC/native/behavioral slot in here later.
    $scanId = [guid]::NewGuid().ToString()
    $engagementId = if ($manifest.engagement) { [string]$manifest.engagement.engagement_id } else { $null }
    $findingArgs = @{
        BundleId     = [string]$manifest.bundle_id
        BundleSha256 = [string]$manifest.bundle_sha256
        TenantId     = $TenantId
        ScanId       = $scanId
        EngagementId = $engagementId
    }
    $rules = Import-HHCompiledRules -Path $RulePath
    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($f in @(Invoke-SigmaRules -Events $events -Rules $rules -ScanWindowStart $ScanWindowStart -ScanWindowEnd $ScanWindowEnd -FindingArgs $findingArgs)) { $findings.Add($f) }

    # 5. Corroboration, then 6. score every finding, then 7. dedup/merge.
    Set-HHCorroboration -Findings $findings.ToArray()
    $map = Get-HHAttackMap -Path $AttackMap
    foreach ($f in $findings) { [void](Resolve-HHFindingAttack -Finding $f -Map $map); [void](Get-HHRiskScore -Finding $f -Map $map) }
    $merged = @(Merge-HHFindings -Findings $findings.ToArray())

    # 8. Host score.
    $hostScore = Get-HHHostScore -Findings $merged -Map $map -Now $ScanWindowEnd

    # 9. Build the host_scan_summary.v1.
    $hostObj = New-HHFindingHost -EventHost $manifest.host
    $bySeverity = @{}; $byTactic = @{}
    foreach ($f in $merged) {
        $sev = [string]$f['severity']; $bySeverity[$sev] = 1 + $(if ($bySeverity.ContainsKey($sev)) { $bySeverity[$sev] } else { 0 })
        foreach ($t in (Resolve-HHFindingAttack -Finding $f -Map $map)) { $byTactic[$t] = 1 + $(if ($byTactic.ContainsKey($t)) { $byTactic[$t] } else { 0 }) }
    }
    $summary = [ordered]@{
        schema_version = '1.0'
        title          = 'sentinel_ca.host_scan_summary.v1'
        scan_id        = $scanId
        tenant_id      = $TenantId
        engagement_id  = $engagementId
        campaign_id    = $null
        host           = $hostObj
        started_at     = $started.ToString('o')
        completed_at   = [DateTime]::UtcNow.ToString('o')
        collector      = [ordered]@{ tool = $manifest.tool; tool_version = $manifest.tool_version; bundle_id = $manifest.bundle_id }
        detection      = [ordered]@{ engines = @('sigma'); rules_evaluated = @($rules).Count; events_evaluated = $events.Count }
        integrity      = [ordered]@{ bundle_valid = [bool]$bundleCheck.Valid; coc_valid = [bool]$cocCheck.Valid; bundle_sha256 = [string]$manifest.bundle_sha256 }
        totals         = [ordered]@{ findings = $merged.Count; by_severity = $bySeverity; by_tactic = $byTactic }
        host_score     = $hostScore
        assurance_limitation = 'Point-in-time compromise assessment. Absence of evidence is not evidence of absence; coverage is limited to collected artifacts and the enabled rule set.'
    }

    # 10. Write outputs (separate detection dir - never touches the sealed evidence).
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $findingsPath = Join-Path $OutputPath 'findings.json'
    $summaryPath  = Join-Path $OutputPath 'host-summary.json'
    $reportPath   = Join-Path $OutputPath 'detection-report.html'
    ($merged  | ConvertTo-Json -Depth 20)  | Set-Content -LiteralPath $findingsPath -Encoding utf8
    ($summary | ConvertTo-Json -Depth 20)  | Set-Content -LiteralPath $summaryPath -Encoding utf8
    if (Get-Command -Name Write-DetectionReport -ErrorAction SilentlyContinue) {
        Write-DetectionReport -Summary $summary -Findings $merged -Path $reportPath
    }

    # 11. Separate analysis ledger (NOT the evidence custody ledger).
    $detectLedger = Join-Path $OutputPath 'detect.jsonl'
    $findingsHash = Get-HHStringHash -InputString (($merged | ConvertTo-Json -Depth 20 -Compress))
    @(
        (@{ ts = $started.ToString('o');           event = 'analysis_started';  bundle_id = [string]$manifest.bundle_id; bundle_sha256 = [string]$manifest.bundle_sha256; bundle_valid = [bool]$bundleCheck.Valid; coc_valid = [bool]$cocCheck.Valid } | ConvertTo-Json -Compress),
        (@{ ts = [DateTime]::UtcNow.ToString('o'); event = 'analysis_complete'; scan_id = $scanId; findings = $merged.Count; host_score = $hostScore.score; findings_sha256 = $findingsHash } | ConvertTo-Json -Compress)
    ) | Set-Content -LiteralPath $detectLedger -Encoding utf8

    if (-not $bundleCheck.Valid) { Write-Warning "Bundle integrity FAILED - findings produced under -Force and are marked accordingly." }

    return [pscustomobject]@{
        ScanId       = $scanId
        OutputPath   = $OutputPath
        Findings     = $merged.Count
        HostScore    = $hostScore.score
        Band         = $hostScore.band
        BundleValid  = [bool]$bundleCheck.Valid
        CocValid     = [bool]$cocCheck.Valid
        FindingsFile = $findingsPath
        SummaryFile  = $summaryPath
        ReportFile   = $reportPath
    }
}
