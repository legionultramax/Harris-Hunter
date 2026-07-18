<#
.SYNOPSIS
    Detection-rule CI gate (blueprint CGD-CA-DESIGN-001 section 11 governance model).
.DESCRIPTION
    1. Compiles the Sigma pack (tools/Convert-SigmaPack.ps1) and lints every compiled rule:
       required fields present, severity/confidence in range, a condition AST, >=1 selection.
    2. Runs fixture regression: a known-bad record set must yield the expected finding types and
       a known-good set must yield zero. Fixtures use benign, deterministic data (fixed dates,
       ordinary paths) - no live host and no malware-like content required.
    Returns a summary object and sets exit code 1 on any failure (for CI).
#>
[CmdletBinding()]
param([switch]$Quiet)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'HaarisHunter.psd1') -Force 3>$null

$pass = 0; $fail = 0
function Assert-Rule { param([string]$Name, [bool]$Cond, [string]$Detail='')
    if ($Cond) { if (-not $Quiet) { Write-Host "  [PASS] $Name" -ForegroundColor Green }; $script:pass++ }
    else { Write-Host ("  [FAIL] $Name" + $(if($Detail){" -> $Detail"}else{''})) -ForegroundColor Red; $script:fail++ }
}

function Import-HHFixtureRecords {
    param([string]$Path)
    $txt = Get-Content -LiteralPath $Path -Raw
    $parsed = ConvertFrom-Json $txt
    if ($parsed -is [System.Array]) { return @($parsed) }
    return @($parsed)
}

Write-Host "HAARIS-HUNTER detection-rule CI"
Write-Host "PowerShell $($PSVersionTable.PSVersion)"

# --- 1. Compile + lint -----------------------------------------------------------------------
Write-Host "`n[1] Compile Sigma pack"
$compileRes = & (Join-Path $repoRoot 'tools/Convert-SigmaPack.ps1') -Quiet
Assert-Rule "sigma pack compiles (>=1 rule, 0 failures)" ($compileRes.Compiled -ge 1 -and $compileRes.Failed -eq 0) "compiled=$($compileRes.Compiled) failed=$($compileRes.Failed)"

Write-Host "`n[2] Lint compiled rules"
$compiledDir = Join-Path $repoRoot 'config/detection/rules/compiled'
$rules = Import-HHCompiledRules -Path $compiledDir
Assert-Rule "compiled rules load" ($rules.Count -ge 1) "loaded=$($rules.Count)"
$sevOk = @('informational','low','medium','high','critical')
$confOk = @('low','medium','high','confirmed')
foreach ($r in $rules) {
    $id = if ($r.id) { $r.id } else { '<no-id>' }
    $hasId    = [bool]$r.id
    $hasCat   = [bool]$r.logsource -and [bool]$r.logsource.category
    $hasSel   = $r.selections -and (@($r.selections.PSObject.Properties.Name).Count -ge 1)
    $hasAst   = [bool]$r.condition_ast
    $hasFt    = [bool]$r.finding_type
    $sevValid = $r.severity -in $sevOk
    $confValid= $r.confidence -in $confOk
    Assert-Rule "rule $id : id/category/selection/condition/finding_type present" ($hasId -and $hasCat -and $hasSel -and $hasAst -and $hasFt)
    Assert-Rule "rule $id : severity+confidence in range" ($sevValid -and $confValid) "sev=$($r.severity) conf=$($r.confidence)"
}

# --- 3. Fixture regression -------------------------------------------------------------------
Write-Host "`n[3] Fixture regression"
$fixDir = Join-Path $repoRoot 'tests/fixtures'
$win = [datetime]'2026-07-01T00:00:00Z'   # fixed scan window so recency/timeframe is deterministic

# known-bad: expect exactly the registry_run finding
$bad = Import-HHFixtureRecords -Path (Join-Path $fixDir 'known-bad-records.json')
$badEvents = @(ConvertTo-HHNormalizedEvents -Records $bad)
$badFindings = @(Invoke-SigmaRules -Events $badEvents -Rules $rules -ScanWindowStart $win -ScanWindowEnd ([datetime]'2026-07-18T00:00:00Z') -FindingArgs @{})
$badTypes = @($badFindings | ForEach-Object { $_['finding_type'] } | Sort-Object -Unique)
Assert-Rule "known-bad yields exactly 1 finding" ($badFindings.Count -eq 1) "count=$($badFindings.Count)"
Assert-Rule "known-bad finding is persistence.registry_run" ($badTypes -contains 'persistence.registry_run') "types=$($badTypes -join ',')"
if ($badFindings.Count -ge 1) {
    Assert-Rule "known-bad finding validates against finding.v1" (Test-Finding -Finding $badFindings[0])
}

# known-good: expect zero
$good = Import-HHFixtureRecords -Path (Join-Path $fixDir 'known-good-records.json')
$goodEvents = @(ConvertTo-HHNormalizedEvents -Records $good)
$goodFindings = @(Invoke-SigmaRules -Events $goodEvents -Rules $rules -ScanWindowStart $win -ScanWindowEnd ([datetime]'2026-07-18T00:00:00Z') -FindingArgs @{})
Assert-Rule "known-good yields zero findings" ($goodFindings.Count -eq 0) "count=$($goodFindings.Count)"

Write-Host "`n==== $pass passed, $fail failed ===="
if ($fail -gt 0) { exit 1 }
return [pscustomobject]@{ Passed = $pass; Failed = $fail }
