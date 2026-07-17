<#
.SYNOPSIS
    Cross-platform example / smoke run of HAARIS-HUNTER. Generates a permissive self-test
    engagement (operator '*', host '*'), runs collection, and re-verifies the sealed bundle.
    Use this to field-test the Linux collectors on a real host:
        sudo pwsh -File tools/Invoke-Example.ps1 -Profile standard
    On Windows run elevated for full coverage. NOT for real engagements - use a scoped
    engagement.json with Invoke-HaarisHunter directly for those.
#>
[CmdletBinding()]
param(
    [ValidateSet('quick', 'standard', 'deep')][string]$Profile = 'standard',
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$moduleRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $moduleRoot 'HaarisHunter.psd1') -Force

$eng = Join-Path ([IO.Path]::GetTempPath()) 'hh_example_engagement.json'
@{
    engagement_id = 'CGD-ENG-EXAMPLE'; client = 'Self Test'; authorization_reference = 'EXAMPLE-1'
    authorized_operators = @('*')
    authorized_scope = @{ hostnames = @('*'); ips = @(); asset_tags = @() }
    valid_from = '2020-01-01T00:00:00Z'; valid_to = '2099-12-31T23:59:59Z'; collection_mode = 'full'
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $eng -Encoding utf8

if (-not $OutputPath) {
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmssZ')
    $OutputPath = Join-Path (Get-Location) "HH_example_$stamp"
}

$result = Invoke-HaarisHunter -EngagementFile $eng -Profile $Profile -OutputPath $OutputPath -LogLevel Info

Write-Host "`n=== Verify ===" -ForegroundColor Cyan
$v = Test-EvidenceBundle -BundlePath $result.OutputPath
Write-Host ("Valid={0}  CocValid={1}  Problems={2}" -f $v.Valid, $v.CocValid, ($v.Problems -join '; ')) -ForegroundColor $(if ($v.Valid) { 'Green' } else { 'Red' })

Write-Host "`n=== Per-collector ===" -ForegroundColor Cyan
foreach ($k in $result.Stats.PerCollector.Keys) {
    $c = $result.Stats.PerCollector[$k]
    "{0,-16} {1,6} records  {2,8} ms  {3}" -f $k, $c.records, $c.duration_ms, $c.status
}
Write-Host "`nBundle: $($result.OutputPath)" -ForegroundColor Cyan
Write-Host "Report: $($result.ReportPath)" -ForegroundColor Cyan
