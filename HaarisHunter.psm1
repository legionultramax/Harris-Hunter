# HaarisHunter.psm1 - module loader
# Dot-sources the framework in dependency order and exposes the public surface.
# Part of HAARIS-HUNTER (CGD-CA-DESIGN-001), Phase 1: Core Framework + Windows collectors.
# Runs on Windows PowerShell 5.1 and PowerShell 7+.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:HHModuleRoot = $PSScriptRoot

# Load order matters: Core defines the primitives every collector/report depends on.
$loadAreas = @('src/Core', 'src/Collectors', 'src/Reporting')

foreach ($area in $loadAreas) {
    $areaPath = Join-Path $script:HHModuleRoot $area
    if (Test-Path -LiteralPath $areaPath) {
        Get-ChildItem -LiteralPath $areaPath -Recurse -Filter '*.ps1' |
            Sort-Object FullName |
            ForEach-Object {
                . $_.FullName
            }
    }
}

# Orchestrator / public entry point.
. (Join-Path $script:HHModuleRoot 'Invoke-HaarisHunter.ps1')

# Public surface. Collector functions (Collect-*) are discovered dynamically by the
# orchestrator and are intentionally not part of the exported API.
$publicFunctions = @(
    'Invoke-HaarisHunter',
    'Assert-Authorization',
    'New-EvidenceRecord',
    'Test-EvidenceRecord',
    'Add-EvidenceFile',
    'Get-HHConfiguration',
    'Get-HostMetadata',
    'Get-TimeIntegrity',
    'Get-HHStringHash',
    'Seal-EvidenceBundle',
    'Test-EvidenceBundle',
    'Test-ChainOfCustody',
    'Protect-EvidenceBundle',
    'Unprotect-EvidenceBundle',
    'Write-HtmlReport'
)

Export-ModuleMember -Function $publicFunctions
