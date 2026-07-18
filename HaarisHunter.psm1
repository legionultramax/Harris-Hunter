# HaarisHunter.psm1 - module loader
# Dot-sources the framework in dependency order and exposes the public surface.
# Part of HAARIS-HUNTER (CGD-CA-DESIGN-001), Phase 1: Core Framework + Windows collectors.
# Runs on Windows PowerShell 5.1 and PowerShell 7+.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:HHModuleRoot = $PSScriptRoot

# NB: dot-source at module top level (via the pipeline). Wrapping this in a named function
# would trap the definitions in that function's scope instead of the module scope.

# 1. Core first - defines the primitives (incl. platform detection) everything depends on.
Get-ChildItem -LiteralPath (Join-Path $script:HHModuleRoot 'src/Core') -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue |
    Sort-Object FullName | ForEach-Object { . $_.FullName }

# 1.5 Detection engine (Phase 2): normalization + Sigma + scoring. Consumes sealed bundles and
#     depends only on Core primitives, so it loads right after Core. Load-order-independent
#     (resolution is at call time); guarded so partial builds still import.
$detectionPath = Join-Path $script:HHModuleRoot 'src/Detection'
if (Test-Path -LiteralPath $detectionPath) {
    Get-ChildItem -LiteralPath $detectionPath -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue |
        Sort-Object FullName | ForEach-Object { . $_.FullName }
}

# 2. Load ONLY the current OS's collectors. Windows and Linux both define Collect-Process,
#    Collect-Network, etc.; loading both would collide. Platform is known now that Core loaded.
$collectorSub = switch (Get-HHPlatform) {
    'Windows' { 'Windows' }
    'Linux'   { 'Linux' }
    'macOS'   { 'Linux' }   # macOS shares the Linux collectors best-effort until a dedicated set exists
    default   { 'Windows' }
}
$collectorPath = Join-Path $script:HHModuleRoot "src/Collectors/$collectorSub"
if (Test-Path -LiteralPath $collectorPath) {
    Get-ChildItem -LiteralPath $collectorPath -Recurse -Filter '*.ps1' |
        Sort-Object FullName | ForEach-Object { . $_.FullName }
}

# 3. Reporting.
Get-ChildItem -LiteralPath (Join-Path $script:HHModuleRoot 'src/Reporting') -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue |
    Sort-Object FullName | ForEach-Object { . $_.FullName }

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
