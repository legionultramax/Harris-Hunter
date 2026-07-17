# Logging.ps1 - structured logging + SHA-256 hash engine.
# Logging writes human-readable lines to console and, once initialized, appends to a
# run log file. The hash engine is the single source of truth for all hashing so the
# algorithm and encoding stay consistent across records, artifacts, and the bundle.

$script:HHLogFile   = $null
$script:HHLogLevels = @{ Debug = 0; Info = 1; Warn = 2; Error = 3 }
$script:HHMinLevel  = 'Info'

function Initialize-HHLogging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$FileName = 'haaris-hunter.log',
        [ValidateSet('Debug', 'Info', 'Warn', 'Error')][string]$MinLevel = 'Info'
    )
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $script:HHLogFile  = Join-Path $OutputPath $FileName
    $script:HHMinLevel = $MinLevel
    # Touch the file so downstream hashing always has a target.
    if (-not (Test-Path -LiteralPath $script:HHLogFile)) {
        New-Item -ItemType File -Path $script:HHLogFile -Force | Out-Null
    }
}

function Write-HHLog {
    [CmdletBinding()]
    param(
        [ValidateSet('Debug', 'Info', 'Warn', 'Error')][string]$Level = 'Info',
        [Parameter(Mandatory, Position = 0)][string]$Message
    )
    if ($script:HHLogLevels[$Level] -lt $script:HHLogLevels[$script:HHMinLevel]) { return }

    $ts   = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $line = "$ts [$($Level.ToUpper().PadRight(5))] $Message"

    switch ($Level) {
        'Debug' { Write-Host $line -ForegroundColor DarkGray }
        'Info'  { Write-Host $line -ForegroundColor Gray }
        'Warn'  { Write-Host $line -ForegroundColor Yellow }
        'Error' { Write-Host $line -ForegroundColor Red }
    }

    if ($script:HHLogFile) {
        Add-Content -LiteralPath $script:HHLogFile -Value $line -Encoding utf8
    }
}

function Get-HHStringHash {
    <#
    .SYNOPSIS
        SHA-256 (default) of a UTF-8 string, returned as lowercase hex.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$InputString,
        [ValidateSet('SHA256', 'SHA384', 'SHA512')][string]$Algorithm = 'SHA256'
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $algo  = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    try {
        $hash = $algo.ComputeHash($bytes)
        return -join ($hash | ForEach-Object { $_.ToString('x2') })
    }
    finally {
        $algo.Dispose()
    }
}

function Get-HHFileHash {
    <#
    .SYNOPSIS
        SHA-256 of a file as lowercase hex, or $null if the file is missing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('SHA256', 'SHA384', 'SHA512')][string]$Algorithm = 'SHA256'
    )
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm $Algorithm).Hash.ToLower()
}
