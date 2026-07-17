# Platform.ps1 - OS detection for Windows PowerShell 5.1 and PowerShell 7+.
# Windows PowerShell 5.1 has no $IsWindows/$IsLinux/$IsMacOS automatic variables (and under
# Set-StrictMode referencing them would throw), so we probe with Get-Variable first.

function Get-HHPlatform {
    [CmdletBinding()]
    param()
    if (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) {
        if ($IsWindows) { return 'Windows' }
        if ($IsLinux)   { return 'Linux' }
        if ($IsMacOS)   { return 'macOS' }
        return 'Unknown'
    }
    # Windows PowerShell 5.1 only runs on Windows.
    return 'Windows'
}

$script:HHPlatform  = Get-HHPlatform
$script:HHIsWindows = ($script:HHPlatform -eq 'Windows')
$script:HHIsLinux   = ($script:HHPlatform -eq 'Linux')
$script:HHIsMacOS   = ($script:HHPlatform -eq 'macOS')

function Test-HHCommand {
    <#
    .SYNOPSIS
        True if an external command / cmdlet is available. Used by collectors to degrade
        gracefully when a tool (ss, systemctl, rpm, docker, ...) is not installed.
    #>
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}
