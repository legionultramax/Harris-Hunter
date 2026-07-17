# Configuration.ps1 - load and merge constants, collection profile, and engagement.
# Produces a single resolved config object the orchestrator consumes. Also resolves
# which collectors are enabled for the chosen profile, honoring Include/Exclude.

function ConvertTo-HHHashtable {
    <#
    .SYNOPSIS
        Recursively convert a ConvertFrom-Json result (PSCustomObject/array) into nested
        [hashtable]s. Gives us ConvertFrom-Json -AsHashtable semantics on Windows
        PowerShell 5.1 as well as PowerShell 7+ (so the tool runs on stock Windows hosts).
    #>
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $ht = @{}
        foreach ($k in @($InputObject.Keys)) { $ht[$k] = ConvertTo-HHHashtable $InputObject[$k] }
        return $ht
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $ht = @{}
        foreach ($p in $InputObject.PSObject.Properties) { $ht[$p.Name] = ConvertTo-HHHashtable $p.Value }
        return $ht
    }
    if (($InputObject -is [System.Collections.IEnumerable]) -and ($InputObject -isnot [string])) {
        return @(foreach ($item in $InputObject) { ConvertTo-HHHashtable $item })
    }
    return $InputObject
}

function ConvertFrom-HHJsonFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Configuration file not found: $Path"
    }
    try {
        $obj = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json
        return (ConvertTo-HHHashtable $obj)
    }
    catch {
        throw "Failed to parse JSON '$Path': $($_.Exception.Message)"
    }
}

function Test-HHEngagement {
    <#
    .SYNOPSIS
        Structural validation of an engagement definition (not authorization - that is
        Assert-Authorization's job). Throws on missing/invalid fields.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Engagement)

    $required = @('engagement_id', 'client', 'authorization_reference',
                  'authorized_operators', 'authorized_scope', 'valid_from', 'valid_to')
    $missing = $required | Where-Object { -not $Engagement.ContainsKey($_) -or $null -eq $Engagement[$_] }
    if ($missing) {
        throw "Engagement is missing required field(s): $($missing -join ', ')"
    }

    foreach ($field in 'valid_from', 'valid_to') {
        $parsed = [datetime]::MinValue
        $ok = [datetime]::TryParse($Engagement[$field], [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed)
        if (-not $ok) { throw "Engagement.$field is not a valid ISO-8601 timestamp: $($Engagement[$field])" }
    }

    if (@($Engagement['authorized_operators']).Count -eq 0) {
        throw 'Engagement.authorized_operators must list at least one operator.'
    }

    $mode = if ($Engagement.ContainsKey('collection_mode')) { $Engagement['collection_mode'] } else { 'minimized' }
    if ($mode -notin 'full', 'minimized') {
        throw "Engagement.collection_mode must be 'full' or 'minimized' (got '$mode')."
    }
}

function Get-HHConfiguration {
    <#
    .SYNOPSIS
        Load constants + profile + engagement and resolve the effective collector set.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EngagementFile,
        [ValidateSet('quick', 'standard', 'deep')][string]$Profile,
        [string]$ConstantsFile,
        [string]$ProfileFile,
        [string[]]$Include = @(),
        [string[]]$Exclude = @()
    )

    $configDir = Join-Path $script:HHModuleRoot 'config'
    if (-not $ConstantsFile) { $ConstantsFile = Join-Path $configDir 'constants.json' }
    if (-not $ProfileFile)   { $ProfileFile   = Join-Path $configDir 'default-profile.json' }

    $constants   = ConvertFrom-HHJsonFile -Path $ConstantsFile
    $profileData = ConvertFrom-HHJsonFile -Path $ProfileFile
    $engagement  = ConvertFrom-HHJsonFile -Path $EngagementFile
    Test-HHEngagement -Engagement $engagement

    # Select the collector set for the current OS. macOS shares the linux set for now.
    $osKey = if ($script:HHIsLinux -or $script:HHIsMacOS) { 'linux' } else { 'windows' }
    if (-not $profileData.ContainsKey($osKey)) {
        throw "Profile file has no '$osKey' section."
    }
    $osProfiles = $profileData[$osKey]

    $profileName = if ($Profile) { $Profile } else { $osProfiles['default_profile'] }
    if (-not $osProfiles['profiles'].ContainsKey($profileName)) {
        throw "Unknown $osKey profile '$profileName'. Available: $($osProfiles['profiles'].Keys -join ', ')"
    }

    # Resolve collectors: profile set, plus Include, minus Exclude (de-duped, order-preserving).
    $collectors = [System.Collections.Generic.List[string]]::new()
    foreach ($c in @($osProfiles['profiles'][$profileName]) + @($Include)) {
        if ($c -and ($collectors -notcontains $c)) { $collectors.Add($c) }
    }
    if ($Exclude.Count -gt 0) {
        $collectors = [System.Collections.Generic.List[string]](
            $collectors | Where-Object { $Exclude -notcontains $_ })
    }

    $continueOnError = $true
    if ($profileData.ContainsKey('execution') -and $profileData['execution'].ContainsKey('continue_on_collector_error')) {
        $continueOnError = [bool]$profileData['execution']['continue_on_collector_error']
    }

    [pscustomobject]@{
        Constants         = $constants
        Profile           = $profileName
        Engagement        = $engagement
        CollectionMode    = if ($engagement.ContainsKey('collection_mode')) { $engagement['collection_mode'] } else { 'minimized' }
        EnabledCollectors = $collectors.ToArray()
        ContinueOnError   = $continueOnError
        SchemaVersion     = $constants['schema_version']
        ToolVersion       = $constants['tool_version']
        ToolName          = $constants['tool_name']
    }
}
