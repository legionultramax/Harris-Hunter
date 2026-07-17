# AuthorizationGate.ps1 - engagement + scope enforcement.
# A core control: collection may only run when the running operator, the target host, and the
# current time all fall inside the authorized engagement. The decision is returned (not thrown)
# so the orchestrator can honor -DryRun; the engagement_id then stamps every record.

function Get-HHOperatorIdentity {
    <#
    .SYNOPSIS
        Collect the identity forms the running operator may be authorized under:
        sam name, DOMAIN\user, and UPN (best-effort).
    #>
    [CmdletBinding()]
    param()
    $identities = [System.Collections.Generic.List[string]]::new()

    if ($script:HHIsLinux) {
        if ($env:USER) { $identities.Add($env:USER) }
        try { $w = (& whoami 2>$null); if ($w) { $identities.Add($w.Trim()) } } catch { }
        try { $id = (& id -un 2>$null); if ($id) { $identities.Add($id.Trim()) } } catch { }
        return @($identities | Where-Object { $_ } | Select-Object -Unique)
    }

    $user   = $env:USERNAME
    $domain = $env:USERDOMAIN
    if ($user)             { $identities.Add($user) }
    if ($domain -and $user){ $identities.Add("$domain\$user") }

    try {
        $upn = (whoami /upn 2>$null)
        if ($LASTEXITCODE -eq 0 -and $upn) { $identities.Add($upn.Trim()) }
    } catch { }

    try {
        $identities.Add([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
    } catch { }

    # De-dupe, drop empties.
    return @($identities | Where-Object { $_ } | Select-Object -Unique)
}

function Test-HHScopeMatch {
    <#
    .SYNOPSIS
        True if any candidate value matches any wildcard pattern (PowerShell -like).
    #>
    param([string[]]$Patterns, [string[]]$Candidates)
    foreach ($p in $Patterns) {
        foreach ($c in $Candidates) {
            if ($c -and ($c -like $p)) { return $true }
        }
    }
    return $false
}

function Assert-Authorization {
    <#
    .SYNOPSIS
        Evaluate whether this run is authorized by the engagement. Returns a decision
        object; it does not throw (the orchestrator enforces, so -DryRun can proceed).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Engagement,
        [Parameter(Mandatory)]$HostMeta,
        [string[]]$OperatorIdentities
    )

    if (-not $OperatorIdentities) { $OperatorIdentities = Get-HHOperatorIdentity }
    $reasons = [System.Collections.Generic.List[string]]::new()

    # --- Operator check ---
    $authOps = @($Engagement['authorized_operators'])
    $operatorOk = $false
    foreach ($id in $OperatorIdentities) {
        if ($authOps | Where-Object { $_ -and ($id -like $_ -or $_ -like $id) }) { $operatorOk = $true; break }
    }
    if (-not $operatorOk) {
        $reasons.Add("operator not authorized (running as: $($OperatorIdentities -join ', '))")
    }

    # --- Time-window check ---
    $now      = [DateTimeOffset]::UtcNow
    $from     = [DateTimeOffset]::Parse($Engagement['valid_from'], [cultureinfo]::InvariantCulture)
    $to       = [DateTimeOffset]::Parse($Engagement['valid_to'],   [cultureinfo]::InvariantCulture)
    $timeOk   = ($now -ge $from -and $now -le $to)
    if (-not $timeOk) {
        $reasons.Add("outside authorized window ($($Engagement['valid_from']) .. $($Engagement['valid_to']))")
    }

    # --- Scope check ---
    $scope        = $Engagement['authorized_scope']
    $hostPatterns = @($scope['hostnames'])
    $ipPatterns   = @($scope['ips'])
    $hostCandidates = @($HostMeta.hostname, $HostMeta.fqdn) | Where-Object { $_ }
    $ipCandidates   = @($HostMeta.ips)

    $hostOk = ($hostPatterns.Count -gt 0) -and (Test-HHScopeMatch -Patterns $hostPatterns -Candidates $hostCandidates)
    $ipOk   = ($ipPatterns.Count   -gt 0) -and (Test-HHScopeMatch -Patterns $ipPatterns   -Candidates $ipCandidates)
    $scopeOk = ($hostOk -or $ipOk)
    if (-not $scopeOk) {
        $reasons.Add("host not in authorized scope (host: $($hostCandidates -join ', '); ips: $($ipCandidates -join ', '))")
    }

    $authorized = ($operatorOk -and $timeOk -and $scopeOk)

    [pscustomobject]@{
        Authorized   = $authorized
        Reasons      = $reasons.ToArray()
        EngagementId = $Engagement['engagement_id']
        Operator     = ($OperatorIdentities -join ', ')
        DecisionUtc  = $now.ToString('o')
        Checks       = [ordered]@{
            operator = $operatorOk
            time     = $timeOk
            scope    = $scopeOk
        }
    }
}
