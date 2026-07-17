# Invoke-HaarisHunter.ps1 - the orchestrator / public entry point.
# Flow: load config -> host metadata -> authorization gate -> custody + time integrity
#       -> run enabled collectors (fault-isolated) -> seal bundle -> render report.
# Collectors are discovered dynamically: any loaded function named Collect-<Name> whose
# <Name> appears in the resolved profile is invoked. With zero collectors present this
# still produces a valid (empty) sealed, chain-of-custody'd bundle + report.

function Invoke-HaarisHunter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EngagementFile,
        [ValidateSet('quick', 'standard', 'deep')][string]$Profile,
        [string]$OutputPath,
        [string[]]$Include = @(),
        [string[]]$Exclude = @(),
        [switch]$Encrypt,
        [switch]$DryRun,
        [ValidateSet('Debug', 'Info', 'Warn', 'Error')][string]$LogLevel = 'Info'
    )

    # --- Configuration ---
    $config = Get-HHConfiguration -EngagementFile $EngagementFile -Profile $Profile -Include $Include -Exclude $Exclude

    # --- Output location ---
    if (-not $OutputPath) {
        $safeEng  = ($config.Engagement['engagement_id'] -replace '[^\w.-]', '_')
        $safeHost = ([System.Net.Dns]::GetHostName() -replace '[^\w.-]', '_')
        $stamp    = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmssZ')
        $OutputPath = Join-Path (Get-Location) "HH_${safeEng}_${safeHost}_${stamp}"
    }
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path

    # --- Logging + custody ---
    Initialize-HHLogging -OutputPath $OutputPath -MinLevel $LogLevel
    Initialize-ChainOfCustody -OutputPath $OutputPath

    Write-HHLog -Level Info -Message "HAARIS-HUNTER v$($config.ToolVersion) starting | engagement=$($config.Engagement['engagement_id']) | profile=$($config.Profile) | mode=$($config.CollectionMode)"
    Write-HHLog -Level Info -Message "Output: $OutputPath"

    # --- Host metadata ---
    $hostMeta = Get-HostMetadata
    Write-HHLog -Level Info -Message "Host: $($hostMeta.hostname) ($($hostMeta.os))"

    # --- Authorization gate ---
    $auth = Assert-Authorization -Engagement $config.Engagement -HostMeta $hostMeta
    if ($auth.Authorized) {
        Write-HHLog -Level Info -Message "Authorization: PASSED (operator=$($auth.Operator))"
    }
    else {
        Write-HHLog -Level Warn -Message "Authorization: FAILED - $($auth.Reasons -join '; ')"
        if (-not $DryRun) {
            Add-CocEvent -EventType 'authorization_denied' -Details @{ reasons = $auth.Reasons; operator = $auth.Operator }
            throw "Authorization denied for engagement '$($config.Engagement['engagement_id'])': $($auth.Reasons -join '; '). Re-run with -DryRun to collect an explicitly-unauthorized bundle for testing."
        }
        Write-HHLog -Level Warn -Message '-DryRun set: continuing with an UNAUTHORIZED bundle (for testing only).'
    }

    # --- Time integrity + gate event ---
    $timeIntegrity = Get-TimeIntegrity -NtpServer $config.Constants['time']['ntp_server']
    Add-CocEvent -EventType 'gate_passed' -Details @{
        engagement_id = $config.Engagement['engagement_id']
        operator      = $auth.Operator
        authorized    = $auth.Authorized
        dry_run       = [bool]$DryRun
        host          = $hostMeta.hostname
        profile       = $config.Profile
    }

    # --- Run context handed to every collector ---
    $context = [pscustomobject]@{
        ToolName       = $config.ToolName
        ToolVersion    = $config.ToolVersion
        SchemaVersion  = $config.SchemaVersion
        Host           = $hostMeta
        EngagementId   = $config.Engagement['engagement_id']
        Engagement     = $config.Engagement
        CollectionMode = $config.CollectionMode
        Constants      = $config.Constants
    }

    # --- Collection ---
    $stats     = New-HHRunStats
    $collected = [ordered]@{}

    foreach ($name in $config.EnabledCollectors) {
        $fnName = "Collect-$name"
        $fn = Get-Command -Name $fnName -CommandType Function -ErrorAction SilentlyContinue
        if (-not $fn) {
            Write-HHLog -Level Warn -Message "Collector '$name' not implemented yet ($fnName) - skipped."
            Add-HHCollectorStat -Stats $stats -Collector $name -Status 'skipped'
            Add-CocEvent -EventType 'collector_skipped' -Details @{ collector = $name; reason = 'not_implemented' }
            continue
        }

        Add-CocEvent -EventType 'collector_start' -Details @{ collector = $name }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $records = @(& $fnName -Context $context)
            $sw.Stop()

            # Best-effort schema guard: warn (do not fail) on malformed records.
            $bad = @($records | Where-Object { -not (Test-EvidenceRecord -Record $_) }).Count
            if ($bad -gt 0) { Write-HHLog -Level Warn -Message "Collector '$name' produced $bad record(s) failing schema validation." }

            $collected[$name] = $records
            Add-HHCollectorStat -Stats $stats -Collector $name -Records $records.Count -DurationMs $sw.Elapsed.TotalMilliseconds -Status 'ok'
            Add-CocEvent -EventType 'collector_complete' -Details @{ collector = $name; records = $records.Count; duration_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 1) }
            Write-HHLog -Level Info -Message "  [$name] $($records.Count) record(s) in $([math]::Round($sw.Elapsed.TotalMilliseconds)) ms"
        }
        catch {
            $sw.Stop()
            Add-HHCollectorStat -Stats $stats -Collector $name -DurationMs $sw.Elapsed.TotalMilliseconds -Status 'failed'
            Add-CocEvent -EventType 'collector_error' -Details @{ collector = $name; error = "$($_.Exception.Message)" }
            Write-HHLog -Level Error -Message "  [$name] FAILED: $($_.Exception.Message)"
            if (-not $config.ContinueOnError) { throw }
        }
    }

    # --- Seal + report ---
    $manifest = Seal-EvidenceBundle -OutputPath $OutputPath -Collected $collected -Context $context `
        -TimeIntegrity $timeIntegrity -AuthDecision $auth -RunStats $stats

    Export-ConsolidatedBundle -OutputPath $OutputPath -Manifest $manifest -Collected $collected | Out-Null
    $reportPath = Write-HtmlReport -Manifest $manifest -Collected $collected -OutputPath $OutputPath

    Write-HHLog -Level Info -Message "Bundle sealed: $($manifest.bundle_sha256)"
    Write-HHLog -Level Info -Message "Report: $reportPath"

    # --- Optional transport encryption ---
    $encFile = $null
    if ($Encrypt) {
        $encFile = Protect-EvidenceBundle -BundlePath $OutputPath
    }

    Write-HHLog -Level Info -Message "Done. $($stats.CollectorsRun) collector(s) run, $($stats.TotalRecords) record(s), $($stats.CollectorsFailed) failed, $($stats.CollectorsSkipped) skipped."

    return [pscustomobject]@{
        OutputPath   = $OutputPath
        Manifest     = $manifest
        Authorized   = $auth.Authorized
        ReportPath   = $reportPath
        EncryptedTo  = $encFile
        Stats        = $stats
    }
}
