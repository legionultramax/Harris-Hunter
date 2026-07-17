# Collect-DefenderState.ps1 - Microsoft Defender status, exclusions, threat history.
# Exclusions (T1562.001, impair defenses) are high-value: attackers add them to hide payloads.

function Collect-DefenderState {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        $records.Add((New-EvidenceRecord -ArtifactType 'defender_status' -Collector 'Collect-DefenderState' `
            -Source 'Get-MpComputerStatus' -Context $Context -Data @{
                am_service_enabled     = [bool]$s.AMServiceEnabled
                antispyware_enabled    = [bool]$s.AntispywareEnabled
                antivirus_enabled      = [bool]$s.AntivirusEnabled
                realtime_enabled       = [bool]$s.RealTimeProtectionEnabled
                behavior_monitor       = [bool]$s.BehaviorMonitorEnabled
                tamper_protected       = [bool]$s.IsTamperProtected
                engine_version         = $s.AMEngineVersion
                signature_version      = $s.AntivirusSignatureVersion
                signature_age_days     = $s.AntivirusSignatureAge
            }))
    } catch { }

    try {
        $p = Get-MpPreference -ErrorAction Stop
        $hasExclusions = (@($p.ExclusionPath).Count + @($p.ExclusionProcess).Count + @($p.ExclusionExtension).Count) -gt 0
        $records.Add((New-EvidenceRecord -ArtifactType 'defender_preferences' -Collector 'Collect-DefenderState' `
            -Source 'Get-MpPreference' -Attack ($(if ($hasExclusions) { @('T1562.001') } else { @() })) -Context $Context -Data @{
                exclusion_paths      = @($p.ExclusionPath)
                exclusion_processes  = @($p.ExclusionProcess)
                exclusion_extensions = @($p.ExclusionExtension)
                disable_realtime     = [bool]$p.DisableRealtimeMonitoring
                disable_ioav         = [bool]$p.DisableIOAVProtection
                submit_samples       = [string]$p.SubmitSamplesConsent
                mapmb_reporting      = [string]$p.MAPSReporting
            }))
    } catch { }

    try {
        foreach ($t in (Get-MpThreatDetection -ErrorAction Stop)) {
            $records.Add((New-EvidenceRecord -ArtifactType 'defender_detection' -Collector 'Collect-DefenderState' `
                -Source 'Get-MpThreatDetection' -Attack @('T1204') -Context $Context -Data @{
                    threat_id       = $t.ThreatID
                    detection_time  = if ($t.InitialDetectionTime) { $t.InitialDetectionTime.ToUniversalTime().ToString('o') } else { $null }
                    resources       = @($t.Resources)
                    action_success  = [bool]$t.ActionSuccess
                }))
        }
    } catch { }

    return $records.ToArray()
}
