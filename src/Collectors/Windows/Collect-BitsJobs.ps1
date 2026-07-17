# Collect-BitsJobs.ps1 - Background Intelligent Transfer Service jobs.
# ATT&CK: T1197 (BITS jobs) - abused for stealthy download/exfil and persistence.

function Collect-BitsJobs {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    $jobs = @()
    try { $jobs = Get-BitsTransfer -AllUsers -ErrorAction Stop } catch {
        try { $jobs = Get-BitsTransfer -ErrorAction Stop } catch { return @() }
    }

    foreach ($j in $jobs) {
        $files = @()
        try {
            $files = @($j.FileList | ForEach-Object {
                [ordered]@{ remote = $_.RemoteName; local = $_.LocalName }
            })
        } catch { }

        $records.Add((New-EvidenceRecord -ArtifactType 'bits_job' -Collector 'Collect-BitsJobs' `
            -Source 'Get-BitsTransfer' -Attack @('T1197') -Context $Context -Data @{
                display_name = $j.DisplayName
                job_id       = [string]$j.JobId
                state        = [string]$j.JobState
                owner        = $j.OwnerAccount
                created_utc  = if ($j.CreationTime) { $j.CreationTime.ToUniversalTime().ToString('o') } else { $null }
                priority     = [string]$j.Priority
                transfer_type= [string]$j.TransferType
                files        = $files
            }))
    }

    return $records.ToArray()
}
