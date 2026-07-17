# Collect-Services.ps1 - Windows services with binary hash + signature.
# ATT&CK: T1543.003 (create/modify system process: Windows service).

function Collect-Services {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    $svcs = @()
    try { $svcs = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop } catch { return @() }

    foreach ($s in $svcs) {
        $image = Resolve-HHImagePath -CommandLine $s.PathName
        $ev = Get-HHFileEvidence -Path $image

        $attack = @('T1543.003')
        # Service binary outside system dirs or unsigned is worth flagging cheaply.
        if ($ev.exists -and -not $ev.signed) { $attack += 'T1543.003' }

        $records.Add((New-EvidenceRecord -ArtifactType 'service' -Collector 'Collect-Services' `
            -Source 'Win32_Service' -Attack ($attack | Select-Object -Unique) -Context $Context -Data @{
                name             = $s.Name
                display_name     = $s.DisplayName
                state            = $s.State
                start_mode       = $s.StartMode
                start_name       = $s.StartName       # log-on account
                path_name        = $s.PathName
                image            = $ev.path
                sha256           = $ev.sha256
                signed           = $ev.signed
                signer           = $ev.signer
                signature_status = $ev.signature_status
                pid              = $s.ProcessId
                description      = $s.Description
            }))
    }

    return $records.ToArray()
}
