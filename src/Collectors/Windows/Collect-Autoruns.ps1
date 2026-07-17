# Collect-Autoruns.ps1 - autostart extensibility points.
# ATT&CK: T1547.001 (Run keys), T1546.012 (IFEO), T1547.004 (Winlogon), T1547.002/005 (LSA).

function Collect-Autoruns {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    # --- Run / RunOnce keys (machine + wow64 + current user) ---
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        foreach ($kv in (Get-HHRegValues -Path $key).GetEnumerator()) {
            $ev = Get-HHFileEvidence -Path (Resolve-HHImagePath -CommandLine $kv.Value)
            $records.Add((New-EvidenceRecord -ArtifactType 'autorun_run_key' -Collector 'Collect-Autoruns' `
                -Source $key -Attack @('T1547.001') -Context $Context -Data @{
                    location  = $key
                    name      = $kv.Key
                    command   = $kv.Value
                    image     = $ev.path
                    sha256    = $ev.sha256
                    signed    = $ev.signed
                    signer    = $ev.signer
                }))
        }
    }

    # --- Image File Execution Options: Debugger hijacks ---
    $ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    try {
        Get-ChildItem -LiteralPath $ifeoRoot -ErrorAction Stop | ForEach-Object {
            $vals = Get-HHRegValues -Path $_.PSPath
            if ($vals.ContainsKey('Debugger') -or $vals.ContainsKey('GlobalFlag')) {
                $records.Add((New-EvidenceRecord -ArtifactType 'autorun_ifeo' -Collector 'Collect-Autoruns' `
                    -Source $_.PSPath -Attack @('T1546.012') -Context $Context -Data @{
                        image_name = $_.PSChildName
                        debugger   = $vals['Debugger']
                        global_flag= $vals['GlobalFlag']
                    }))
            }
        }
    } catch { }

    # --- Winlogon Shell / Userinit ---
    $wl = Get-HHRegValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if ($wl.Count -gt 0) {
        $records.Add((New-EvidenceRecord -ArtifactType 'autorun_winlogon' -Collector 'Collect-Autoruns' `
            -Source 'Winlogon' -Attack @('T1547.004') -Context $Context -Data @{
                shell    = $wl['Shell']
                userinit = $wl['Userinit']
            }))
    }

    # --- LSA authentication / security packages ---
    $lsa = Get-HHRegValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if ($lsa.Count -gt 0) {
        $records.Add((New-EvidenceRecord -ArtifactType 'autorun_lsa' -Collector 'Collect-Autoruns' `
            -Source 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -Attack @('T1547.002', 'T1547.005') -Context $Context -Data @{
                authentication_packages = @($lsa['Authentication Packages'])
                security_packages       = @($lsa['Security Packages'])
                notification_packages   = @($lsa['Notification Packages'])
            }))
    }

    return $records.ToArray()
}
