# Collect-Autoruns.ps1 - autostart extensibility points.
# ATT&CK: T1547.001 (Run keys/Startup), T1546.012 (IFEO), T1547.004 (Winlogon),
# T1547.002/005 (LSA), T1546.010 (AppInit), T1546.009 (AppCert), T1547.014 (Active Setup),
# T1547.010 (print monitors), T1546.002 (screensaver).

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
            if (Test-HHSuspectImage -Ev $ev) { [void](Add-FlaggedFile -Path $ev.path -KnownSha256 $ev.sha256) }
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

    # --- AppInit_DLLs (loaded into every process linking user32.dll) ---
    foreach ($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
    )) {
        $vals = Get-HHRegValues -Path $key
        if ($vals.ContainsKey('AppInit_DLLs') -and $vals['AppInit_DLLs']) {
            $records.Add((New-EvidenceRecord -ArtifactType 'autorun_appinit_dlls' -Collector 'Collect-Autoruns' `
                -Source $key -Attack @('T1546.010') -Context $Context -Data @{
                    location       = $key
                    appinit_dlls   = $vals['AppInit_DLLs']
                    load_appinit   = $vals['LoadAppInit_DLLs']
                    require_signed = $vals['RequireSignedAppInit_DLLs']
                }))
        }
    }

    # --- AppCertDlls (loaded via CreateProcess family) ---
    $appCert = Get-HHRegValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    if ($appCert.Count -gt 0) {
        $records.Add((New-EvidenceRecord -ArtifactType 'autorun_appcert_dlls' -Collector 'Collect-Autoruns' `
            -Source 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -Attack @('T1546.009') -Context $Context -Data @{
                location = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
                entries  = @($appCert.Keys | ForEach-Object { [ordered]@{ name = $_; dll = $appCert[$_] } })
            }))
    }

    # --- Active Setup StubPath (runs once per user at logon) ---
    foreach ($root in @(
        'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components'
    )) {
        try {
            Get-ChildItem -LiteralPath $root -ErrorAction Stop | ForEach-Object {
                $vals = Get-HHRegValues -Path $_.PSPath
                if ($vals.ContainsKey('StubPath') -and $vals['StubPath']) {
                    $ev = Get-HHFileEvidence -Path (Resolve-HHImagePath -CommandLine $vals['StubPath'])
                    if (Test-HHSuspectImage -Ev $ev) { [void](Add-FlaggedFile -Path $ev.path -KnownSha256 $ev.sha256) }
                    $records.Add((New-EvidenceRecord -ArtifactType 'autorun_active_setup' -Collector 'Collect-Autoruns' `
                        -Source $_.PSPath -Attack @('T1547.014') -Context $Context -Data @{
                            location  = $root
                            component = $_.PSChildName
                            name      = $vals['(default)']
                            stub_path = $vals['StubPath']
                            image     = $ev.path
                            sha256    = $ev.sha256
                            signed    = $ev.signed
                            signer    = $ev.signer
                        }))
                }
            }
        } catch { }
    }

    # --- Startup folders (all-users + per-user filesystem autostarts) ---
    $startupDirs = [System.Collections.Generic.List[string]]::new()
    $startupDirs.Add((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'))
    try {
        Get-ChildItem -LiteralPath 'C:\Users' -Directory -ErrorAction Stop | ForEach-Object {
            $startupDirs.Add((Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'))
        }
    } catch { }
    foreach ($dir in $startupDirs) {
        try {
            if (-not (Test-Path -LiteralPath $dir -ErrorAction SilentlyContinue)) { continue }
            Get-ChildItem -LiteralPath $dir -File -ErrorAction Stop | ForEach-Object {
                $ev = Get-HHFileEvidence -Path $_.FullName
                if (Test-HHSuspectImage -Ev $ev) { [void](Add-FlaggedFile -Path $ev.path -KnownSha256 $ev.sha256) }
                $records.Add((New-EvidenceRecord -ArtifactType 'autorun_startup_folder' -Collector 'Collect-Autoruns' `
                    -Source $dir -Attack @('T1547.001') -Context $Context -Data @{
                        location  = $dir
                        name      = $_.Name
                        image     = $ev.path
                        sha256    = $ev.sha256
                        signed    = $ev.signed
                        signer    = $ev.signer
                        mtime_utc = $_.LastWriteTimeUtc.ToString('o')
                    }))
            }
        } catch { }
    }

    # --- Print monitors (Driver DLL loaded by spoolsv.exe as SYSTEM) ---
    try {
        Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -ErrorAction Stop | ForEach-Object {
            $vals = Get-HHRegValues -Path $_.PSPath
            if ($vals.ContainsKey('Driver') -and $vals['Driver']) {
                $records.Add((New-EvidenceRecord -ArtifactType 'autorun_print_monitor' -Collector 'Collect-Autoruns' `
                    -Source $_.PSPath -Attack @('T1547.010') -Context $Context -Data @{
                        monitor = $_.PSChildName
                        driver  = $vals['Driver']
                    }))
            }
        }
    } catch { }

    # --- Screensaver executable (operator hive) ---
    $scr = Get-HHRegValues -Path 'HKCU:\Control Panel\Desktop'
    if ($scr.ContainsKey('SCRNSAVE.EXE') -and $scr['SCRNSAVE.EXE']) {
        $ev = Get-HHFileEvidence -Path (Resolve-HHImagePath -CommandLine $scr['SCRNSAVE.EXE'])
        if (Test-HHSuspectImage -Ev $ev) { [void](Add-FlaggedFile -Path $ev.path -KnownSha256 $ev.sha256) }
        $records.Add((New-EvidenceRecord -ArtifactType 'autorun_screensaver' -Collector 'Collect-Autoruns' `
            -Source 'HKCU\Control Panel\Desktop' -Attack @('T1546.002') -Context $Context -Data @{
                scrnsave = $scr['SCRNSAVE.EXE']
                active   = $scr['ScreenSaveActive']
                image    = $ev.path
                sha256   = $ev.sha256
                signed   = $ev.signed
                signer   = $ev.signer
            }))
    }

    return $records.ToArray()
}
