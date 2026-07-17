# Collect-System.ps1 - OS, hardware, boot time, and installed hotfixes.

function Collect-System {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $records.Add((New-EvidenceRecord -ArtifactType 'os_info' -Collector 'Collect-System' `
            -Source 'Win32_OperatingSystem' -Context $Context -Data @{
                caption          = $os.Caption
                version          = $os.Version
                build            = $os.BuildNumber
                architecture     = $os.OSArchitecture
                install_date     = if ($os.InstallDate) { $os.InstallDate.ToUniversalTime().ToString('o') } else { $null }
                last_boot_utc    = if ($os.LastBootUpTime) { $os.LastBootUpTime.ToUniversalTime().ToString('o') } else { $null }
                serial_number    = $os.SerialNumber
                registered_user  = $os.RegisteredUser
                system_directory = $os.SystemDirectory
                country_code     = $os.CountryCode
            }))
    } catch { }

    try {
        $cs  = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
        $cpu  = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        $records.Add((New-EvidenceRecord -ArtifactType 'hardware' -Collector 'Collect-System' `
            -Source 'Win32_ComputerSystem/BIOS/Processor' -Context $Context -Data @{
                manufacturer     = $cs.Manufacturer
                model            = $cs.Model
                domain           = $cs.Domain
                part_of_domain   = [bool]$cs.PartOfDomain
                total_ram_bytes  = $cs.TotalPhysicalMemory
                logical_procs    = $cs.NumberOfLogicalProcessors
                cpu              = if ($cpu) { $cpu.Name } else { $null }
                bios_version     = if ($bios) { $bios.SMBIOSBIOSVersion } else { $null }
                bios_serial      = if ($bios) { $bios.SerialNumber } else { $null }
            }))
    } catch { }

    try {
        foreach ($hf in (Get-HotFix -ErrorAction Stop)) {
            $records.Add((New-EvidenceRecord -ArtifactType 'hotfix' -Collector 'Collect-System' `
                -Source 'Get-HotFix' -Context $Context -Data @{
                    hotfix_id    = $hf.HotFixID
                    description  = $hf.Description
                    installed_by = $hf.InstalledBy
                    installed_on = if ($hf.InstalledOn) { $hf.InstalledOn.ToUniversalTime().ToString('o') } else { $null }
                }))
        }
    } catch { }

    return $records.ToArray()
}
