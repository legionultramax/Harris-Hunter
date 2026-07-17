# Collect-MemoryHints.ps1 - memory-relevant configuration pointers (NOT a memory capture).
# Records where volatile evidence lives (pagefile, crash dumps, hibernation) so responders
# know what full-capture tooling should target next. Deliberately collects config, not content.

function Collect-MemoryHints {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $records.Add((New-EvidenceRecord -ArtifactType 'memory_summary' -Collector 'Collect-MemoryHints' `
            -Source 'Win32_OperatingSystem' -Context $Context -Data @{
                total_visible_kb   = $os.TotalVisibleMemorySize
                free_physical_kb   = $os.FreePhysicalMemory
                total_virtual_kb   = $os.TotalVirtualMemorySize
            }))
    } catch { }

    try {
        foreach ($pf in (Get-CimInstance Win32_PageFileUsage -ErrorAction Stop)) {
            $records.Add((New-EvidenceRecord -ArtifactType 'pagefile' -Collector 'Collect-MemoryHints' `
                -Source 'Win32_PageFileUsage' -Context $Context -Data @{
                    path            = $pf.Name
                    allocated_mb    = $pf.AllocatedBaseSize
                    current_usage_mb= $pf.CurrentUsage
                    peak_usage_mb   = $pf.PeakUsage
                }))
        }
    } catch { }

    try {
        $cd = Get-CimInstance Win32_OSRecoveryConfiguration -ErrorAction Stop
        $records.Add((New-EvidenceRecord -ArtifactType 'crashdump_config' -Collector 'Collect-MemoryHints' `
            -Source 'Win32_OSRecoveryConfiguration' -Context $Context -Data @{
                debug_info_type = $cd.DebugInfoType
                dump_file       = $cd.DebugFilePath
                minidump_dir    = $cd.MiniDumpDirectory
            }))
    } catch { }

    return $records.ToArray()
}
