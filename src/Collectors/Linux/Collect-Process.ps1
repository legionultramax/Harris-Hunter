# Collect-Process.ps1 (Linux) - running processes from /proc, with image hash and
# deleted-executable detection (a running binary whose on-disk file is gone - a strong
# malware indicator). ATT&CK: T1059.004 (unix shell), T1070.004 (file deletion), T1055.

function Collect-Process {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    $pidDirs = @()
    try { $pidDirs = @(Get-ChildItem -LiteralPath '/proc' -Directory -ErrorAction Stop | Where-Object { $_.Name -match '^\d+$' }) } catch { return @() }

    # First pass: read each process's identity once and build lineage maps (pid -> exe/comm and
    # a child tally), so every record can carry its parent's image + how many children it spawned
    # (process-tree reconstruction for downstream detection). Reused in the emit pass below.
    $info       = [System.Collections.Generic.List[object]]::new()
    $exeByPid   = @{}
    $commByPid  = @{}
    $childCount = @{}

    foreach ($d in $pidDirs) {
        $procId = $d.Name

        $exeRaw = $null
        try { $exeRaw = (& readlink "/proc/$procId/exe" 2>$null) } catch { }
        $deleted = $false
        $exePath = $exeRaw
        if ($exeRaw -and $exeRaw.EndsWith(' (deleted)')) {
            $deleted = $true
            $exePath = $exeRaw.Substring(0, $exeRaw.Length - ' (deleted)'.Length)
        }

        $cmdline = $null
        try {
            $raw = Get-Content -LiteralPath "/proc/$procId/cmdline" -Raw -ErrorAction Stop
            if ($raw) { $cmdline = ($raw -replace "`0", ' ').Trim() }
        } catch { }

        $comm = $null
        try { $comm = (Get-Content -LiteralPath "/proc/$procId/comm" -Raw -ErrorAction Stop).Trim() } catch { }

        $ppid = Get-HHProcStatusField -ProcessId $procId -Field 'PPid'
        $uidLine = Get-HHProcStatusField -ProcessId $procId -Field 'Uid'   # "real eff saved fs"
        $uid = if ($uidLine) { ($uidLine -split '\s+')[0] } else { $null }
        $user = ConvertFrom-HHUid -Uid $uid

        $exeByPid[$procId]  = $exePath
        $commByPid[$procId] = $comm
        if ($ppid) {
            $childCount[$ppid] = 1 + $(if ($childCount.ContainsKey($ppid)) { $childCount[$ppid] } else { 0 })
        }

        $info.Add([pscustomobject]@{
            procId = $procId; exePath = $exePath; deleted = $deleted
            cmdline = $cmdline; comm = $comm; ppid = $ppid; uid = $uid; user = $user
        })
    }

    foreach ($pi in $info) {
        $ev = if ($pi.exePath) { Get-HHLinuxFileEvidence -Path $pi.exePath } else { $null }

        $parentComm  = if ($pi.ppid -and $commByPid.ContainsKey($pi.ppid)) { $commByPid[$pi.ppid] } else { $null }
        $parentImage = if ($pi.ppid -and $exeByPid.ContainsKey($pi.ppid))  { $exeByPid[$pi.ppid] }  else { $null }
        $kids        = if ($childCount.ContainsKey($pi.procId)) { $childCount[$pi.procId] } else { 0 }

        $attack = @()
        if ($pi.deleted) { $attack += 'T1070.004' }
        if ($pi.cmdline -match '(?i)\b(bash|sh|dash|zsh|python|python3|perl|ruby|nc|ncat|socat)\b') { $attack += 'T1059.004' }

        $records.Add((New-EvidenceRecord -ArtifactType 'process' -Collector 'Collect-Process' `
            -Source '/proc/<pid> + Get-FileHash' -Attack $attack -Context $Context -Data @{
                pid          = [int]$pi.procId
                ppid         = if ($pi.ppid) { [int]$pi.ppid } else { $null }
                comm         = $pi.comm
                parent_comm  = $parentComm
                parent_image = $parentImage
                child_count  = $kids
                user         = $pi.user
                uid          = $pi.uid
                exe          = $pi.exePath
                exe_deleted  = $pi.deleted
                command_line = $pi.cmdline
                sha256       = if ($ev) { $ev.sha256 } else { $null }
                image_size   = if ($ev) { $ev.size } else { $null }
                mode         = if ($ev) { $ev.mode } else { $null }
            }))
    }

    return $records.ToArray()
}
