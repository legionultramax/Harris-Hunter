# Collect-Process.ps1 (Linux) - running processes from /proc, with image hash and
# deleted-executable detection (a running binary whose on-disk file is gone - a strong
# malware indicator). ATT&CK: T1059.004 (unix shell), T1070.004 (file deletion), T1055.

function Collect-Process {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    $pidDirs = @()
    try { $pidDirs = @(Get-ChildItem -LiteralPath '/proc' -Directory -ErrorAction Stop | Where-Object { $_.Name -match '^\d+$' }) } catch { return @() }

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

        $ev = if ($exePath) { Get-HHLinuxFileEvidence -Path $exePath } else { $null }

        $attack = @()
        if ($deleted) { $attack += 'T1070.004' }
        if ($cmdline -match '(?i)\b(bash|sh|dash|zsh|python|python3|perl|ruby|nc|ncat|socat)\b') { $attack += 'T1059.004' }

        $records.Add((New-EvidenceRecord -ArtifactType 'process' -Collector 'Collect-Process' `
            -Source '/proc/<pid> + Get-FileHash' -Attack $attack -Context $Context -Data @{
                pid          = [int]$procId
                ppid         = if ($ppid) { [int]$ppid } else { $null }
                comm         = $comm
                user         = $user
                uid          = $uid
                exe          = $exePath
                exe_deleted  = $deleted
                command_line = $cmdline
                sha256       = if ($ev) { $ev.sha256 } else { $null }
                image_size   = if ($ev) { $ev.size } else { $null }
                mode         = if ($ev) { $ev.mode } else { $null }
            }))
    }

    return $records.ToArray()
}
