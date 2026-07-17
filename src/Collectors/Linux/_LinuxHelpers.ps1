# _LinuxHelpers.ps1 - shared helpers for Linux collectors (loaded only on Linux).
# Not a collector (no Collect- prefix). Get-HHStringHash / Get-HHFileHash come from Core.

$script:HHLinuxFileCache = @{}

function Get-HHLinuxFileEvidence {
    <#
    .SYNOPSIS
        Normalized file evidence for a path: existence, size, SHA-256, mode/owner/group,
        mtime. Cached per run. Never throws. (No Authenticode on Linux.)
    #>
    param([string]$Path)
    $result = [ordered]@{
        path      = $Path
        exists    = $false
        size      = $null
        sha256    = $null
        mode      = $null
        owner     = $null
        group     = $null
        mtime_utc = $null
    }
    if (-not $Path) { return $result }
    if ($script:HHLinuxFileCache.ContainsKey($Path)) { return $script:HHLinuxFileCache[$Path] }

    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction Stop)) {
            $script:HHLinuxFileCache[$Path] = $result; return $result
        }
    } catch { $script:HHLinuxFileCache[$Path] = $result; return $result }
    $result.exists = $true

    try {
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $result.size = $fi.Length
        $result.mtime_utc = $fi.LastWriteTimeUtc.ToString('o')
    } catch { }
    try { $result.sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { }
    try {
        $s = & stat -c '%A|%U|%G' $Path 2>$null
        if ($s) { $parts = ($s.Trim() -split '\|'); $result.mode = $parts[0]; $result.owner = $parts[1]; $result.group = $parts[2] }
    } catch { }

    $script:HHLinuxFileCache[$Path] = $result
    return $result
}

function Get-HHLinuxUsers {
    <#
    .SYNOPSIS
        Parse /etc/passwd into user objects (name, uid, gid, home, shell). Best-effort.
    #>
    $users = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($l in (Get-Content -LiteralPath '/etc/passwd' -ErrorAction Stop)) {
            if (-not $l -or $l.StartsWith('#')) { continue }
            $p = $l -split ':'
            if ($p.Count -ge 7) {
                $users.Add([ordered]@{ name = $p[0]; uid = $p[2]; gid = $p[3]; home = $p[5]; shell = $p[6] })
            }
        }
    } catch { }
    return $users.ToArray()
}

function Get-HHProcStatusField {
    <#
    .SYNOPSIS
        Read a single field (e.g. PPid, Uid, Name) from /proc/<pid>/status.
    #>
    param([Parameter(Mandatory)][string]$Pid, [Parameter(Mandatory)][string]$Field)
    try {
        foreach ($line in (Get-Content -LiteralPath "/proc/$Pid/status" -ErrorAction Stop)) {
            if ($line -match "^$Field`:\s*(.+)$") { return $Matches[1].Trim() }
        }
    } catch { }
    return $null
}

function ConvertFrom-HHUid {
    <#
    .SYNOPSIS
        Resolve a numeric uid to a username from /etc/passwd (best-effort).
    #>
    param([string]$Uid)
    if (-not $Uid) { return $null }
    if (-not $script:HHUidMap) {
        $script:HHUidMap = @{}
        try {
            foreach ($l in (Get-Content -LiteralPath '/etc/passwd' -ErrorAction Stop)) {
                $p = $l -split ':'
                if ($p.Count -ge 3) { $script:HHUidMap[$p[2]] = $p[0] }
            }
        } catch { }
    }
    if ($script:HHUidMap.ContainsKey($Uid)) { return $script:HHUidMap[$Uid] }
    return $Uid
}
