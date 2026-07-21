# _LinuxHelpers.ps1 - shared helpers for Linux collectors (loaded only on Linux).
# Not a collector (no Collect- prefix). Get-HHStringHash / Get-HHFileHash come from Core.

$script:HHLinuxFileCache = @{}

function Reset-HHFileEvidenceCache {
    # Called by the orchestrator at the start of each run so a second Invoke in the same
    # session never serves stale file hashes or a stale uid->name map.
    $script:HHLinuxFileCache = @{}
    $script:HHUidMap = $null
}

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
    param([Parameter(Mandatory)][string]$ProcessId, [Parameter(Mandatory)][string]$Field)
    try {
        foreach ($line in (Get-Content -LiteralPath "/proc/$ProcessId/status" -ErrorAction Stop)) {
            if ($line -match "^$Field`:\s*(.+)$") { return $Matches[1].Trim() }
        }
    } catch { }
    return $null
}

function Get-HHLocalScanRoots {
    <#
    .SYNOPSIS
        Mount points backed by a real local persistent filesystem (from /proc/self/mounts), plus the
        high-risk volatile dirs (/tmp, /var/tmp, /dev/shm). Excludes network (nfs/cifs), drvfs/9p
        (e.g. WSL's Windows drives), overlay, and pseudo-filesystems - the mounts that make an
        unbounded walk slow or meaningless. De-duped.
    #>
    $localFs = @('ext2','ext3','ext4','xfs','btrfs','f2fs','jfs','reiserfs','reiser4','zfs')
    $roots = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($line in (Get-Content -LiteralPath '/proc/self/mounts' -ErrorAction Stop)) {
            $f = $line -split '\s+'
            if ($f.Count -ge 3 -and ($localFs -contains $f[2])) {
                $mp = $f[1] -replace '\\040', ' '   # /proc/mounts octal-escapes spaces
                if ($mp -and ($roots -notcontains $mp)) { $roots.Add($mp) }
            }
        }
    } catch { }
    foreach ($d in @('/tmp','/var/tmp','/dev/shm')) {
        if ((Test-Path -LiteralPath $d) -and ($roots -notcontains $d)) { $roots.Add($d) }
    }
    if ($roots.Count -eq 0) { $roots.Add('/') }
    return $roots.ToArray()
}

function Invoke-HHBoundedFind {
    <#
    .SYNOPSIS
        Run `find` over ONE filesystem, bounded to that filesystem by -xdev and (where available)
        under a hard `timeout` so a slow/huge/remote mount degrades gracefully instead of hanging.
        Never throws. Returns { Files = <string[]>; Truncated = <bool> } - Truncated is $true when the
        timeout killed the walk (exit 124). Every recursive filesystem walk in the Linux collectors
        goes through this, so the "unbounded walk that hangs the run" class of bug cannot recur.
    .PARAMETER Predicate
        find expression AFTER "find <root> -xdev" (e.g. '-type','f','-perm','-4000').
    #>
    param(
        [Parameter(Mandatory)][string]$Root,
        [string[]]$Predicate = @(),
        [int]$TimeoutSec = 120
    )
    $out = $null; $truncated = $false
    try {
        if (Test-HHCommand 'timeout') {
            $out = & timeout $TimeoutSec find $Root -xdev @Predicate 2>$null
            if ($LASTEXITCODE -eq 124) { $truncated = $true }
        } else {
            $out = & find $Root -xdev @Predicate 2>$null
        }
    } catch { }
    return [pscustomobject]@{ Files = @($out | Where-Object { $_ }); Truncated = $truncated }
}

function Invoke-HHBoundedTool {
    <#
    .SYNOPSIS
        Run an external command under a hard `timeout` (where available) so a slow tool degrades
        gracefully instead of hanging the run. Never throws. Returns { Lines = <string[]>;
        Truncated = <bool> } (Truncated = timeout killed it, exit 124). Used for the slow
        package-verification tools (rpm -Va / debsums / dpkg --verify) that re-hash every packaged
        file and can run for minutes.
    #>
    param(
        [Parameter(Mandatory)][string]$Command,
        [string[]]$Arguments = @(),
        [int]$TimeoutSec = 300,
        [int]$Max = 1000
    )
    $out = $null; $truncated = $false
    try {
        if (Test-HHCommand 'timeout') {
            $out = & timeout $TimeoutSec $Command @Arguments 2>$null
            if ($LASTEXITCODE -eq 124) { $truncated = $true }
        } else {
            $out = & $Command @Arguments 2>$null
        }
    } catch { }
    return [pscustomobject]@{ Lines = @($out | Where-Object { $_ } | Select-Object -First $Max); Truncated = $truncated }
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
