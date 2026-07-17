# _CollectorHelpers.ps1 - shared helpers for Windows collectors.
# Loaded with the rest of src (function resolution is at call time, so load order is
# irrelevant). Not a collector (no Collect- prefix), so the orchestrator never invokes it.

# Per-run cache so the same image is hashed/verified once even if many processes or
# services reference it (e.g. svchost.exe).
$script:HHFileEvidenceCache = @{}

function Reset-HHFileEvidenceCache {
    # Called by the orchestrator at the start of each run so a second Invoke in the same
    # session never serves file hashes computed against an earlier run's file state.
    $script:HHFileEvidenceCache = @{}
}

function Resolve-HHImagePath {
    <#
    .SYNOPSIS
        Extract the executable path from a raw command line and expand env vars.
        Handles "C:\path with spaces\x.exe" -args, svchost.exe -k netsvcs, rundll32, etc.
    #>
    param([string]$CommandLine)
    if (-not $CommandLine) { return $null }
    $cl = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())

    if ($cl.StartsWith('"')) {
        $end = $cl.IndexOf('"', 1)
        if ($end -gt 1) { return $cl.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($cl, '^(.*?\.(?:exe|dll|sys|scr|com))\b', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($cl -split '\s+')[0]
}

function Get-HHFileEvidence {
    <#
    .SYNOPSIS
        Return normalized file evidence for an image path: existence, size, SHA-256,
        and Authenticode signature status/signer. Cached per run. Never throws.
    #>
    param([string]$Path)

    $result = [ordered]@{
        path             = $Path
        exists           = $false
        size             = $null
        sha256           = $null
        signed           = $null
        signer           = $null
        signature_status = $null
    }
    if (-not $Path) { return $result }

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    $result.path = $expanded

    if ($script:HHFileEvidenceCache.ContainsKey($expanded)) {
        return $script:HHFileEvidenceCache[$expanded]
    }

    try {
        if (-not (Test-Path -LiteralPath $expanded -PathType Leaf -ErrorAction Stop)) {
            $script:HHFileEvidenceCache[$expanded] = $result
            return $result
        }
    } catch {
        # Illegal path chars, unmapped drive, etc. - treat as not-collectable.
        $script:HHFileEvidenceCache[$expanded] = $result
        return $result
    }
    $result.exists = $true

    try { $result.size = (Get-Item -LiteralPath $expanded -ErrorAction Stop).Length } catch { }
    try { $result.sha256 = (Get-FileHash -LiteralPath $expanded -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $expanded -ErrorAction Stop
        $result.signature_status = [string]$sig.Status
        $result.signed = ($sig.Status -eq 'Valid')
        if ($sig.SignerCertificate) { $result.signer = $sig.SignerCertificate.Subject }
    } catch { }

    $script:HHFileEvidenceCache[$expanded] = $result
    return $result
}

function Read-HHFileBytesShared {
    <#
    .SYNOPSIS
        Read up to MaxBytes of a file with FileShare.ReadWrite so live-locked files (e.g. a
        browser History DB held open by the browser) can still be read. Returns byte[] or $null.
    #>
    param([Parameter(Mandatory)][string]$Path, [int]$MaxBytes = 52428800)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $len = [int][Math]::Min([long]$fs.Length, [long]$MaxBytes)
            $buf = New-Object byte[] $len
            $off = 0
            while ($off -lt $len) {
                $n = $fs.Read($buf, $off, $len - $off)
                if ($n -le 0) { break }
                $off += $n
            }
            if ($off -eq $len) { return $buf } else { return $buf[0..($off - 1)] }
        } finally { $fs.Dispose() }
    } catch { return $null }
}

function Get-HHRegValues {
    <#
    .SYNOPSIS
        Return the value name/data pairs under a registry key as a hashtable, or an
        empty hashtable if the key is absent/unreadable. Skips PS* metadata properties.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $out = @{}
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $out }
        $props = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                $out[$p.Name] = $p.Value
            }
        }
    } catch { }
    return $out
}
