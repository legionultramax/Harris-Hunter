# _CollectorHelpers.ps1 - shared helpers for Windows collectors.
# Loaded with the rest of src (function resolution is at call time, so load order is
# irrelevant). Not a collector (no Collect- prefix), so the orchestrator never invokes it.

# Per-run cache so the same image is hashed/verified once even if many processes or
# services reference it (e.g. svchost.exe).
$script:HHFileEvidenceCache = @{}

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
