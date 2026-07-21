# EvidenceFiles.ps1 - raw evidence file sink + bounded flagged-file capture.
# Lets collectors contribute raw binary artifacts (e.g. exported .evtx) that are copied into
# the bundle, hashed, and folded into the manifest + bundle hash + custody ledger. Collectors
# still do not own hashing or the manifest; they only hand a source path to Add-EvidenceFile.
#
# Add-FlaggedFile (CGD-CA-DESIGN-001 section 10.2) captures flagged files / high-risk paths as a
# BOUNDED set (not full disk): per-file size cap, global count + byte budget, an executable/script
# eligibility gate, and a full-collection-mode gate (raw file bytes are content, like credentials).
# It is a thin policy layer over Add-EvidenceFile so captured files re-use the same hash + custody path.

$script:HHEvidenceFileDir = $null
$script:HHEvidenceFiles    = [System.Collections.Generic.List[object]]::new()

# Flagged-file capture state (reset per run by Initialize-EvidenceFiles).
$script:HHCaptureMode      = 'minimized'
$script:HHCapturePolicy    = $null
$script:HHFlaggedCaptured  = @{}
$script:HHFlaggedBytes     = [long]0
$script:HHFlaggedCount     = 0

function Get-HHCaptureDefaults {
    # The bounded-capture policy defaults. Overridable via config/constants.json evidence_capture.
    return @{
        enabled           = $true
        max_file_bytes    = [long]33554432    # 32 MiB per file
        max_total_bytes   = [long]268435456   # 256 MiB total per run
        max_files         = 512
        script_extensions = @('.ps1','.psm1','.psd1','.vbs','.vbe','.js','.jse','.wsf','.wsh',
                              '.bat','.cmd','.sh','.py','.pl','.rb','.php','.hta','.jar','.lnk')
    }
}

function Get-HHNormalizedCapturePolicy {
    # Merge a raw config node (IDictionary or PSCustomObject or $null) over the defaults and
    # coerce types so downstream comparisons are total-ordered and never throw under StrictMode.
    param($Raw)
    $defaults = Get-HHCaptureDefaults
    $out = @{}
    foreach ($k in $defaults.Keys) { $out[$k] = $defaults[$k] }
    if ($null -ne $Raw) {
        foreach ($k in @($defaults.Keys)) {
            $v = $null
            if ($Raw -is [System.Collections.IDictionary]) {
                if ($Raw.Contains($k)) { $v = $Raw[$k] }
            } elseif ($Raw.PSObject -and $Raw.PSObject.Properties[$k]) {
                $v = $Raw.PSObject.Properties[$k].Value
            }
            if ($null -ne $v) { $out[$k] = $v }
        }
    }
    $out['enabled']         = [bool]$out['enabled']
    $out['max_file_bytes']  = [long]$out['max_file_bytes']
    $out['max_total_bytes'] = [long]$out['max_total_bytes']
    $out['max_files']       = [int]$out['max_files']
    $out['script_extensions'] = @(@($out['script_extensions']) | ForEach-Object { ([string]$_).ToLowerInvariant() })
    return $out
}

function Initialize-EvidenceFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$SubDir = 'files',
        $CapturePolicy,
        [string]$CollectionMode = 'minimized'
    )
    $script:HHEvidenceFileDir = Join-Path $OutputPath $SubDir
    $script:HHEvidenceFiles    = [System.Collections.Generic.List[object]]::new()
    Set-HHCapturePolicy -Policy $CapturePolicy -CollectionMode $CollectionMode
}

function Set-HHCapturePolicy {
    <#
    .SYNOPSIS
        Set (or reset) the bounded flagged-file capture policy + collection mode, and clear the
        per-run capture counters. Called by Initialize-EvidenceFiles; also usable to tune at runtime.
    #>
    [CmdletBinding()]
    param($Policy, [string]$CollectionMode)
    if ($PSBoundParameters.ContainsKey('CollectionMode') -and $CollectionMode) { $script:HHCaptureMode = $CollectionMode }
    $script:HHCapturePolicy   = Get-HHNormalizedCapturePolicy -Raw $Policy
    $script:HHFlaggedCaptured = @{}
    $script:HHFlaggedBytes    = [long]0
    $script:HHFlaggedCount    = 0
}

function Add-EvidenceFile {
    <#
    .SYNOPSIS
        Copy a raw evidence file into files/<category>/ inside the bundle, hash it, register
        it for the manifest, and log it to the custody ledger. Returns the record or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$Category,
        [string]$Name
    )
    if (-not $script:HHEvidenceFileDir) { throw 'Evidence file sink not initialized. Call Initialize-EvidenceFiles first.' }
    if (-not (Test-Path -LiteralPath $SourcePath -ErrorAction SilentlyContinue)) { return $null }
    if (-not $Name) { $Name = Split-Path -Leaf $SourcePath }
    # Defense-in-depth: never let a caller-supplied name escape the category dir (path traversal).
    $Name = Split-Path -Leaf $Name

    $catDir = Join-Path $script:HHEvidenceFileDir $Category
    if (-not (Test-Path -LiteralPath $catDir)) { New-Item -ItemType Directory -Path $catDir -Force | Out-Null }

    # Guarantee a unique destination name so distinct sources never overwrite each other
    # (e.g. multiple browser profiles each with a 'History' file). A collision would leave one
    # file on disk but multiple manifest entries -> false "tampering" on re-verify.
    $dest = Join-Path $catDir $Name
    if (Test-Path -LiteralPath $dest) {
        # Append the counter at the very end (not before a "." - names like a user's
        # foo.bar aren't extensions). Collisions here are rare (e.g. multiple browser profiles).
        $orig = $Name
        $i = 1
        do { $Name = "${orig}_$i"; $dest = Join-Path $catDir $Name; $i++ } while (Test-Path -LiteralPath $dest)
    }
    try { Copy-Item -LiteralPath $SourcePath -Destination $dest -Force -ErrorAction Stop }
    catch { return $null }

    $rec = [ordered]@{
        file     = "files/$Category/$Name"
        category = $Category
        source   = $SourcePath
        size     = (Get-Item -LiteralPath $dest).Length
        sha256   = (Get-HHFileHash -Path $dest)
    }
    $script:HHEvidenceFiles.Add($rec)

    # Custody: record the raw file capture if the ledger is active.
    if ($script:HHCocPath) {
        Add-CocEvent -EventType 'evidence_file_added' -Details @{
            file = $rec.file; source = $rec.source; sha256 = $rec.sha256; size = $rec.size
        }
    }
    return $rec
}

function Read-HHFileHeaderBytes {
    # Read up to Count leading bytes with FileShare.ReadWrite so live/locked files (e.g. a running
    # image) can still be classified. Cross-platform (pure System.IO). Returns byte[] or $null.
    param([Parameter(Mandatory)][string]$Path, [int]$Count = 4)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $n = [int][Math]::Min([long]$fs.Length, [long]$Count)
            if ($n -le 0) { return $null }
            $buf = New-Object byte[] $n
            $off = 0
            while ($off -lt $n) { $r = $fs.Read($buf, $off, $n - $off); if ($r -le 0) { break }; $off += $r }
            if ($off -lt $n) { return $buf[0..($off - 1)] }
            return $buf
        } finally { $fs.Dispose() }
    } catch { return $null }
}

function Test-HHCaptureEligible {
    <#
    .SYNOPSIS
        True when a path is worth capturing for later file-content scanning (YARA/ClamAV): its
        header is a known executable magic (PE/ELF/Mach-O/shebang) OR its extension is a known
        script type. This is the "not full disk, for performance" gate of section 10.2.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, $Policy)
    if (-not $Policy) { $Policy = Get-HHNormalizedCapturePolicy -Raw $null }

    $hdr = Read-HHFileHeaderBytes -Path $Path -Count 4
    if ($hdr -and $hdr.Length -ge 2) {
        if ($hdr[0] -eq 0x4D -and $hdr[1] -eq 0x5A) { return $true }   # MZ  -> PE (exe/dll/sys/scr)
        if ($hdr[0] -eq 0x23 -and $hdr[1] -eq 0x21) { return $true }   # #!  -> script shebang
        if ($hdr.Length -ge 4) {
            $m0 = $hdr[0]; $m1 = $hdr[1]; $m2 = $hdr[2]; $m3 = $hdr[3]
            if ($m0 -eq 0x7F -and $m1 -eq 0x45 -and $m2 -eq 0x4C -and $m3 -eq 0x46) { return $true }  # ELF
            # Mach-O 32/64 (LE+BE) and universal/fat
            if (($m0 -eq 0xFE -and $m1 -eq 0xED -and $m2 -eq 0xFA -and ($m3 -eq 0xCE -or $m3 -eq 0xCF)) -or
                (($m0 -eq 0xCE -or $m0 -eq 0xCF) -and $m1 -eq 0xFA -and $m2 -eq 0xED -and $m3 -eq 0xFE) -or
                ($m0 -eq 0xCA -and $m1 -eq 0xFE -and $m2 -eq 0xBA -and $m3 -eq 0xBE)) { return $true }
        }
    }
    # Header-less scripts (a .ps1/.bat has no magic) - fall back to an extension allowlist.
    $ext = [System.IO.Path]::GetExtension($Path)
    if ($ext) {
        $ext = $ext.ToLowerInvariant()
        if (@($Policy['script_extensions']) -contains $ext) { return $true }
    }
    return $false
}

function Add-FlaggedFile {
    <#
    .SYNOPSIS
        Capture a flagged file into the bundle as part of the BOUNDED high-risk set (section 10.2),
        subject to: full-collection-mode gate, per-file size cap, global count + byte budget,
        eligibility (executable/script) gate, and per-run path de-duplication. Delegates the actual
        copy+hash+manifest+custody to Add-EvidenceFile. Never throws; returns a result object.
    .OUTPUTS
        [pscustomobject] { captured; deduped; reason; file; sha256 }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Category = 'flagged',
        [string]$KnownSha256
    )
    $result = [ordered]@{ captured = $false; deduped = $false; reason = $null; file = $null; sha256 = $KnownSha256 }

    if (-not $script:HHEvidenceFileDir) { $result.reason = 'sink_uninitialized'; return [pscustomobject]$result }
    $pol = $script:HHCapturePolicy
    if (-not $pol) { $pol = Get-HHNormalizedCapturePolicy -Raw $null }
    if (-not $pol['enabled'])            { $result.reason = 'disabled';      return [pscustomobject]$result }
    if ($script:HHCaptureMode -ne 'full'){ $result.reason = 'mode_not_full'; return [pscustomobject]$result }
    if (-not $Path)                      { $result.reason = 'no_path';       return [pscustomobject]$result }

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    $full = $null
    try { $full = (Resolve-Path -LiteralPath $expanded -ErrorAction Stop).Path } catch { $result.reason = 'not_found'; return [pscustomobject]$result }
    try { if (-not (Test-Path -LiteralPath $full -PathType Leaf -ErrorAction Stop)) { $result.reason = 'not_a_file'; return [pscustomobject]$result } }
    catch { $result.reason = 'not_a_file'; return [pscustomobject]$result }

    # De-dup: the same image is referenced by many processes/services (e.g. svchost.exe). Capture
    # once; hand later callers the existing record so they can still link by file/sha256.
    $key = $full.ToLowerInvariant()
    if ($script:HHFlaggedCaptured.ContainsKey($key)) {
        $prev = $script:HHFlaggedCaptured[$key]
        $result.captured = $true; $result.deduped = $true; $result.file = $prev.file; $result.sha256 = $prev.sha256
        return [pscustomobject]$result
    }

    $size = [long]0
    try { $size = [long](Get-Item -LiteralPath $full -ErrorAction Stop).Length } catch { $result.reason = 'stat_failed'; return [pscustomobject]$result }
    if ($size -gt [long]$pol['max_file_bytes'])                          { $result.reason = 'too_large';  return [pscustomobject]$result }
    if ($script:HHFlaggedCount -ge [int]$pol['max_files'])              { $result.reason = 'max_files';   return [pscustomobject]$result }
    if (($script:HHFlaggedBytes + $size) -gt [long]$pol['max_total_bytes']) { $result.reason = 'byte_budget'; return [pscustomobject]$result }
    if (-not (Test-HHCaptureEligible -Path $full -Policy $pol))          { $result.reason = 'ineligible_type'; return [pscustomobject]$result }

    $rec = Add-EvidenceFile -SourcePath $full -Category $Category
    if (-not $rec) { $result.reason = 'copy_failed'; return [pscustomobject]$result }

    $script:HHFlaggedCaptured[$key] = $rec
    $script:HHFlaggedBytes += [long]$rec.size
    $script:HHFlaggedCount++
    $result.captured = $true; $result.file = $rec.file; $result.sha256 = $rec.sha256
    return [pscustomobject]$result
}

function Get-HHEvidenceFiles { return $script:HHEvidenceFiles.ToArray() }
