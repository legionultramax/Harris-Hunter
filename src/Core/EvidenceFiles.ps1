# EvidenceFiles.ps1 - raw evidence file sink.
# Lets collectors contribute raw binary artifacts (e.g. exported .evtx) that are copied into
# the bundle, hashed, and folded into the manifest + bundle hash + custody ledger. Collectors
# still do not own hashing or the manifest; they only hand a source path to Add-EvidenceFile.

$script:HHEvidenceFileDir = $null
$script:HHEvidenceFiles    = [System.Collections.Generic.List[object]]::new()

function Initialize-EvidenceFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$SubDir = 'files'
    )
    $script:HHEvidenceFileDir = Join-Path $OutputPath $SubDir
    $script:HHEvidenceFiles    = [System.Collections.Generic.List[object]]::new()
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

function Get-HHEvidenceFiles { return $script:HHEvidenceFiles.ToArray() }
