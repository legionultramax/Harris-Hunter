# Write-JsonBundle.ps1 - the primary, ingestion-ready JSON output.
# Per-artifact files are the canonical, individually-hashed evidence. A consolidated
# bundle.json is written as a convenience for downstream single-file ingestion.

$script:HHJsonDepth = 12

function ConvertTo-HHJson {
    <#
    .SYNOPSIS
        Serialize with consistent depth so nested evidence data is never truncated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$InputObject,
        [int]$Depth = $script:HHJsonDepth,
        [switch]$Compress
    )
    process {
        $InputObject | ConvertTo-Json -Depth $Depth -Compress:$Compress
    }
}

function Write-EvidenceArtifact {
    <#
    .SYNOPSIS
        Write one artifact type's records to artifacts/<type>.json and return its
        manifest entry (relative path, record count, SHA-256).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ArtifactsDir,
        [Parameter(Mandatory)][string]$ArtifactType,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Records
    )
    $fileName = ("{0}.json" -f $ArtifactType.ToLower())
    $fullPath = Join-Path $ArtifactsDir $fileName

    # Always emit a JSON array, even for zero or one record, so parsing is uniform.
    if ($Records.Count -eq 0) {
        $json = '[]'
    }
    elseif ($Records.Count -eq 1) {
        $json = '[' + ($Records[0] | ConvertTo-Json -Depth $script:HHJsonDepth) + ']'
    }
    else {
        $json = $Records | ConvertTo-Json -Depth $script:HHJsonDepth
    }
    Set-Content -LiteralPath $fullPath -Value $json -Encoding utf8

    [ordered]@{
        file          = "artifacts/$fileName"
        artifact_type = $ArtifactType
        records       = @($Records).Count
        sha256        = (Get-HHFileHash -Path $fullPath)
    }
}

function Export-ConsolidatedBundle {
    <#
    .SYNOPSIS
        Convenience single-file view: the manifest plus all records inline. Not part of
        the manifest hash set (the per-artifact files are the canonical evidence).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)]$Collected,
        [string]$FileName = 'bundle.json'
    )
    $bundle = [ordered]@{
        manifest = $Manifest
        records  = $Collected
    }
    $target = Join-Path $OutputPath $FileName
    $bundle | ConvertTo-Json -Depth ($script:HHJsonDepth + 3) | Set-Content -LiteralPath $target -Encoding utf8
    return $target
}
