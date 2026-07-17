# EvidenceWriter.ps1 - seal collected evidence into a hashed, verifiable bundle.
# Writes each artifact type to its own file (individually hashed), builds the manifest,
# computes a deterministic bundle hash over the artifact hashes, and records the seal in
# the custody ledger. Test-EvidenceBundle re-verifies the whole thing; Protect/Unprotect
# provide optional AES-256 transport encryption (carried over from Live-Forensicator).

function Seal-EvidenceBundle {
    <#
    .SYNOPSIS
        Persist all collected records and produce manifest.json (the sealed bundle head).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$Collected,        # ordered dict: artifact_type -> record[]
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$TimeIntegrity,
        $AuthDecision,
        $RunStats
    )

    $artifactsDir = Join-Path $OutputPath 'artifacts'
    if (-not (Test-Path -LiteralPath $artifactsDir)) {
        New-Item -ItemType Directory -Path $artifactsDir -Force | Out-Null
    }

    $artifactEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($type in $Collected.Keys) {
        $entry = Write-EvidenceArtifact -ArtifactsDir $artifactsDir -ArtifactType $type -Records @($Collected[$type])
        $artifactEntries.Add($entry)
        Add-CocEvent -EventType 'artifact_written' -Details @{
            artifact_type = $type; file = $entry.file; records = $entry.records; sha256 = $entry.sha256
        }
    }

    if ($RunStats) { $RunStats.FinishedUtc = [DateTime]::UtcNow }

    $manifest = [ordered]@{
        bundle_id       = [guid]::NewGuid().ToString()
        tool            = $Context.ToolName
        tool_version    = $Context.ToolVersion
        schema_version  = $Context.SchemaVersion
        design_ref      = 'CGD-CA-DESIGN-001'
        created_utc     = [DateTime]::UtcNow.ToString('o')
        engagement      = [ordered]@{
            engagement_id           = $Context.Engagement['engagement_id']
            client                  = $Context.Engagement['client']
            authorization_reference = $Context.Engagement['authorization_reference']
        }
        collection_mode = $Context.CollectionMode
        authorized      = if ($AuthDecision) { [bool]$AuthDecision.Authorized } else { $null }
        authorization   = if ($AuthDecision) {
            [ordered]@{
                operator     = $AuthDecision.Operator
                decision_utc = $AuthDecision.DecisionUtc
                checks       = $AuthDecision.Checks
                reasons      = $AuthDecision.Reasons
            }
        } else { $null }
        host            = $Context.Host
        time_integrity  = $TimeIntegrity
        run_stats       = $RunStats
        artifacts       = $artifactEntries.ToArray()
        coc_ledger      = 'coc.jsonl'
        log_file        = 'haaris-hunter.log'
    }

    # Deterministic bundle hash: sort artifact entries by file, hash "file:sha256" lines.
    # NB: use a scriptblock sort key - Sort-Object -Property 'file' does NOT sort ordered
    # dictionaries (it can't see hashtable keys as properties), which would desync this from
    # Test-EvidenceBundle's recompute over the JSON-read objects.
    $concat = ($artifactEntries | Sort-Object { $_.file } | ForEach-Object { "$($_.file):$($_.sha256)" }) -join "`n"
    $manifest['bundle_sha256'] = 'sha256:' + (Get-HHStringHash -InputString $concat)

    $manifestPath = Join-Path $OutputPath 'manifest.json'
    $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding utf8

    Add-CocEvent -EventType 'bundle_sealed' -Details @{
        bundle_sha256   = $manifest['bundle_sha256']
        manifest_sha256 = (Get-HHFileHash -Path $manifestPath)
        artifact_count  = $artifactEntries.Count
    }

    return $manifest
}

function Test-EvidenceBundle {
    <#
    .SYNOPSIS
        Re-verify a sealed bundle: every artifact file must match its manifest hash, the
        bundle hash must recompute, and the custody ledger chain must be intact.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$BundlePath)

    $problems = [System.Collections.Generic.List[string]]::new()
    $manifestPath = Join-Path $BundlePath 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        return [pscustomobject]@{ Valid = $false; Problems = @("manifest.json not found in $BundlePath") }
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding utf8 | ConvertFrom-Json

    foreach ($a in $manifest.artifacts) {
        $file = Join-Path $BundlePath ($a.file -replace '/', [IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $file)) {
            $problems.Add("missing artifact file: $($a.file)")
            continue
        }
        $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $a.sha256) {
            $problems.Add("hash mismatch (tampering) in $($a.file): manifest=$($a.sha256) actual=$actual")
        }
    }

    $concat   = ($manifest.artifacts | Sort-Object { $_.file } | ForEach-Object { "$($_.file):$($_.sha256)" }) -join "`n"
    $expected = 'sha256:' + (Get-HHStringHash -InputString $concat)
    if ($expected -ne $manifest.bundle_sha256) {
        $problems.Add("bundle_sha256 mismatch: manifest=$($manifest.bundle_sha256) recomputed=$expected")
    }

    $cocPath = Join-Path $BundlePath 'coc.jsonl'
    $cocResult = $null
    if (Test-Path -LiteralPath $cocPath) {
        $cocResult = Test-ChainOfCustody -Path $cocPath
        if (-not $cocResult.Valid) {
            foreach ($p in $cocResult.Problems) { $problems.Add("coc: $p") }
        }
    }

    [pscustomobject]@{
        Valid       = ($problems.Count -eq 0)
        BundleId    = $manifest.bundle_id
        Artifacts   = @($manifest.artifacts).Count
        CocValid    = if ($cocResult) { $cocResult.Valid } else { $null }
        Problems    = $problems.ToArray()
    }
}

# --- Optional AES-256 transport encryption ---------------------------------------

function ConvertFrom-HHSecureString {
    param([Parameter(Mandatory)][securestring]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try   { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function New-HHRandomBytes {
    param([Parameter(Mandatory)][int]$Count)
    $bytes = [byte[]]::new($Count)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return $bytes
}

function Protect-EvidenceBundle {
    <#
    .SYNOPSIS
        Zip a sealed bundle and AES-256-CBC encrypt it for transport. The passphrase is
        never written to disk or logged; the key is PBKDF2-derived (SHA-256, 200k iters).
        File layout: magic 'HHENC1' | int32 iterations | salt[16] | iv[16] | ciphertext.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BundlePath,
        [string]$OutFile,
        [securestring]$Passphrase
    )
    if (-not $Passphrase) { $Passphrase = Read-Host -AsSecureString -Prompt 'Encryption passphrase' }
    if (-not $OutFile)    { $OutFile = (Resolve-Path -LiteralPath $BundlePath).Path.TrimEnd('\','/') + '.hhbundle.aes' }

    $iterations = 200000
    $zip = [IO.Path]::Combine([IO.Path]::GetTempPath(), ("hh_" + [guid]::NewGuid().ToString('N') + '.zip'))
    try {
        Compress-Archive -Path (Join-Path $BundlePath '*') -DestinationPath $zip -Force
        $plain = [IO.File]::ReadAllBytes($zip)

        $salt = New-HHRandomBytes -Count 16
        $passBytes = [Text.Encoding]::UTF8.GetBytes((ConvertFrom-HHSecureString -Secure $Passphrase))
        $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new($passBytes, $salt, $iterations, [Security.Cryptography.HashAlgorithmName]::SHA256)
        try { $key = $kdf.GetBytes(32) } finally { $kdf.Dispose() }

        $aes = [Security.Cryptography.Aes]::Create()
        try {
            $aes.KeySize = 256; $aes.Key = $key; $aes.GenerateIV()
            $enc    = $aes.CreateEncryptor()
            $cipher = $enc.TransformFinalBlock($plain, 0, $plain.Length)

            $fs = [IO.File]::Create($OutFile)
            try {
                $fs.Write([Text.Encoding]::ASCII.GetBytes('HHENC1'), 0, 6)
                $fs.Write([BitConverter]::GetBytes([int]$iterations), 0, 4)
                $fs.Write($salt, 0, $salt.Length)
                $fs.Write($aes.IV, 0, $aes.IV.Length)
                $fs.Write($cipher, 0, $cipher.Length)
            } finally { $fs.Dispose() }
        } finally { $aes.Dispose() }

        Write-HHLog -Level Info -Message "Encrypted bundle written: $OutFile"
        return $OutFile
    }
    finally {
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    }
}

function Unprotect-EvidenceBundle {
    <#
    .SYNOPSIS
        Decrypt a .hhbundle.aes file back to a zip (and optionally expand it).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$OutZip,
        [switch]$Expand,
        [securestring]$Passphrase
    )
    if (-not $Passphrase) { $Passphrase = Read-Host -AsSecureString -Prompt 'Decryption passphrase' }
    if (-not $OutZip)     { $OutZip = [IO.Path]::ChangeExtension($Path, '.decrypted.zip') }

    $bytes = [IO.File]::ReadAllBytes($Path)
    $magic = [Text.Encoding]::ASCII.GetString($bytes, 0, 6)
    if ($magic -ne 'HHENC1') { throw "Not an HAARIS-HUNTER encrypted bundle (bad magic: $magic)." }

    $iterations = [BitConverter]::ToInt32($bytes, 6)
    $salt   = $bytes[10..25]
    $iv     = $bytes[26..41]
    $cipher = $bytes[42..($bytes.Length - 1)]

    $passBytes = [Text.Encoding]::UTF8.GetBytes((ConvertFrom-HHSecureString -Secure $Passphrase))
    $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new($passBytes, [byte[]]$salt, $iterations, [Security.Cryptography.HashAlgorithmName]::SHA256)
    try { $key = $kdf.GetBytes(32) } finally { $kdf.Dispose() }

    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256; $aes.Key = $key; $aes.IV = [byte[]]$iv
        $dec = $aes.CreateDecryptor()
        try {
            $plain = $dec.TransformFinalBlock([byte[]]$cipher, 0, $cipher.Length)
        } catch {
            throw 'Decryption failed - wrong passphrase or corrupted file.'
        }
        [IO.File]::WriteAllBytes($OutZip, $plain)
    } finally { $aes.Dispose() }

    if ($Expand) {
        $dest = [IO.Path]::ChangeExtension($OutZip, $null).TrimEnd('.')
        Expand-Archive -LiteralPath $OutZip -DestinationPath $dest -Force
        return $dest
    }
    return $OutZip
}
