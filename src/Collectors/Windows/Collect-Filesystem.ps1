# Collect-Filesystem.ps1 - execution/drop-site artifacts: Prefetch, common drop dirs, Amcache.
# ATT&CK: T1204 (user execution). Prefetch confirms what ran; drop dirs surface staged payloads.

function Collect-Filesystem {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    # --- Prefetch (evidence of execution) ---
    $pfDir = Join-Path $env:SystemRoot 'Prefetch'
    try {
        Get-ChildItem -LiteralPath $pfDir -Filter '*.pf' -ErrorAction Stop | ForEach-Object {
            $records.Add((New-EvidenceRecord -ArtifactType 'prefetch' -Collector 'Collect-Filesystem' `
                -Source $pfDir -Attack @('T1204') -Context $Context -Data @{
                    name         = $_.Name
                    size         = $_.Length
                    created_utc  = $_.CreationTimeUtc.ToString('o')
                    modified_utc = $_.LastWriteTimeUtc.ToString('o')
                    sha256       = (Get-HHFileEvidence -Path $_.FullName).sha256
                }))
        }
    } catch {
        $records.Add((New-EvidenceRecord -ArtifactType 'prefetch_note' -Collector 'Collect-Filesystem' `
            -Source $pfDir -Context $Context -Data @{ collected = $false; reason = "$($_.Exception.Message)" }))
    }

    # --- Executables staged in common drop directories (recent, capped) ---
    $dropDirs = @($env:TEMP, (Join-Path $env:LOCALAPPDATA 'Temp'), $env:ProgramData, (Join-Path $env:PUBLIC 'Downloads')) |
        Where-Object { $_ } | Select-Object -Unique
    $cutoff = (Get-Date).AddDays(-30)
    $cap = 250; $count = 0
    foreach ($dir in $dropDirs) {
        if ($count -ge $cap) { break }
        try {
            Get-ChildItem -LiteralPath $dir -Recurse -File -Include '*.exe','*.dll','*.ps1','*.bat','*.scr','*.vbs','*.js' -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $cutoff } |
                Select-Object -First ($cap - $count) | ForEach-Object {
                    $count++
                    $ev = Get-HHFileEvidence -Path $_.FullName
                    $records.Add((New-EvidenceRecord -ArtifactType 'dropped_file' -Collector 'Collect-Filesystem' `
                        -Source $dir -Attack @('T1204') -Context $Context -Data @{
                            path         = $_.FullName
                            size         = $_.Length
                            modified_utc = $_.LastWriteTimeUtc.ToString('o')
                            sha256       = $ev.sha256
                            signed       = $ev.signed
                            signer       = $ev.signer
                        }))
                }
        } catch { }
    }

    # --- Amcache (execution history) - locked live; record presence + hash for offline parse ---
    $amcache = Join-Path $env:SystemRoot 'AppCompat\Programs\Amcache.hve'
    try {
        if (Test-Path -LiteralPath $amcache -ErrorAction SilentlyContinue) {
            $fi = Get-Item -LiteralPath $amcache -ErrorAction Stop
            $records.Add((New-EvidenceRecord -ArtifactType 'amcache_pointer' -Collector 'Collect-Filesystem' `
                -Source $amcache -Context $Context -Data @{
                    path         = $amcache
                    size         = $fi.Length
                    modified_utc = $fi.LastWriteTimeUtc.ToString('o')
                    note         = 'Registry hive locked while live; parse offline (e.g. AmcacheParser) from a raw copy.'
                }))
        }
    } catch { }

    return $records.ToArray()
}
