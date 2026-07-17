# Collect-BrowserHistory.ps1 - browser history: raw DB capture + URL IOC surface.
# User content, so it runs ONLY in 'full' mode. For each history store this:
#   1. captures the raw DB into the evidence-file sink (hashed into the manifest) so precise
#      structured parsing (visit counts/timestamps) can be done offline, and
#   2. extracts the visited-URL IOC surface directly (dependency-free, via a shared read of
#      the live-locked file) so URLs are available for Phase 2 IOC matching immediately.
# ATT&CK: T1217 (browser information discovery).

function Collect-BrowserHistory {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    if ($Context.CollectionMode -ne 'full') {
        $records.Add((New-EvidenceRecord -ArtifactType 'browser_history_note' -Collector 'Collect-BrowserHistory' `
            -Source 'collection_mode' -Context $Context -Data @{
                collected = $false
                reason    = "collection_mode is '$($Context.CollectionMode)'; browser history is user content, collected only in 'full' mode."
            }))
        return $records.ToArray()
    }

    $userRoots = @()
    try { $userRoots = @(Get-ChildItem 'C:\Users' -Directory -ErrorAction Stop | Select-Object -ExpandProperty FullName) } catch { $userRoots = @($env:USERPROFILE) }

    $targets = @(
        @{ Browser = 'Chrome';  Rel = 'AppData\Local\Google\Chrome\User Data';   File = 'History' },
        @{ Browser = 'Edge';    Rel = 'AppData\Local\Microsoft\Edge\User Data';  File = 'History' },
        @{ Browser = 'Firefox'; Rel = 'AppData\Roaming\Mozilla\Firefox\Profiles'; File = 'places.sqlite' }
    )

    # Stop at whitespace, quotes, brackets, and any control byte (adjacent SQLite fields often
    # begin with a low serial-type byte). The domain prefix is always intact even when a title
    # is glued onto the path tail, so a parsed domain is emitted for reliable IOC matching.
    $urlRegex   = [regex]'https?://[^\s"''<>\\)\]\}\x00-\x1f]{4,2048}'
    $latin1     = [System.Text.Encoding]::GetEncoding('ISO-8859-1')
    $maxUrls    = 500   # per store, bounds bundle size

    foreach ($root in $userRoots) {
        $userName = Split-Path $root -Leaf
        foreach ($t in $targets) {
            $base = Join-Path $root $t.Rel
            if (-not (Test-Path -LiteralPath $base -ErrorAction SilentlyContinue)) { continue }
            try {
                Get-ChildItem -LiteralPath $base -Recurse -Filter $t.File -ErrorAction SilentlyContinue |
                    Select-Object -First 25 | ForEach-Object {
                        $dbPath = $_.FullName
                        $bytes  = Read-HHFileBytesShared -Path $dbPath

                        # 1. Capture the raw DB (hashed into manifest) for offline structured parsing.
                        $captured = $null
                        if ($bytes) {
                            $tmp = Join-Path ([IO.Path]::GetTempPath()) ("hh_hist_" + [guid]::NewGuid().ToString('N') + '.sqlite')
                            try {
                                [IO.File]::WriteAllBytes($tmp, $bytes)
                                $profile = Split-Path -Leaf (Split-Path -Parent $dbPath)
                                $safe = ($userName + '_' + $t.Browser + '_' + $profile + '_' + $_.Name) -replace '[^\w.\-]', '_'
                                $captured = Add-EvidenceFile -SourcePath $tmp -Category 'browser' -Name $safe
                            } catch { }
                            finally { if (Test-Path -LiteralPath $tmp -ErrorAction SilentlyContinue) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
                        }

                        # Store-level record (metadata + hash + capture reference).
                        $records.Add((New-EvidenceRecord -ArtifactType 'browser_history_store' -Collector 'Collect-BrowserHistory' `
                            -Source $t.Browser -Attack @('T1217') -Context $Context -Data @{
                                browser        = $t.Browser
                                user           = $userName
                                path           = $dbPath
                                size           = $_.Length
                                modified_utc   = $_.LastWriteTimeUtc.ToString('o')
                                captured_file  = if ($captured) { $captured.file } else { $null }
                                sha256         = if ($captured) { $captured.sha256 } else { (Get-HHFileEvidence -Path $dbPath).sha256 }
                            }))

                        # 2. Extract the visited-URL IOC surface (dependency-free string scan).
                        if ($bytes) {
                            $text = $latin1.GetString($bytes)
                            $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                            $count = 0
                            foreach ($m in $urlRegex.Matches($text)) {
                                if ($count -ge $maxUrls) { break }
                                $u = $m.Value.TrimEnd('.', ',', ')', ']', '}', ';')
                                if ($seen.Add($u)) {
                                    $count++
                                    $domain = $null
                                    try { $domain = ([uri]$u).Host } catch { }
                                    $records.Add((New-EvidenceRecord -ArtifactType 'browser_url' -Collector 'Collect-BrowserHistory' `
                                        -Source "$($t.Browser) history (extracted)" -Attack @('T1217') -Context $Context -Data @{
                                            browser = $t.Browser
                                            user    = $userName
                                            url     = $u
                                            domain  = $domain
                                            note    = 'URL/domain string-extracted from the history DB (IOC surface); the path tail may include adjacent title text - use the captured raw DB for exact records.'
                                        }))
                                }
                            }
                        }
                    }
            } catch { }
        }
    }

    if ($records.Count -eq 0) {
        $records.Add((New-EvidenceRecord -ArtifactType 'browser_history_note' -Collector 'Collect-BrowserHistory' `
            -Source 'browser history' -Context $Context -Data @{ collected = $true; stores_found = 0 }))
    }

    return $records.ToArray()
}
