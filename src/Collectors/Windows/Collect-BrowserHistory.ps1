# Collect-BrowserHistory.ps1 - browser history DB locations (metadata + hash).
# User content, so it runs ONLY in 'full' mode. Phase 1 records the history-store files and
# their hashes (chain-of-custody over the evidence); URL/visit parsing needs a SQLite reader
# and is a Phase 1.x enhancement (kept out to avoid a runtime dependency).

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

    # Enumerate all user profiles (best-effort; requires admin for other users).
    $userRoots = @()
    try { $userRoots = @(Get-ChildItem 'C:\Users' -Directory -ErrorAction Stop | Select-Object -ExpandProperty FullName) } catch { $userRoots = @($env:USERPROFILE) }

    $targets = @(
        @{ Browser = 'Chrome';  Rel = 'AppData\Local\Google\Chrome\User Data';   File = 'History' },
        @{ Browser = 'Edge';    Rel = 'AppData\Local\Microsoft\Edge\User Data';  File = 'History' },
        @{ Browser = 'Firefox'; Rel = 'AppData\Roaming\Mozilla\Firefox\Profiles'; File = 'places.sqlite' }
    )

    foreach ($root in $userRoots) {
        $userName = Split-Path $root -Leaf
        foreach ($t in $targets) {
            $base = Join-Path $root $t.Rel
            if (-not (Test-Path -LiteralPath $base -ErrorAction SilentlyContinue)) { continue }
            try {
                Get-ChildItem -LiteralPath $base -Recurse -Filter $t.File -ErrorAction SilentlyContinue |
                    Select-Object -First 25 | ForEach-Object {
                        $ev = Get-HHFileEvidence -Path $_.FullName
                        $records.Add((New-EvidenceRecord -ArtifactType 'browser_history_store' -Collector 'Collect-BrowserHistory' `
                            -Source $t.Browser -Attack @('T1217') -Context $Context -Data @{
                                browser      = $t.Browser
                                user         = $userName
                                path         = $_.FullName
                                size         = $_.Length
                                modified_utc = $_.LastWriteTimeUtc.ToString('o')
                                sha256       = $ev.sha256
                                note         = 'History store captured by reference (path+hash); parse URLs offline with a SQLite reader.'
                            }))
                    }
            } catch { }
        }
    }

    return $records.ToArray()
}
