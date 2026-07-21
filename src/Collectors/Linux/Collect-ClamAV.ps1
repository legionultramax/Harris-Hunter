# Collect-ClamAV.ps1 (Linux) - CM-10 anti-malware scan (blueprint section 9).
# Runs ClamAV over the bounded high-risk path set (section 9.3), NON-DESTRUCTIVELY (no --remove /
# --move, section 9.7 - detect and report only), under resource guards (nice/ionice/timeout +
# size/recursion limits, sections 9.5-9.6), and emits:
#   clamav_detection      one per FOUND line (path, signature, sha256, size, mtime)
#   clamav_scan_summary   engine + signature versions, staleness gate (9.2), counts, truncation
# The clamscan log is folded into the evidence bundle (section 9.7: scan logs are evidence).
# Collectors only collect: detections here are evidence records; the detection phase turns
# clamav_detection into malware.clamav_detection finding.v1 records.

function Collect-ClamAV {
    param($Context)
    $records = [System.Collections.Generic.List[object]]::new()

    if (-not (Test-HHCommand 'clamscan')) {
        $records.Add((New-EvidenceRecord -ArtifactType 'clamav_scan_summary' -Collector 'Collect-ClamAV' `
            -Source 'clamscan' -Attack @() -Context $Context -Data @{
                status = 'clamav_not_installed'
                note   = 'ClamAV (clamscan) not found on host; anti-malware scan skipped.'
            }))
        return $records.ToArray()
    }

    # --- Signature staleness gate (9.2) -----------------------------------------------------
    # freshclam is expected to run as a service / scheduled task; we do not force a network update
    # inside a forensic collection. We READ the installed DB age and flag it - stale signatures
    # materially reduce detection confidence and analysts must know.
    $sigMaxAgeDays = 7
    $sigVersion = $null; $sigAgeDays = $null; $sigStale = $null; $sigBuildUtc = $null
    if (Test-HHCommand 'sigtool') {
        try {
            $dailyDb = @('/var/lib/clamav/daily.cld','/var/lib/clamav/daily.cvd') |
                Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
            if ($dailyDb) {
                $info = & sigtool --info $dailyDb 2>$null
                foreach ($l in $info) {
                    if ($l -match '^\s*Version:\s*(.+)$')    { $sigVersion  = $Matches[1].Trim() }
                    if ($l -match '^\s*Build time:\s*(.+)$')  { $sigBuildUtc = $Matches[1].Trim() }
                }
                if ($sigBuildUtc) {
                    $built = [datetime]::MinValue
                    if ([datetime]::TryParse($sigBuildUtc, [System.Globalization.CultureInfo]::InvariantCulture,
                            [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$built)) {
                        $sigAgeDays = [int][math]::Floor(([datetime]::UtcNow - $built).TotalDays)
                        $sigStale   = ($sigAgeDays -gt $sigMaxAgeDays)
                    }
                }
            }
        } catch { }
    }

    # --- Targets (9.3): the bounded high-risk set, only paths that exist ---------------------
    $candidateTargets = @(
        '/tmp','/var/tmp','/dev/shm','/home','/root','/opt','/usr/local/bin','/usr/local/sbin',
        '/var/www','/srv','/etc/cron.d','/etc/cron.hourly','/etc/cron.daily','/etc/cron.weekly',
        '/etc/cron.monthly','/etc/init.d','/etc/systemd/system','/var/spool/cron'
    )
    $targets = @($candidateTargets | Where-Object { Test-Path -LiteralPath $_ })
    if ($targets.Count -eq 0) {
        $records.Add((New-EvidenceRecord -ArtifactType 'clamav_scan_summary' -Collector 'Collect-ClamAV' `
            -Source 'clamscan' -Attack @() -Context $Context -Data @{
                status = 'no_targets'; note = 'None of the high-risk scan paths exist on this host.'
                signatures_stale = $sigStale; signature_version = $sigVersion
            }))
        return $records.ToArray()
    }

    # --- Exclusions (9.4): container overlays + pseudo-filesystems. We drop ^/dev/ because
    #     /dev/shm is an explicit target (a classic payload-staging dir).
    $excludeDirs = @(
        '^/proc/','^/sys/','^/run/','^/var/run/','^/snap/','^/boot/efi/',
        '^/var/lib/docker/overlay2/','^/var/lib/containers/storage/overlay/',
        '^/var/lib/containerd/','^/var/lib/kubelet/pods/'
    )

    # --- Build the clamscan invocation (limits 9.6; non-destructive 9.7) --------------------
    $scanTimeout = 7200   # seconds; configurable per profile in a later increment
    $log = Join-Path ([IO.Path]::GetTempPath()) ("hh_clamscan_" + [guid]::NewGuid().ToString('N') + '.log')

    $clamArgs = [System.Collections.Generic.List[string]]::new()
    $clamArgs.AddRange([string[]]@(
        '--recursive','--infected','--no-summary','--cross-fs=no',
        '--max-filesize=100M','--max-scansize=400M','--max-recursion=16','--max-files=10000',
        '--alert-exceeds-max=yes','--database=/var/lib/clamav',"--log=$log"
    ))
    # Custom signature pack (9.8), if the CTI-distributed dir is present.
    if (Test-Path -LiteralPath '/var/lib/clamav-custom') { $clamArgs.Add('--database=/var/lib/clamav-custom') }
    foreach ($ex in $excludeDirs) { $clamArgs.Add("--exclude-dir=$ex") }
    foreach ($t in $targets)      { $clamArgs.Add($t) }

    # Resource guards (9.5): idle CPU/IO priority + hard wall-clock timeout, each applied only if
    # the tool exists (minimal systems may lack them).
    $prefix = [System.Collections.Generic.List[string]]::new()
    if (Test-HHCommand 'nice')   { $prefix.AddRange([string[]]@('nice','-n','19')) }
    if (Test-HHCommand 'ionice') { $prefix.AddRange([string[]]@('ionice','-c','3')) }
    if (Test-HHCommand 'timeout'){ $prefix.AddRange([string[]]@('timeout','--kill-after=60',"$scanTimeout")) }

    $scanRc = $null; $durationMs = $null; $scanTruncated = $false
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if ($prefix.Count -gt 0) {
            $exe = $prefix[0]; $rest = @($prefix[1..($prefix.Count-1)]) + 'clamscan' + $clamArgs.ToArray()
            & $exe @rest 2>$null | Out-Null
        } else {
            & clamscan @($clamArgs.ToArray()) 2>$null | Out-Null
        }
        $scanRc = $LASTEXITCODE
    } catch { $scanRc = -1 }
    $sw.Stop(); $durationMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 0)
    # clamscan RC: 0=clean, 1=detections, 2=errors. timeout kills with 124.
    if ($scanRc -eq 124) { $scanTruncated = $true }

    # --- Parse the log: FOUND -> detection record; ERROR -> counted ------------------------
    $infected = 0; $scanErrors = 0
    if (Test-Path -LiteralPath $log) {
        foreach ($line in (Get-Content -LiteralPath $log -ErrorAction SilentlyContinue)) {
            $t = if ($line) { $line.Trim() } else { '' }
            if (-not $t) { continue }
            $m = [regex]::Match($t, '^(?<path>.+?): (?<sig>.+) FOUND$')
            if ($m.Success) {
                $infected++
                $p  = $m.Groups['path'].Value
                $ev = Get-HHLinuxFileEvidence -Path $p
                $records.Add((New-EvidenceRecord -ArtifactType 'clamav_detection' -Collector 'Collect-ClamAV' `
                    -Source 'clamscan' -Attack @() -Context $Context -Data @{
                        file_path = $p
                        signature = $m.Groups['sig'].Value.Trim()
                        sha256    = $ev.sha256
                        size      = $ev.size
                        mtime_utc = $ev.mtime_utc
                        owner     = $ev.owner
                        mode      = $ev.mode
                        signature_version = $sigVersion
                    }))
                continue
            }
            if ($t -match ' ERROR$') { $scanErrors++ }
        }
    }

    # --- Fold the scan log into the bundle as evidence (9.7) -------------------------------
    $logEvidence = $null
    if ((Get-Command -Name Add-EvidenceFile -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $log) -and ((Get-Item -LiteralPath $log).Length -gt 0)) {
        try { $logEvidence = Add-EvidenceFile -SourcePath $log -Category 'clamav' -Name 'clamscan.log' } catch { }
    }
    Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue

    $engineVersion = $null
    try { $engineVersion = ((& clamscan --version 2>$null) | Select-Object -First 1) } catch { }

    $records.Add((New-EvidenceRecord -ArtifactType 'clamav_scan_summary' -Collector 'Collect-ClamAV' `
        -Source 'clamscan' -Attack @() -Context $Context -Data @{
            status            = 'completed'
            engine_version    = $engineVersion
            signature_version = $sigVersion
            signature_age_days= $sigAgeDays
            signatures_stale  = $sigStale
            targets           = $targets
            infected_count    = $infected
            error_count       = $scanErrors
            scan_truncated    = $scanTruncated
            scan_rc           = $scanRc
            duration_ms       = $durationMs
            log_evidence      = if ($logEvidence) { $logEvidence.file } else { $null }
            log_sha256        = if ($logEvidence) { $logEvidence.sha256 } else { $null }
        }))

    return $records.ToArray()
}
