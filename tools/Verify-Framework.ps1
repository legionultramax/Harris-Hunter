<#
.SYNOPSIS
    Dependency-free verification of the HAARIS-HUNTER Phase 1 Core Framework.
    Runs on Windows PowerShell 5.1 and PowerShell 7+. Exits 0 on success, 1 on failure.
    Proves: module import, evidence schema, hashing, authorization gate (all paths),
    end-to-end seal + report, bundle re-verification, tamper detection, custody-chain
    tamper detection, and the AES encrypt/decrypt round-trip.

    Uses two lightweight in-memory collectors (Zeta, Alpha) whose include order differs
    from their alphabetical file order, so the bundle-hash ordering guarantee is regression
    tested without pulling in the slow host collectors. All real Windows collectors are
    excluded from these runs so verification stays fast.
#>
[CmdletBinding()]
param(
    [string]$ModuleRoot
)

$ErrorActionPreference = 'Stop'
$script:Pass = 0
$script:Fail = 0

if (-not $ModuleRoot) {
    $here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $ModuleRoot = Split-Path -Parent $here
}

# Every real collector (Windows + Linux) - excluded so the framework runs stay fast and
# deterministic on whichever OS the verifier runs on.
$script:RealCollectors = @(
    # Windows
    'System','Process','Network','Autoruns','Services','ScheduledTasks','WmiPersistence',
    'Accounts','AuthEvents','EventLogs','Filesystem','DefenderState','BitsJobs','MemoryHints',
    'Wireless','BrowserHistory',
    # Linux
    'SystemdUnits','Cron','InitScripts','SshKeys','Sudoers','AuthLogs','SystemLogs','ShellHistory',
    'SuidSgid','KernelModules','PackageIntegrity','Containers'
)

function Assert-That {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { Write-Host ("  [PASS] " + $Name) -ForegroundColor Green; $script:Pass++ }
    else { Write-Host ("  [FAIL] " + $Name + $(if ($Detail) { " -> $Detail" } else { '' })) -ForegroundColor Red; $script:Fail++ }
}

function New-TempDir {
    $p = Join-Path ([IO.Path]::GetTempPath()) ("hhverify_" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $p -Force | Out-Null
    return $p
}

function New-EngagementFile {
    param([string]$Path, [string[]]$Operators = @('*'), [string[]]$Hostnames = @('*'),
          [string]$From = '2026-01-01T00:00:00Z', [string]$To = '2026-12-31T23:59:59Z')
    @{
        engagement_id = 'CGD-ENG-VERIFY'; client = 'Self Test'; authorization_reference = 'VERIFY-1'
        authorized_operators = $Operators
        authorized_scope = @{ hostnames = $Hostnames; ips = @(); asset_tags = @() }
        valid_from = $From; valid_to = $To; collection_mode = 'full'
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding utf8
}

function Invoke-VerifyRun {
    # Include Zeta then Alpha (insertion order zeta,alpha != alphabetical alpha,zeta) so the
    # bundle-hash sort is genuinely exercised. Exclude every real collector for speed.
    param([string]$OutputPath)
    Invoke-HaarisHunter -EngagementFile $script:eng -Profile quick -Include 'Zeta','Alpha' `
        -Exclude $script:RealCollectors -OutputPath $OutputPath -LogLevel Error
}

Write-Host "HAARIS-HUNTER framework verification" -ForegroundColor Cyan
Write-Host ("PowerShell $($PSVersionTable.PSVersion)  |  module: $ModuleRoot") -ForegroundColor DarkGray

# --- Import ---
Write-Host "`n[1] Module import" -ForegroundColor Cyan
Import-Module (Join-Path $ModuleRoot 'HaarisHunter.psd1') -Force
$expected = 'Invoke-HaarisHunter','Assert-Authorization','New-EvidenceRecord','Test-EvidenceRecord',
            'Seal-EvidenceBundle','Test-EvidenceBundle','Test-ChainOfCustody','Protect-EvidenceBundle',
            'Unprotect-EvidenceBundle','Get-HHStringHash','Write-HtmlReport',
            'Add-FlaggedFile','Set-HHCapturePolicy','Test-HHCaptureEligible'
foreach ($fn in $expected) { Assert-That "exports $fn" ([bool](Get-Command $fn -ErrorAction SilentlyContinue)) }

# --- Hash engine ---
Write-Host "`n[2] Hash engine" -ForegroundColor Cyan
$abc = Get-HHStringHash -InputString 'abc'
Assert-That "SHA-256('abc') known vector" ($abc -eq 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') $abc

# --- Evidence schema ---
Write-Host "`n[3] Evidence schema" -ForegroundColor Cyan
$ctx = [pscustomobject]@{ Host = @{ hostname = 'H' }; EngagementId = 'E1' }
$rec = New-EvidenceRecord -ArtifactType 'test' -Collector 'C' -Data @{ a = 1 } -Attack @('T1059') -Context $ctx
Assert-That "New-EvidenceRecord valid" (Test-EvidenceRecord -Record $rec)
Assert-That "record carries engagement_id" ($rec.engagement_id -eq 'E1')
Assert-That "empty attack still yields an array" ((New-EvidenceRecord -ArtifactType 't' -Collector 'C' -Data @{} -Attack @() -Context $ctx)['attack'] -is [System.Collections.IEnumerable])
Assert-That "malformed record rejected" (-not (Test-EvidenceRecord -Record @{ foo = 'bar' }))

# --- Authorization gate ---
Write-Host "`n[4] Authorization gate" -ForegroundColor Cyan
$hostMeta = @{ hostname = 'WKS-1'; fqdn = 'wks-1.corp'; ips = @('10.0.0.5') }
$engOk = @{ engagement_id='E'; authorized_operators=@('*'); authorized_scope=@{hostnames=@('*');ips=@()}; valid_from='2026-01-01T00:00:00Z'; valid_to='2026-12-31T23:59:59Z' }
Assert-That "in-scope + operator + window PASSES" ((Assert-Authorization -Engagement $engOk -HostMeta $hostMeta).Authorized)
$engBadHost = @{ engagement_id='E'; authorized_operators=@('*'); authorized_scope=@{hostnames=@('OTHER-*');ips=@()}; valid_from='2026-01-01T00:00:00Z'; valid_to='2026-12-31T23:59:59Z' }
Assert-That "out-of-scope host FAILS" (-not (Assert-Authorization -Engagement $engBadHost -HostMeta $hostMeta).Authorized)
$engExpired = @{ engagement_id='E'; authorized_operators=@('*'); authorized_scope=@{hostnames=@('*');ips=@()}; valid_from='2020-01-01T00:00:00Z'; valid_to='2020-02-01T00:00:00Z' }
Assert-That "expired window FAILS" (-not (Assert-Authorization -Engagement $engExpired -HostMeta $hostMeta).Authorized)
$engBadOp = @{ engagement_id='E'; authorized_operators=@('nobody@nowhere'); authorized_scope=@{hostnames=@('*');ips=@()}; valid_from='2026-01-01T00:00:00Z'; valid_to='2026-12-31T23:59:59Z' }
Assert-That "wrong operator FAILS" (-not (Assert-Authorization -Engagement $engBadOp -HostMeta $hostMeta -OperatorIdentities @('someone-else')).Authorized)
Assert-That "IP-scope match PASSES" ((Assert-Authorization -Engagement @{ engagement_id='E'; authorized_operators=@('*'); authorized_scope=@{hostnames=@();ips=@('10.0.0.*')}; valid_from='2026-01-01T00:00:00Z'; valid_to='2026-12-31T23:59:59Z' } -HostMeta $hostMeta).Authorized)

# --- Two in-memory collectors: include order (Zeta,Alpha) != file order (alpha,zeta) ---
function global:Collect-Zeta  { param($Context) New-EvidenceRecord -ArtifactType 'zeta'  -Collector 'Collect-Zeta'  -Attack @('T1059') -Data @{ v = 1 } -Context $Context }
function global:Collect-Alpha {
    param($Context)
    # Contribute TWO raw files with the SAME requested name to exercise the sink's collision
    # de-duplication (distinct sources must not overwrite each other or false-flag tampering).
    foreach ($v in 'evidence-bytes-1', 'evidence-bytes-2') {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("hh_ev_" + [guid]::NewGuid().ToString('N') + '.bin')
        Set-Content -LiteralPath $tmp -Value $v -Encoding utf8
        $null = Add-EvidenceFile -SourcePath $tmp -Category 'test' -Name 'sample.bin'
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    New-EvidenceRecord -ArtifactType 'alpha' -Collector 'Collect-Alpha' -Attack @() -Data @{ v = 2 } -Context $Context
}

$script:eng = Join-Path ([IO.Path]::GetTempPath()) 'hh_verify_eng.json'
New-EngagementFile -Path $script:eng

# --- End-to-end (authorized), multi-artifact ---
Write-Host "`n[5] End-to-end seal + verify" -ForegroundColor Cyan
$out = New-TempDir
$run = Invoke-VerifyRun -OutputPath $out
Assert-That "run authorized" ($run.Authorized -eq $true)
foreach ($f in 'manifest.json','coc.jsonl','bundle.json','report.html','haaris-hunter.log') {
    Assert-That "output has $f" (Test-Path (Join-Path $out $f))
}
Assert-That "both artifacts written" ((Test-Path (Join-Path $out 'artifacts/alpha.json')) -and (Test-Path (Join-Path $out 'artifacts/zeta.json')))
Assert-That "raw evidence files captured into bundle" (Test-Path (Join-Path $out 'files/test/sample.bin'))
$man5 = Get-Content (Join-Path $out 'manifest.json') -Raw | ConvertFrom-Json
Assert-That "same-named evidence files de-collide (2 distinct)" (@($man5.evidence_files).Count -ge 2 -and (@($man5.evidence_files.sha256 | Sort-Object -Unique).Count -eq @($man5.evidence_files).Count))
$verify = Test-EvidenceBundle -BundlePath $out
Assert-That "sealed bundle re-verifies (artifacts + evidence files)" ($verify.Valid) ($verify.Problems -join '; ')
Assert-That "custody chain intact" ($verify.CocValid -eq $true)

# --- Tamper detection ---
Write-Host "`n[6] Tamper detection" -ForegroundColor Cyan
Add-Content -LiteralPath (Join-Path $out 'artifacts/alpha.json') -Value ' '
Assert-That "artifact tampering detected" (-not (Test-EvidenceBundle -BundlePath $out).Valid)

$outE = New-TempDir
Invoke-VerifyRun -OutputPath $outE | Out-Null
Add-Content -LiteralPath (Join-Path $outE 'files/test/sample.bin') -Value 'x'
Assert-That "evidence-file tampering detected" (-not (Test-EvidenceBundle -BundlePath $outE).Valid)

# manifest.json edited but kept internally self-consistent (still parses); caught only by the
# custody-ledger anchor (ledger records the original manifest hash).
$outM = New-TempDir
Invoke-VerifyRun -OutputPath $outM | Out-Null
Add-Content -LiteralPath (Join-Path $outM 'manifest.json') -Value ' '
Assert-That "manifest tamper caught via custody-ledger anchor" (-not (Test-EvidenceBundle -BundlePath $outM).Valid)

$out2 = New-TempDir
Invoke-VerifyRun -OutputPath $out2 | Out-Null
$coc = Join-Path $out2 'coc.jsonl'
$lines = Get-Content -LiteralPath $coc
$lines[1] = $lines[1] -replace '"event":"[^"]+"', '"event":"forged"'
Set-Content -LiteralPath $coc -Value $lines -Encoding utf8
Assert-That "custody-ledger tampering detected" (-not (Test-ChainOfCustody -Path $coc).Valid)

# --- AES round-trip ---
Write-Host "`n[7] AES transport encryption" -ForegroundColor Cyan
$out3 = New-TempDir
Invoke-VerifyRun -OutputPath $out3 | Out-Null
$securePass = ConvertTo-SecureString 'Verify-Passphrase-123!' -AsPlainText -Force
$enc  = Protect-EvidenceBundle -BundlePath $out3 -Passphrase $securePass
Assert-That "encrypted bundle created" (Test-Path $enc)
$zip  = Unprotect-EvidenceBundle -Path $enc -Passphrase $securePass -OutZip (Join-Path ([IO.Path]::GetTempPath()) 'hh_ok.zip')
Assert-That "decrypt with correct passphrase" (Test-Path $zip)
$wrongOk = $true
try { Unprotect-EvidenceBundle -Path $enc -Passphrase (ConvertTo-SecureString 'wrong' -AsPlainText -Force) -OutZip (Join-Path ([IO.Path]::GetTempPath()) 'hh_bad.zip') | Out-Null }
catch { $wrongOk = $false }
Assert-That "wrong passphrase rejected" (-not $wrongOk)

# --- Detection engine (Phase 2: normalize -> Sigma -> finding -> risk) ---
Write-Host "`n[8] Detection engine" -ForegroundColor Cyan
& (Join-Path $ModuleRoot 'tools/Convert-SigmaPack.ps1') -Quiet | Out-Null
$detRules = Import-HHCompiledRules -Path (Join-Path $ModuleRoot 'config/detection/rules/compiled')
Assert-That "compiled Sigma rules load" ($detRules.Count -ge 1) "loaded=$($detRules.Count)"

# A benign, ordinary user-writable autostart created in-window must fire the registry_run rule.
$detHost = @{ hostname = 'VERIFY'; os = 'windows'; host_id = 'verify-1' }
$detRec = [ordered]@{
    schema_version='1.0'; artifact_type='autorun_run_key'; collector='Collect-Verify'
    collected_at_utc='2026-07-18T00:00:00Z'; host=$detHost; engagement_id='CGD-VERIFY'
    source='HKCU..Run'; attack=@('T1547.001')
    data=@{ location='HKCU\..\Run'; name='Updater'; command='C:\Users\Public\updater.exe'; created='2026-07-15T00:00:00Z' }
}
$detEvents = @(ConvertTo-HHNormalizedEvents -Records @($detRec))
Assert-That "record normalizes to a persistence event" ($detEvents.Count -eq 1 -and $detEvents[0].category -eq 'persistence_inventory')

$detFindings = @(Invoke-SigmaRules -Events $detEvents -Rules $detRules -ScanWindowStart ([datetime]'2026-07-01T00:00:00Z') -ScanWindowEnd ([datetime]'2026-07-18T00:00:00Z') -FindingArgs @{})
Assert-That "Sigma fires on user-writable autostart" ($detFindings.Count -eq 1 -and $detFindings[0]['finding_type'] -eq 'persistence.registry_run')
Assert-That "finding validates against finding.v1" ($detFindings.Count -ge 1 -and (Test-Finding -Finding $detFindings[0]))

# Recency filter: same record with an out-of-window created date must NOT fire.
$detRecOld = [ordered]@{
    schema_version='1.0'; artifact_type='autorun_run_key'; collector='Collect-Verify'
    collected_at_utc='2026-07-18T00:00:00Z'; host=$detHost; engagement_id='CGD-VERIFY'
    source='HKCU..Run'; attack=@('T1547.001')
    data=@{ location='HKCU\..\Run'; name='Old'; command='C:\Users\Public\old.exe'; created='2026-01-01T00:00:00Z' }
}
$detOld = @(Invoke-SigmaRules -Events @(ConvertTo-HHNormalizedEvents -Records @($detRecOld)) -Rules $detRules -ScanWindowStart ([datetime]'2026-07-01T00:00:00Z') -FindingArgs @{})
Assert-That "recency/timeframe filter excludes pre-window autostart" ($detOld.Count -eq 0) "count=$($detOld.Count)"

# Risk math (blueprint section 28.6): high(70) x medium(0.7) = 49; +10 crown_jewel => 59.
$rf = [ordered]@{ severity='high'; confidence='medium'; observed_at='2026-07-15T00:00:00Z'; host=@{ asset_criticality='crown_jewel' }; detection=@{ engine='sigma'; mitre_attack=@() }; risk_score=$null }
Get-HHRiskScore -Finding $rf | Out-Null
Assert-That "finding risk math (70*0.7 + 10 crown_jewel = 59)" ($rf['risk_score'] -eq 59) "got=$($rf['risk_score'])"

# --- Flagged-file capture (section 10.2: bounded high-risk set) ---
Write-Host "`n[9] Flagged-file capture (bounded)" -ForegroundColor Cyan

# Eligibility gate is pure (no sink/state): PE magic + script extension pass; plain text fails.
$tmpMZ  = Join-Path ([IO.Path]::GetTempPath()) ("hhcap_" + [guid]::NewGuid().ToString('N') + '.exe')
$mzBytes = New-Object byte[] 24; $mzBytes[0] = 0x4D; $mzBytes[1] = 0x5A
[IO.File]::WriteAllBytes($tmpMZ, $mzBytes)
$tmpTxt = Join-Path ([IO.Path]::GetTempPath()) ("hhcap_" + [guid]::NewGuid().ToString('N') + '.txt')
[IO.File]::WriteAllText($tmpTxt, 'this is not an executable')
$tmpPs1 = Join-Path ([IO.Path]::GetTempPath()) ("hhcap_" + [guid]::NewGuid().ToString('N') + '.ps1')
[IO.File]::WriteAllText($tmpPs1, 'Write-Output 1')
Assert-That "eligible: PE (MZ) magic" (Test-HHCaptureEligible -Path $tmpMZ)
Assert-That "eligible: script extension (.ps1)" (Test-HHCaptureEligible -Path $tmpPs1)
Assert-That "ineligible: plain .txt" (-not (Test-HHCaptureEligible -Path $tmpTxt))
foreach ($f in $tmpMZ,$tmpTxt,$tmpPs1) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }

# Full end-to-end capture with a tiny budget, exercised through a real (full-mode) run so the
# orchestrator wires the policy + mode. The collector sets a small budget then feeds Add-FlaggedFile.
function global:Collect-Capture {
    param($Context)
    Set-HHCapturePolicy -Policy @{ enabled=$true; max_file_bytes=64; max_total_bytes=100000; max_files=8; script_extensions=@('.ps1') } -CollectionMode 'full'
    $good = Join-Path ([IO.Path]::GetTempPath()) ("hhc_" + [guid]::NewGuid().ToString('N') + '.exe')
    $b = New-Object byte[] 32; $b[0] = 0x4D; $b[1] = 0x5A; [IO.File]::WriteAllBytes($good, $b)
    $txt  = Join-Path ([IO.Path]::GetTempPath()) ("hhc_" + [guid]::NewGuid().ToString('N') + '.txt')
    [IO.File]::WriteAllText($txt, 'nope')
    $big  = Join-Path ([IO.Path]::GetTempPath()) ("hhc_" + [guid]::NewGuid().ToString('N') + '.exe')
    $bb = New-Object byte[] 200; $bb[0] = 0x4D; $bb[1] = 0x5A; [IO.File]::WriteAllBytes($big, $bb)
    $global:HHCapResults = [ordered]@{
        good = Add-FlaggedFile -Path $good
        txt  = Add-FlaggedFile -Path $txt
        big  = Add-FlaggedFile -Path $big
        dup  = Add-FlaggedFile -Path $good
    }
    foreach ($f in $good,$txt,$big) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    New-EvidenceRecord -ArtifactType 'capture' -Collector 'Collect-Capture' -Attack @() -Data @{ ok = 1 } -Context $Context
}
$outC = New-TempDir
Invoke-HaarisHunter -EngagementFile $script:eng -Profile quick -Include 'Capture' `
    -Exclude $script:RealCollectors -OutputPath $outC -LogLevel Error | Out-Null
$cap = $global:HHCapResults
Assert-That "eligible PE captured" ($cap.good.captured -eq $true) "reason=$($cap.good.reason)"
Assert-That "ineligible .txt skipped" ($cap.txt.captured -eq $false -and $cap.txt.reason -eq 'ineligible_type') "reason=$($cap.txt.reason)"
Assert-That "over-cap file skipped (too_large)" ($cap.big.captured -eq $false -and $cap.big.reason -eq 'too_large') "reason=$($cap.big.reason)"
Assert-That "same path de-duplicated" ($cap.dup.captured -eq $true -and $cap.dup.deduped -eq $true)
Assert-That "captured file landed in bundle" (Test-Path (Join-Path $outC ($cap.good.file -replace '/', [IO.Path]::DirectorySeparatorChar)))
$manC = Get-Content (Join-Path $outC 'manifest.json') -Raw | ConvertFrom-Json
Assert-That "capture folded into manifest.evidence_files exactly once" (@($manC.evidence_files | Where-Object { $_.category -eq 'flagged' }).Count -eq 1)
Assert-That "captured bundle re-verifies" ((Test-EvidenceBundle -BundlePath $outC).Valid)

# Minimized mode must NOT capture (raw bytes are content; full-mode only).
$engMin = Join-Path ([IO.Path]::GetTempPath()) 'hh_verify_eng_min.json'
@{
    engagement_id='CGD-ENG-VERIFY'; client='Self Test'; authorization_reference='VERIFY-1'
    authorized_operators=@('*'); authorized_scope=@{ hostnames=@('*'); ips=@(); asset_tags=@() }
    valid_from='2026-01-01T00:00:00Z'; valid_to='2026-12-31T23:59:59Z'; collection_mode='minimized'
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $engMin -Encoding utf8
function global:Collect-CaptureMin {
    param($Context)
    $good = Join-Path ([IO.Path]::GetTempPath()) ("hhcm_" + [guid]::NewGuid().ToString('N') + '.exe')
    $b = New-Object byte[] 32; $b[0] = 0x4D; $b[1] = 0x5A; [IO.File]::WriteAllBytes($good, $b)
    $global:HHCapMin = Add-FlaggedFile -Path $good
    Remove-Item -LiteralPath $good -Force -ErrorAction SilentlyContinue
    New-EvidenceRecord -ArtifactType 'capture' -Collector 'Collect-CaptureMin' -Attack @() -Data @{ ok = 1 } -Context $Context
}
$outCm = New-TempDir
Invoke-HaarisHunter -EngagementFile $engMin -Profile quick -Include 'CaptureMin' `
    -Exclude $script:RealCollectors -OutputPath $outCm -LogLevel Error | Out-Null
Assert-That "minimized mode does not capture flagged files" ($global:HHCapMin.captured -eq $false -and $global:HHCapMin.reason -eq 'mode_not_full') "reason=$($global:HHCapMin.reason)"

# --- Cleanup ---
Remove-Item Function:\Collect-Zeta, Function:\Collect-Alpha, Function:\Collect-Capture, Function:\Collect-CaptureMin -ErrorAction SilentlyContinue
Remove-Item Variable:\HHCapResults, Variable:\HHCapMin -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $engMin -Force -ErrorAction SilentlyContinue
foreach ($d in $outC,$outCm) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
foreach ($d in $out,$outE,$outM,$out2,$out3) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
Remove-Item -LiteralPath $enc -Force -ErrorAction SilentlyContinue

Write-Host ("`n==== {0} passed, {1} failed ====" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail){'Red'}else{'Green'})
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
