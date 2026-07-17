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

# Every real collector - excluded so the framework runs stay fast and deterministic.
$script:RealCollectors = @(
    'System','Process','Network','Autoruns','Services','ScheduledTasks','WmiPersistence',
    'Accounts','AuthEvents','EventLogs','Filesystem','DefenderState','BitsJobs','MemoryHints',
    'Wireless','BrowserHistory'
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
            'Unprotect-EvidenceBundle','Get-HHStringHash','Write-HtmlReport'
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

# --- Cleanup ---
Remove-Item Function:\Collect-Zeta, Function:\Collect-Alpha -ErrorAction SilentlyContinue
foreach ($d in $out,$outE,$out2,$out3) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
Remove-Item -LiteralPath $enc -Force -ErrorAction SilentlyContinue

Write-Host ("`n==== {0} passed, {1} failed ====" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail){'Red'}else{'Green'})
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
