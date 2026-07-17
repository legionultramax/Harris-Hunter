<#
    Pester v5 tests for the HAARIS-HUNTER Phase 1 Core Framework.
    Requires Pester 5+ (Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser).
    For a dependency-free equivalent that runs on any PowerShell, use tools/Verify-Framework.ps1.
    Run:  Invoke-Pester -Path tests/HaarisHunter.Tests.ps1
#>

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:ModuleRoot 'HaarisHunter.psd1') -Force

    function New-TestEngagement {
        param([string[]]$Operators = @('*'), [string[]]$Hostnames = @('*'),
              [string]$From = '2026-01-01T00:00:00Z', [string]$To = '2026-12-31T23:59:59Z')
        $path = Join-Path ([IO.Path]::GetTempPath()) ("hh_eng_" + [guid]::NewGuid().ToString('N') + '.json')
        @{
            engagement_id = 'CGD-ENG-PESTER'; client = 'Pester'; authorization_reference = 'PESTER-1'
            authorized_operators = $Operators
            authorized_scope = @{ hostnames = $Hostnames; ips = @(); asset_tags = @() }
            valid_from = $From; valid_to = $To; collection_mode = 'full'
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding utf8
        $path
    }

    function New-TestOutDir {
        $p = Join-Path ([IO.Path]::GetTempPath()) ("hh_out_" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        $p
    }

    # A self-test collector so end-to-end runs produce a real, hashable artifact.
    function global:Collect-SelfTest {
        param($Context)
        New-EvidenceRecord -ArtifactType 'selftest' -Collector 'Collect-SelfTest' `
            -Source 'pester' -Attack @('T1059') -Data @{ note = 'hello'; n = 1 } -Context $Context
    }
}

AfterAll {
    Remove-Item Function:\Collect-SelfTest -ErrorAction SilentlyContinue
}

Describe 'Hash engine' {
    It 'produces the known SHA-256 vector for "abc"' {
        Get-HHStringHash -InputString 'abc' |
            Should -Be 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    }
}

Describe 'Evidence schema' {
    BeforeAll {
        $ctx = [pscustomobject]@{ Host = @{ hostname = 'H' }; EngagementId = 'E1' }
        $script:rec = New-EvidenceRecord -ArtifactType 'test' -Collector 'C' -Data @{ a = 1 } -Context $ctx
    }
    It 'builds a schema-valid record' { Test-EvidenceRecord -Record $script:rec | Should -BeTrue }
    It 'stamps the engagement id' { $script:rec.engagement_id | Should -Be 'E1' }
    It 'rejects a malformed record' { Test-EvidenceRecord -Record @{ foo = 'bar' } | Should -BeFalse }
}

Describe 'Authorization gate' {
    BeforeAll { $script:hostMeta = @{ hostname = 'WKS-1'; fqdn = 'wks-1.corp'; ips = @('10.0.0.5') } }

    It 'authorizes an in-scope operator inside the window' {
        $eng = @{ engagement_id='E'; authorized_operators=@('*'); authorized_scope=@{hostnames=@('*');ips=@()}; valid_from='2026-01-01T00:00:00Z'; valid_to='2026-12-31T23:59:59Z' }
        (Assert-Authorization -Engagement $eng -HostMeta $script:hostMeta).Authorized | Should -BeTrue
    }
    It 'denies an out-of-scope host' {
        $eng = @{ engagement_id='E'; authorized_operators=@('*'); authorized_scope=@{hostnames=@('OTHER-*');ips=@()}; valid_from='2026-01-01T00:00:00Z'; valid_to='2026-12-31T23:59:59Z' }
        (Assert-Authorization -Engagement $eng -HostMeta $script:hostMeta).Authorized | Should -BeFalse
    }
    It 'denies an expired engagement window' {
        $eng = @{ engagement_id='E'; authorized_operators=@('*'); authorized_scope=@{hostnames=@('*');ips=@()}; valid_from='2020-01-01T00:00:00Z'; valid_to='2020-02-01T00:00:00Z' }
        (Assert-Authorization -Engagement $eng -HostMeta $script:hostMeta).Authorized | Should -BeFalse
    }
    It 'denies an unauthorized operator' {
        $eng = @{ engagement_id='E'; authorized_operators=@('nobody@nowhere'); authorized_scope=@{hostnames=@('*');ips=@()}; valid_from='2026-01-01T00:00:00Z'; valid_to='2026-12-31T23:59:59Z' }
        (Assert-Authorization -Engagement $eng -HostMeta $script:hostMeta -OperatorIdentities @('someone-else')).Authorized | Should -BeFalse
    }
    It 'matches scope by IP wildcard' {
        $eng = @{ engagement_id='E'; authorized_operators=@('*'); authorized_scope=@{hostnames=@();ips=@('10.0.0.*')}; valid_from='2026-01-01T00:00:00Z'; valid_to='2026-12-31T23:59:59Z' }
        (Assert-Authorization -Engagement $eng -HostMeta $script:hostMeta).Authorized | Should -BeTrue
    }
}

Describe 'End-to-end collection and sealing' {
    BeforeAll {
        $script:eng = New-TestEngagement
        $script:out = New-TestOutDir
        $script:run = Invoke-HaarisHunter -EngagementFile $script:eng -Profile quick -Include SelfTest -OutputPath $script:out -LogLevel Error
    }

    It 'reports the run as authorized' { $script:run.Authorized | Should -BeTrue }
    It 'writes the manifest, ledger, bundle, report and log' {
        foreach ($f in 'manifest.json','coc.jsonl','bundle.json','report.html','haaris-hunter.log') {
            Test-Path (Join-Path $script:out $f) | Should -BeTrue
        }
    }
    It 'writes the self-test artifact' { Test-Path (Join-Path $script:out 'artifacts/selftest.json') | Should -BeTrue }
    It 'produces a bundle that re-verifies' { (Test-EvidenceBundle -BundlePath $script:out).Valid | Should -BeTrue }
    It 'has an intact custody chain' { (Test-ChainOfCustody -Path (Join-Path $script:out 'coc.jsonl')).Valid | Should -BeTrue }
}

Describe 'Tamper detection' {
    It 'detects modified artifact content' {
        $eng = New-TestEngagement; $out = New-TestOutDir
        Invoke-HaarisHunter -EngagementFile $eng -Profile quick -Include SelfTest -OutputPath $out -LogLevel Error | Out-Null
        Add-Content -LiteralPath (Join-Path $out 'artifacts/selftest.json') -Value ' '
        (Test-EvidenceBundle -BundlePath $out).Valid | Should -BeFalse
    }
    It 'detects a modified custody ledger' {
        $eng = New-TestEngagement; $out = New-TestOutDir
        Invoke-HaarisHunter -EngagementFile $eng -Profile quick -Include SelfTest -OutputPath $out -LogLevel Error | Out-Null
        $coc = Join-Path $out 'coc.jsonl'
        $lines = Get-Content -LiteralPath $coc
        $lines[1] = $lines[1] -replace '"event":"[^"]+"', '"event":"forged"'
        Set-Content -LiteralPath $coc -Value $lines -Encoding utf8
        (Test-ChainOfCustody -Path $coc).Valid | Should -BeFalse
    }
}

Describe 'AES transport encryption' {
    It 'round-trips with the correct passphrase and rejects a wrong one' {
        $eng = New-TestEngagement; $out = New-TestOutDir
        Invoke-HaarisHunter -EngagementFile $eng -Profile quick -Include SelfTest -OutputPath $out -LogLevel Error | Out-Null
        $secure = ConvertTo-SecureString 'Pester-Passphrase-123!' -AsPlainText -Force
        $enc = Protect-EvidenceBundle -BundlePath $out -Passphrase $secure
        Test-Path $enc | Should -BeTrue
        $zip = Unprotect-EvidenceBundle -Path $enc -Passphrase $secure -OutZip (Join-Path ([IO.Path]::GetTempPath()) ("hh_ok_" + [guid]::NewGuid().ToString('N') + '.zip'))
        Test-Path $zip | Should -BeTrue
        { Unprotect-EvidenceBundle -Path $enc -Passphrase (ConvertTo-SecureString 'wrong' -AsPlainText -Force) -OutZip (Join-Path ([IO.Path]::GetTempPath()) 'hh_bad.zip') } | Should -Throw
    }
}
