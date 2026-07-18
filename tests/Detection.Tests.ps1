<#
    Pester v5 tests for the HAARIS-HUNTER Phase 2 detection engine (Sigma path).
    Requires Pester 5+. For a dependency-free equivalent, use tools/Verify-Framework.ps1 [8]
    and tools/Test-DetectionRules.ps1. All fixtures are benign (ordinary paths, fixed dates).
    Run:  Invoke-Pester -Path tests/Detection.Tests.ps1
#>

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:ModuleRoot 'HaarisHunter.psd1') -Force
    & (Join-Path $script:ModuleRoot 'tools/Convert-SigmaPack.ps1') -Quiet | Out-Null
    $script:Rules = Import-HHCompiledRules -Path (Join-Path $script:ModuleRoot 'config/detection/rules/compiled')
    $script:Win   = [datetime]'2026-07-01T00:00:00Z'

    function New-RunKeyRecord {
        param([string]$Command, [string]$Created = '2026-07-15T00:00:00Z')
        [ordered]@{
            schema_version='1.0'; artifact_type='autorun_run_key'; collector='Collect-Test'
            collected_at_utc='2026-07-18T00:00:00Z'; host=@{ hostname='T'; os='windows'; host_id='t1' }
            engagement_id='E'; source='HKCU..Run'; attack=@('T1547.001')
            data=@{ location='HKCU\..\Run'; name='x'; command=$Command; created=$Created }
        }
    }
}

Describe 'Normalization' {
    It 'explodes a multi-line cron record into one event per entry' {
        $rec = [ordered]@{ artifact_type='cron_job'; collector='c'; collected_at_utc='2026-07-18T00:00:00Z'
            host=@{hostname='H';os='linux';host_id='h'}; engagement_id='E'; source='/etc/crontab'; attack=@()
            data=@{ path='/etc/crontab'; entries=@('0 1 * * * root /usr/bin/a','0 2 * * * root /usr/bin/b') } }
        $ev = @(ConvertTo-HHNormalizedEvent -Record $rec)
        $ev.Count | Should -Be 2
        $ev[0].category | Should -Be 'persistence_inventory'
    }
    It 'maps a run key to a registry_run persistence event' {
        $ev = @(ConvertTo-HHNormalizedEvents -Records @((New-RunKeyRecord -Command 'C:\Users\Public\u.exe')))
        $ev[0].persistence.mechanism | Should -Be 'registry_run'
        $ev[0].persistence.value | Should -Be 'C:\Users\Public\u.exe'
    }
    It 'redacts payment-card-like digit runs in retained free-text' {
        $rec = [ordered]@{ artifact_type='process'; collector='c'; collected_at_utc='2026-07-18T00:00:00Z'
            host=@{hostname='H';os='windows';host_id='h'}; engagement_id='E'; source='p'; attack=@()
            data=@{ pid=1; command_line='app.exe --token 4111111111111111'; image_path='C:\a.exe' } }
        $ev = @(ConvertTo-HHNormalizedEvent -Record $rec)
        $ev[0].process.command_line | Should -Match '\*{12}1111'
    }
}

Describe 'Finding schema' {
    BeforeAll {
        $ev = @(ConvertTo-HHNormalizedEvents -Records @((New-RunKeyRecord -Command 'C:\Users\Public\u.exe')))[0]
        $script:F = New-Finding -Event $ev -FindingType 'persistence.registry_run' -Severity high -Confidence medium -Engine sigma -RuleId 'r1' -Attack @('T1547.001')
    }
    It 'produces a valid finding.v1' { Test-Finding -Finding $script:F | Should -BeTrue }
    It 'rejects an invalid finding' {
        $bad = [ordered]@{ finding_id='x'; severity='bogus' }
        Test-Finding -Finding $bad | Should -BeFalse
    }
    It 'merges duplicate findings by dedup_key' {
        $ev = @(ConvertTo-HHNormalizedEvents -Records @((New-RunKeyRecord -Command 'C:\Users\Public\u.exe')))[0]
        $a = New-Finding -Event $ev -FindingType 'persistence.registry_run' -Severity high -Confidence medium -Engine sigma -RuleId 'r1' -Attack @('T1547.001')
        $b = New-Finding -Event $ev -FindingType 'persistence.registry_run' -Severity high -Confidence medium -Engine sigma -RuleId 'r1' -Attack @('T1547.001')
        $merged = @(Merge-HHFindings -Findings @($a,$b))
        $merged.Count | Should -Be 1
        $merged[0].occurrences | Should -Be 2
    }
}

Describe 'Sigma evaluation' {
    It 'fires on a recent user-writable autostart' {
        $ev = @(ConvertTo-HHNormalizedEvents -Records @((New-RunKeyRecord -Command 'C:\Users\Public\u.exe')))
        $f = @(Invoke-SigmaRules -Events $ev -Rules $script:Rules -ScanWindowStart $script:Win -FindingArgs @{})
        $f.Count | Should -Be 1
        $f[0].finding_type | Should -Be 'persistence.registry_run'
    }
    It 'does not fire on a non-user-writable path' {
        $ev = @(ConvertTo-HHNormalizedEvents -Records @((New-RunKeyRecord -Command 'C:\Program Files\App\app.exe')))
        (@(Invoke-SigmaRules -Events $ev -Rules $script:Rules -ScanWindowStart $script:Win -FindingArgs @{})).Count | Should -Be 0
    }
    It 'excludes autostarts created before the scan window (timeframe filter)' {
        $ev = @(ConvertTo-HHNormalizedEvents -Records @((New-RunKeyRecord -Command 'C:\Users\Public\u.exe' -Created '2026-01-01T00:00:00Z')))
        (@(Invoke-SigmaRules -Events $ev -Rules $script:Rules -ScanWindowStart $script:Win -FindingArgs @{})).Count | Should -Be 0
    }
}

Describe 'Risk scoring (blueprint 28.6)' {
    It 'computes base x confidence + modifiers' {
        $f = [ordered]@{ severity='high'; confidence='medium'; observed_at='2026-07-15T00:00:00Z'; host=@{ asset_criticality='crown_jewel' }; detection=@{ engine='sigma'; mitre_attack=@() }; risk_score=$null }
        Get-HHRiskScore -Finding $f | Out-Null
        $f['risk_score'] | Should -Be 59
    }
    It 'caps host score and rewards tactic breadth' {
        $map = Get-HHAttackMap -Path (Join-Path $script:ModuleRoot 'config/detection/attack-map.json')
        $f1 = [ordered]@{ severity='critical'; confidence='confirmed'; observed_at='2026-07-15T00:00:00Z'; host=@{}; detection=@{ engine='sigma'; mitre_attack=@(@{tactic=$null;technique='T1059.004'}) }; risk_score=90 }
        $f2 = [ordered]@{ severity='high'; confidence='high'; observed_at='2026-07-15T00:00:00Z'; host=@{}; detection=@{ engine='sigma'; mitre_attack=@(@{tactic=$null;technique='T1547.001'}) }; risk_score=63 }
        $hs = Get-HHHostScore -Findings @($f1,$f2) -Map $map -Now ([datetime]'2026-07-18T00:00:00Z')
        $hs.score | Should -BeGreaterThan 90
        $hs.band | Should -Be 'confirmed_critical'
    }
}
