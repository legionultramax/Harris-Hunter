@{
    RootModule           = 'HaarisHunter.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = 'a3874b73-63a4-4cc7-b8ae-67d56aae85e7'
    Author               = 'Cyber Gate Defense - DFIR / Threat Hunting'
    CompanyName          = 'Cyber Gate Defense'
    Copyright            = '(c) Cyber Gate Defense. All rights reserved.'
    Description          = 'HAARIS-HUNTER (CGD-CA-DESIGN-001) Phase 1: authorization-gated, chain-of-custody Windows forensic collection framework. Emits a hashed, normalized JSON evidence bundle for downstream normalize/detect/risk/report pipelines. Runs on Windows PowerShell 5.1 and PowerShell 7+.'
    PowerShellVersion    = '5.1'
    FunctionsToExport    = @(
        'Invoke-HaarisHunter',
        'Assert-Authorization',
        'New-EvidenceRecord',
        'Test-EvidenceRecord',
        'Get-HHConfiguration',
        'Get-HostMetadata',
        'Get-TimeIntegrity',
        'Get-HHStringHash',
        'Seal-EvidenceBundle',
        'Test-EvidenceBundle',
        'Test-ChainOfCustody',
        'Protect-EvidenceBundle',
        'Unprotect-EvidenceBundle',
        'Write-HtmlReport'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData = @{
        PSData = @{
            Tags       = @('DFIR', 'Forensics', 'IncidentResponse', 'CompromiseAssessment', 'HAARIS-HUNTER')
            ProjectUri = ''
        }
        DesignRef     = 'CGD-CA-DESIGN-001'
        SchemaVersion = '1.0'
    }
}
