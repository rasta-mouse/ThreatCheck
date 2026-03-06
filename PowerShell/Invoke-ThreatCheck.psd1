@{
    RootModule        = 'Invoke-ThreatCheck.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a3f2c8d1-4b7e-4f9a-b2c3-d8e5f1a6b7c9'
    Author            = 'HoneyBadger Vanguard LLC'
    CompanyName       = 'HoneyBadger Vanguard LLC'
    Copyright         = '(c) 2025 HoneyBadger Vanguard LLC. MIT License.'
    Description       = 'PowerShell wrapper for rasta-mouse/ThreatCheck with pipeline support, structured output, Wazuh SIEM integration, and HTML reporting.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @('Invoke-ThreatCheck')
    CmdletsToExport   = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('Security', 'RedTeam', 'PurpleTeam', 'AMSI', 'Defender', 'ThreatCheck', 'HoneyBadgerVanguard', 'Wazuh', 'SIEM')
            ProjectUri   = 'https://github.com/MoSLoF/ThreatCheck'
            LicenseUri   = 'https://github.com/MoSLoF/ThreatCheck/blob/master/LICENSE'
            ReleaseNotes = '1.0.0 - Initial release. Pipeline support, structured output, Wazuh NDJSON logging, HTML reporting.'
        }
    }
}
