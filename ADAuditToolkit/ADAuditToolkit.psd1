@{
    RootModule        = 'ADAuditToolkit.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '7e0d3c9a-4b2f-4c61-9a8d-2f5e1b7c0a44'
    Author            = 'Kaleb Cash-Wade'
    Description       = 'Active Directory hygiene auditor. Runs ten identity security checks and produces a scored HTML report. Read-only. Includes a synthetic demo mode that needs no domain.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-ADAudit')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('ActiveDirectory', 'Security', 'Audit', 'BlueTeam', 'IdentitySecurity')
            LicenseUri   = 'https://github.com/Dracarus08/AD-Audit-Toolkit/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/Dracarus08/AD-Audit-Toolkit'
            ReleaseNotes = 'Initial release. Ten checks, HTML report, demo mode.'
        }
    }
}
