function Get-AuditDataFromDemo {
    <#
    .SYNOPSIS
        Loads the bundled synthetic domain dataset and normalizes it.
    .DESCRIPTION
        The dataset stores dates as day offsets so the demo stays stable no matter
        when it runs. Every object in it is fake. See tools/New-DemoDataset.ps1
        for the generator.
    #>
    [CmdletBinding()]
    param(
        [string]$Path
    )

    if (-not $Path) {
        $Path = Join-Path $PSScriptRoot '..\Data\demo-domain.json'
    }
    if (-not (Test-Path $Path)) {
        throw "Demo dataset not found at $Path."
    }

    $raw = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    $now = Get-Date

    $users = foreach ($u in @($raw.Users)) {
        $lastLogon = $null
        if ($u.LastLogonDaysAgo -ge 0) { $lastLogon = $now.AddDays(-1 * $u.LastLogonDaysAgo) }
        $pwdLastSet = $null
        if ($u.PasswordLastSetDaysAgo -ge 0) { $pwdLastSet = $now.AddDays(-1 * $u.PasswordLastSetDaysAgo) }

        [pscustomobject]@{
            SamAccountName        = $u.SamAccountName
            DisplayName           = $u.DisplayName
            Enabled               = [bool]$u.Enabled
            LastLogonDate         = $lastLogon
            PasswordLastSet       = $pwdLastSet
            PasswordNeverExpires  = [bool]$u.PasswordNeverExpires
            PasswordNotRequired   = [bool]$u.PasswordNotRequired
            ServicePrincipalNames = @($u.ServicePrincipalNames)
            TrustedForDelegation  = [bool]$u.TrustedForDelegation
            WhenCreated           = $now.AddDays(-1 * $u.WhenCreatedDaysAgo)
            Description           = $u.Description
        }
    }

    $computers = foreach ($c in @($raw.Computers)) {
        $lastLogon = $null
        if ($c.LastLogonDaysAgo -ge 0) { $lastLogon = $now.AddDays(-1 * $c.LastLogonDaysAgo) }

        [pscustomobject]@{
            Name                 = $c.Name
            Enabled              = [bool]$c.Enabled
            LastLogonDate        = $lastLogon
            OperatingSystem      = $c.OperatingSystem
            TrustedForDelegation = [bool]$c.TrustedForDelegation
            IsDomainController   = [bool]$c.IsDomainController
        }
    }

    $groups = foreach ($g in @($raw.Groups)) {
        [pscustomobject]@{
            Name    = $g.Name
            Members = @($g.Members)
        }
    }

    [pscustomobject]@{
        Domain    = [pscustomobject]@{
            Name           = $raw.Domain.Name
            PasswordPolicy = [pscustomobject]@{
                MinPasswordLength           = [int]$raw.Domain.PasswordPolicy.MinPasswordLength
                MaxPasswordAgeDays          = [int]$raw.Domain.PasswordPolicy.MaxPasswordAgeDays
                LockoutThreshold            = [int]$raw.Domain.PasswordPolicy.LockoutThreshold
                ComplexityEnabled           = [bool]$raw.Domain.PasswordPolicy.ComplexityEnabled
                ReversibleEncryptionEnabled = [bool]$raw.Domain.PasswordPolicy.ReversibleEncryptionEnabled
            }
        }
        Users     = @($users)
        Computers = @($computers)
        Groups    = @($groups)
        Source    = 'Demo (synthetic dataset)'
    }
}
