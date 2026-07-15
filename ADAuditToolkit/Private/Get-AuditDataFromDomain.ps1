function Get-AuditDataFromDomain {
    <#
    .SYNOPSIS
        Collects users, computers, privileged groups, and password policy from a live domain.
    .DESCRIPTION
        Read-only. Uses the ActiveDirectory module from RSAT. Nothing in this
        module writes to the directory.
    #>
    [CmdletBinding()]
    param(
        [string]$Server
    )

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'The ActiveDirectory module is not available. Install RSAT, or run with -Demo to use the synthetic dataset.'
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    $adParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $adParams['Server'] = $Server }

    $userProps = @(
        'DisplayName', 'Enabled', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires',
        'PasswordNotRequired', 'ServicePrincipalNames', 'TrustedForDelegation', 'whenCreated', 'Description'
    )

    Write-Verbose 'Collecting user objects.'
    $users = Get-ADUser -Filter * -Properties $userProps @adParams | ForEach-Object {
        [pscustomobject]@{
            SamAccountName        = $_.SamAccountName
            DisplayName           = $_.DisplayName
            Enabled               = [bool]$_.Enabled
            LastLogonDate         = $_.LastLogonDate
            PasswordLastSet       = $_.PasswordLastSet
            PasswordNeverExpires  = [bool]$_.PasswordNeverExpires
            PasswordNotRequired   = [bool]$_.PasswordNotRequired
            ServicePrincipalNames = @($_.ServicePrincipalNames)
            TrustedForDelegation  = [bool]$_.TrustedForDelegation
            WhenCreated           = $_.whenCreated
            Description           = $_.Description
        }
    }

    Write-Verbose 'Collecting computer objects.'
    $computers = Get-ADComputer -Filter * -Properties LastLogonDate, OperatingSystem, TrustedForDelegation, PrimaryGroupID @adParams | ForEach-Object {
        [pscustomobject]@{
            Name                 = $_.Name
            Enabled              = [bool]$_.Enabled
            LastLogonDate        = $_.LastLogonDate
            OperatingSystem      = $_.OperatingSystem
            TrustedForDelegation = [bool]$_.TrustedForDelegation
            IsDomainController   = ($_.PrimaryGroupID -eq 516)
        }
    }

    Write-Verbose 'Collecting privileged group membership.'
    $groups = foreach ($groupName in $script:PrivilegedGroupNames) {
        $group = Get-ADGroup -Filter "Name -eq '$groupName'" @adParams
        if ($null -eq $group) { continue }
        $members = @(
            Get-ADGroupMember -Identity $group -Recursive @adParams |
                Where-Object { $_.objectClass -eq 'user' } |
                ForEach-Object { $_.SamAccountName }
        )
        [pscustomobject]@{
            Name    = $groupName
            Members = $members
        }
    }

    Write-Verbose 'Collecting password policy.'
    $policy = Get-ADDefaultDomainPasswordPolicy @adParams
    $domain = Get-ADDomain @adParams

    $maxAgeDays = 0
    if ($policy.MaxPasswordAge -and $policy.MaxPasswordAge.TotalDays -gt 0) {
        $maxAgeDays = [int]$policy.MaxPasswordAge.TotalDays
    }

    [pscustomobject]@{
        Domain    = [pscustomobject]@{
            Name           = $domain.DNSRoot
            PasswordPolicy = [pscustomobject]@{
                MinPasswordLength           = [int]$policy.MinPasswordLength
                MaxPasswordAgeDays          = $maxAgeDays
                LockoutThreshold            = [int]$policy.LockoutThreshold
                ComplexityEnabled           = [bool]$policy.ComplexityEnabled
                ReversibleEncryptionEnabled = [bool]$policy.ReversibleEncryptionEnabled
            }
        }
        Users     = @($users)
        Computers = @($computers)
        Groups    = @($groups)
        Source    = "Live domain ($($domain.DNSRoot))"
    }
}
