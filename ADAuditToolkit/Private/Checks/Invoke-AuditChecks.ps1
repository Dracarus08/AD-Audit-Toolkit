function Invoke-AuditChecks {
    <#
    .SYNOPSIS
        Runs every hygiene check against normalized audit data and returns check results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data,
        [int]$StaleAccountDays = 90,
        [int]$OldPasswordDays = 365,
        [int]$DormantComputerDays = 120,
        [int]$PrivInactiveDays = 60
    )

    $now = Get-Date
    $privSet = Get-PrivilegedUserSet -Data $Data
    $enabledUsers = @($Data.Users | Where-Object { $_.Enabled })

    $results = New-Object System.Collections.ArrayList

    # STALE-USERS
    $findings = foreach ($u in $enabledUsers) {
        $days = if ($u.LastLogonDate) { [int]($now - $u.LastLogonDate).TotalDays } else { 99999 }
        if ($days -ge $StaleAccountDays) {
            $label = if ($u.LastLogonDate) { "$days days since last logon" } else { 'never logged on' }
            New-AuditFinding -CheckId 'STALE-USERS' -Severity 'Medium' -ObjectName $u.SamAccountName -ObjectType 'User' -Detail $label
        }
    }
    [void]$results.Add((New-CheckResult -CheckId 'STALE-USERS' -Name 'Stale user accounts' `
        -Description "Enabled user accounts with no interactive logon in the last $StaleAccountDays days." `
        -AttackTechniques @('T1078') `
        -Recommendation 'Disable or remove accounts that are no longer in use. Dormant enabled accounts are a low-noise foothold.' `
        -Findings $findings))

    # PWD-NEVER-EXPIRES
    $findings = foreach ($u in $enabledUsers) {
        if ($u.PasswordNeverExpires) {
            $priv = $privSet.ContainsKey($u.SamAccountName)
            $sev = if ($priv) { 'High' } else { 'Medium' }
            $note = if ($priv) { 'privileged account with a non-expiring password' } else { 'password never expires' }
            New-AuditFinding -CheckId 'PWD-NEVER-EXPIRES' -Severity $sev -ObjectName $u.SamAccountName -ObjectType 'User' -Detail $note
        }
    }
    [void]$results.Add((New-CheckResult -CheckId 'PWD-NEVER-EXPIRES' -Name 'Password never expires' `
        -Description 'Enabled users whose password is set to never expire. Scored higher when the account is privileged.' `
        -AttackTechniques @('T1078', 'T1110') `
        -Recommendation 'Move service accounts to group managed service accounts. Enforce rotation on the rest.' `
        -Findings $findings))

    # PWD-NOT-REQUIRED
    $findings = foreach ($u in $enabledUsers) {
        if ($u.PasswordNotRequired) {
            New-AuditFinding -CheckId 'PWD-NOT-REQUIRED' -Severity 'High' -ObjectName $u.SamAccountName -ObjectType 'User' -Detail 'PASSWD_NOTREQD is set. The account can have a blank password.'
        }
    }
    [void]$results.Add((New-CheckResult -CheckId 'PWD-NOT-REQUIRED' -Name 'Password not required' `
        -Description 'Accounts flagged so that no password is required. These can hold an empty password.' `
        -AttackTechniques @('T1078', 'T1110') `
        -Recommendation 'Clear the PASSWD_NOTREQD flag and force a compliant password reset.' `
        -Findings $findings))

    # OLD-PASSWORDS
    $findings = foreach ($u in $enabledUsers) {
        if ($u.PasswordLastSet) {
            $days = [int]($now - $u.PasswordLastSet).TotalDays
            if ($days -ge $OldPasswordDays) {
                New-AuditFinding -CheckId 'OLD-PASSWORDS' -Severity 'Low' -ObjectName $u.SamAccountName -ObjectType 'User' -Detail "password last set $days days ago"
            }
        }
    }
    [void]$results.Add((New-CheckResult -CheckId 'OLD-PASSWORDS' -Name 'Aged passwords' `
        -Description "Enabled users whose password is older than $OldPasswordDays days." `
        -AttackTechniques @('T1110') `
        -Recommendation 'Enforce a maximum password age. Investigate accounts that never rotate.' `
        -Findings $findings))

    # PRIV-SPRAWL
    $thresholds = @{ 'Domain Admins' = 5; 'Enterprise Admins' = 2; 'Schema Admins' = 1; 'Administrators' = 8; 'Account Operators' = 0; 'Backup Operators' = 2; 'Server Operators' = 2; 'Print Operators' = 0 }
    $findings = foreach ($g in @($Data.Groups)) {
        $count = @(Get-ResolvedGroupMembers -Data $Data -GroupName $g.Name).Count
        $limit = if ($thresholds.ContainsKey($g.Name)) { $thresholds[$g.Name] } else { 10 }
        if ($count -gt $limit) {
            New-AuditFinding -CheckId 'PRIV-SPRAWL' -Severity 'High' -ObjectName $g.Name -ObjectType 'Group' -Detail "$count effective members, baseline is $limit"
        }
    }
    [void]$results.Add((New-CheckResult -CheckId 'PRIV-SPRAWL' -Name 'Privileged group sprawl' `
        -Description 'Privileged groups whose effective membership, including nested groups, exceeds a conservative baseline.' `
        -AttackTechniques @('T1078') `
        -Recommendation 'Reduce standing privilege. Move to just-in-time elevation where possible.' `
        -Findings $findings))

    # PRIV-INACTIVE
    $findings = foreach ($sam in @($privSet.Keys)) {
        $u = $Data.Users | Where-Object { $_.SamAccountName -eq $sam } | Select-Object -First 1
        if ($null -eq $u) { continue }
        if (-not $u.Enabled) {
            New-AuditFinding -CheckId 'PRIV-INACTIVE' -Severity 'High' -ObjectName $sam -ObjectType 'User' -Detail 'disabled account still holds privileged membership'
            continue
        }
        $days = if ($u.LastLogonDate) { [int]($now - $u.LastLogonDate).TotalDays } else { 99999 }
        if ($days -ge $PrivInactiveDays) {
            $label = if ($u.LastLogonDate) { "privileged account inactive for $days days" } else { 'privileged account has never logged on' }
            New-AuditFinding -CheckId 'PRIV-INACTIVE' -Severity 'High' -ObjectName $sam -ObjectType 'User' -Detail $label
        }
    }
    [void]$results.Add((New-CheckResult -CheckId 'PRIV-INACTIVE' -Name 'Inactive privileged accounts' `
        -Description "Members of privileged groups that are disabled or have not logged on in $PrivInactiveDays days." `
        -AttackTechniques @('T1078', 'T1098') `
        -Recommendation 'Remove privileged rights from dormant and disabled accounts immediately.' `
        -Findings $findings))

    # KERBEROASTABLE
    $findings = foreach ($u in $enabledUsers) {
        $spns = @($u.ServicePrincipalNames | Where-Object { $_ })
        if ($spns.Count -gt 0) {
            $priv = $privSet.ContainsKey($u.SamAccountName)
            $sev = if ($priv) { 'High' } else { 'Medium' }
            $note = "user account exposes $($spns.Count) SPN(s)"
            if ($priv) { $note += ' and is privileged' }
            New-AuditFinding -CheckId 'KERBEROASTABLE' -Severity $sev -ObjectName $u.SamAccountName -ObjectType 'User' -Detail $note
        }
    }
    [void]$results.Add((New-CheckResult -CheckId 'KERBEROASTABLE' -Name 'Kerberoastable accounts' `
        -Description 'User accounts carrying service principal names. Any domain user can request their service ticket and crack it offline.' `
        -AttackTechniques @('T1558.003') `
        -Recommendation 'Use group managed service accounts with long random passwords. Keep SPNs off privileged users.' `
        -Findings $findings))

    # UNCONSTRAINED-DELEG
    $findings = @()
    $findings += foreach ($u in @($Data.Users | Where-Object { $_.TrustedForDelegation })) {
        New-AuditFinding -CheckId 'UNCONSTRAINED-DELEG' -Severity 'High' -ObjectName $u.SamAccountName -ObjectType 'User' -Detail 'user object trusted for unconstrained delegation'
    }
    $findings += foreach ($c in @($Data.Computers | Where-Object { $_.TrustedForDelegation -and -not $_.IsDomainController })) {
        New-AuditFinding -CheckId 'UNCONSTRAINED-DELEG' -Severity 'High' -ObjectName $c.Name -ObjectType 'Computer' -Detail 'non-DC computer trusted for unconstrained delegation'
    }
    [void]$results.Add((New-CheckResult -CheckId 'UNCONSTRAINED-DELEG' -Name 'Unconstrained delegation' `
        -Description 'Objects other than domain controllers that are trusted for unconstrained delegation. A compromise here can capture TGTs.' `
        -AttackTechniques @('T1550', 'T1078') `
        -Recommendation 'Replace unconstrained delegation with constrained or resource-based delegation. Mark sensitive accounts as not delegatable.' `
        -Findings $findings))

    # DORMANT-COMPUTERS
    $findings = foreach ($c in @($Data.Computers | Where-Object { $_.Enabled })) {
        $days = if ($c.LastLogonDate) { [int]($now - $c.LastLogonDate).TotalDays } else { 99999 }
        if ($days -ge $DormantComputerDays) {
            $label = if ($c.LastLogonDate) { "$days days since last logon" } else { 'never logged on' }
            New-AuditFinding -CheckId 'DORMANT-COMPUTERS' -Severity 'Low' -ObjectName $c.Name -ObjectType 'Computer' -Detail $label
        }
    }
    [void]$results.Add((New-CheckResult -CheckId 'DORMANT-COMPUTERS' -Name 'Dormant computer objects' `
        -Description "Enabled computer objects with no logon in $DormantComputerDays days." `
        -AttackTechniques @('T1078') `
        -Recommendation 'Disable and remove stale computer objects. They inflate the attack surface and confuse inventory.' `
        -Findings $findings))

    # WEAK-PWD-POLICY
    $policy = $Data.Domain.PasswordPolicy
    $findings = New-Object System.Collections.ArrayList
    if ($policy.MinPasswordLength -lt 14) {
        [void]$findings.Add((New-AuditFinding -CheckId 'WEAK-PWD-POLICY' -Severity 'Medium' -ObjectName 'Default Domain Policy' -ObjectType 'Policy' -Detail "minimum password length is $($policy.MinPasswordLength), baseline is 14"))
    }
    if ($policy.LockoutThreshold -eq 0) {
        [void]$findings.Add((New-AuditFinding -CheckId 'WEAK-PWD-POLICY' -Severity 'Medium' -ObjectName 'Default Domain Policy' -ObjectType 'Policy' -Detail 'account lockout is disabled, online guessing is unbounded'))
    }
    if (-not $policy.ComplexityEnabled) {
        [void]$findings.Add((New-AuditFinding -CheckId 'WEAK-PWD-POLICY' -Severity 'Medium' -ObjectName 'Default Domain Policy' -ObjectType 'Policy' -Detail 'password complexity is disabled'))
    }
    if ($policy.ReversibleEncryptionEnabled) {
        [void]$findings.Add((New-AuditFinding -CheckId 'WEAK-PWD-POLICY' -Severity 'High' -ObjectName 'Default Domain Policy' -ObjectType 'Policy' -Detail 'reversible encryption is enabled, passwords are recoverable in clear text'))
    }
    [void]$results.Add((New-CheckResult -CheckId 'WEAK-PWD-POLICY' -Name 'Weak password policy' `
        -Description 'Domain password policy settings that fall below a defensible baseline.' `
        -AttackTechniques @('T1110') `
        -Recommendation 'Set a 14 character minimum, enable complexity and lockout, and never enable reversible encryption.' `
        -Findings $findings))

    $results.ToArray()
}
