function Test-InactivePrivilegedAccounts {
    [CmdletBinding()]
    param($Data, $Config, $PrivilegedSet)

    $now = Get-Date
    $cutoff = $now.AddDays(-1 * $Config.PrivilegedInactiveDays)

    $findings = foreach ($u in @($Data.Users)) {
        if (-not $PrivilegedSet.ContainsKey($u.SamAccountName)) { continue }

        if (-not $u.Enabled) {
            New-AuditFinding -CheckId 'PRIV-INACTIVE' -Severity 'High' -ObjectName $u.SamAccountName -ObjectType 'User' -Detail 'Disabled account still holds privileged group membership. Re-enabling it silently restores admin rights.'
            continue
        }

        if ($null -ne $u.LastLogonDate -and $u.LastLogonDate -lt $cutoff) {
            $days = [int]($now - $u.LastLogonDate).TotalDays
            New-AuditFinding -CheckId 'PRIV-INACTIVE' -Severity 'High' -ObjectName $u.SamAccountName -ObjectType 'User' -Detail "Privileged account with no logon in $days days."
        }
    }

    New-CheckResult -CheckId 'PRIV-INACTIVE' `
        -Name 'Inactive privileged accounts' `
        -Description "Privileged accounts that are disabled but still in the group, or silent for $($Config.PrivilegedInactiveDays) days. Unused admin credentials are the quietest path to domain compromise." `
        -AttackTechniques @('T1078.002 Valid Accounts: Domain Accounts') `
        -Recommendation 'Remove group membership before or with disablement. Review silent admin accounts with their owners and cut membership that is no longer needed.' `
        -Findings $findings
}
