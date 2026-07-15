function Test-OldPasswords {
    [CmdletBinding()]
    param($Data, $Config, $PrivilegedSet)

    $now = Get-Date
    $cutoff = $now.AddDays(-1 * $Config.OldPasswordDays)

    $findings = foreach ($u in @($Data.Users)) {
        if (-not $u.Enabled) { continue }
        if ($null -eq $u.PasswordLastSet) { continue }
        if ($u.PasswordLastSet -ge $cutoff) { continue }

        $days = [int]($now - $u.PasswordLastSet).TotalDays
        $severity = 'Low'
        if ($PrivilegedSet.ContainsKey($u.SamAccountName)) { $severity = 'Medium' }
        New-AuditFinding -CheckId 'OLD-PASSWORDS' -Severity $severity -ObjectName $u.SamAccountName -ObjectType 'User' -Detail "Password last set $($u.PasswordLastSet.ToString('yyyy-MM-dd')). $days days old."
    }

    New-CheckResult -CheckId 'OLD-PASSWORDS' `
        -Name 'Passwords older than the age threshold' `
        -Description "Enabled accounts whose password has not changed in $($Config.OldPasswordDays) days. Old passwords have had more chances to leak into breach corpuses and old file shares." `
        -AttackTechniques @('T1110 Brute Force', 'T1078 Valid Accounts') `
        -Recommendation 'Prioritize privileged accounts. Rotate through a managed process, not a mass-expiry event that trains users to increment a digit.' `
        -Findings $findings
}
