function Test-PasswordNeverExpires {
    [CmdletBinding()]
    param($Data, $Config, $PrivilegedSet)

    $findings = foreach ($u in @($Data.Users)) {
        if (-not $u.Enabled) { continue }
        if (-not $u.PasswordNeverExpires) { continue }

        $severity = 'Medium'
        $detail = 'Password is set to never expire.'
        if ($PrivilegedSet.ContainsKey($u.SamAccountName)) {
            $severity = 'High'
            $detail = 'Password is set to never expire on a privileged account.'
        }
        New-AuditFinding -CheckId 'PWD-NEVER-EXPIRES' -Severity $severity -ObjectName $u.SamAccountName -ObjectType 'User' -Detail $detail
    }

    New-CheckResult -CheckId 'PWD-NEVER-EXPIRES' `
        -Name 'Passwords set to never expire' `
        -Description 'Accounts exempt from password rotation. A credential stolen from one of these stays valid until someone notices.' `
        -AttackTechniques @('T1078 Valid Accounts', 'T1110 Brute Force') `
        -Recommendation 'Move real service workloads to group Managed Service Accounts. For human accounts, remove the flag and let policy apply.' `
        -Findings $findings
}
