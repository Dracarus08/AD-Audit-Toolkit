function Test-PasswordNotRequired {
    [CmdletBinding()]
    param($Data, $Config, $PrivilegedSet)

    $findings = foreach ($u in @($Data.Users)) {
        if (-not $u.PasswordNotRequired) { continue }

        $state = 'disabled'
        if ($u.Enabled) { $state = 'enabled' }
        New-AuditFinding -CheckId 'PWD-NOT-REQUIRED' -Severity 'High' -ObjectName $u.SamAccountName -ObjectType 'User' -Detail "PASSWD_NOTREQD flag is set on this $state account. The directory will accept an empty password."
    }

    New-CheckResult -CheckId 'PWD-NOT-REQUIRED' `
        -Name 'Accounts that do not require a password' `
        -Description 'The PASSWD_NOTREQD control flag lets an account hold a blank password regardless of policy. There is almost never a legitimate reason for it.' `
        -AttackTechniques @('T1078 Valid Accounts') `
        -Recommendation 'Clear the flag, set a strong password, and find out what created it. This flag usually arrives through scripted account provisioning.' `
        -Findings $findings
}
