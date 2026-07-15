function Test-KerberoastableAccounts {
    [CmdletBinding()]
    param($Data, $Config, $PrivilegedSet)

    $findings = foreach ($u in @($Data.Users)) {
        if (-not $u.Enabled) { continue }
        $spns = @($u.ServicePrincipalNames | Where-Object { $_ })
        if ($spns.Count -eq 0) { continue }

        $severity = 'Medium'
        $note = ''
        if ($PrivilegedSet.ContainsKey($u.SamAccountName)) {
            $severity = 'High'
            $note = ' This account is also privileged, so a cracked ticket is a domain compromise.'
        }
        New-AuditFinding -CheckId 'KERBEROASTABLE' -Severity $severity -ObjectName $u.SamAccountName -ObjectType 'User' -Detail "User account carries $($spns.Count) SPN(s), for example $($spns[0]). Any domain user can request a service ticket for it and crack the password offline.$note"
    }

    New-CheckResult -CheckId 'KERBEROASTABLE' `
        -Name 'Kerberoastable user accounts' `
        -Description 'User accounts with service principal names. Their service tickets are encrypted with the account password hash, and any authenticated user can request one to attack offline.' `
        -AttackTechniques @('T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting') `
        -Recommendation 'Replace with group Managed Service Accounts where possible. Where not, use 25 plus character random passwords and never nest these accounts in privileged groups.' `
        -Findings $findings
}
