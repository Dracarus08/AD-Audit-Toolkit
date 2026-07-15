function Test-StaleUsers {
    [CmdletBinding()]
    param($Data, $Config, $PrivilegedSet)

    $now = Get-Date
    $cutoff = $now.AddDays(-1 * $Config.StaleUserDays)

    $findings = foreach ($u in @($Data.Users)) {
        if (-not $u.Enabled) { continue }

        $detail = $null
        if ($null -eq $u.LastLogonDate) {
            if ($u.WhenCreated -lt $cutoff) {
                $detail = "Never logged on. Created $($u.WhenCreated.ToString('yyyy-MM-dd'))."
            }
        }
        elseif ($u.LastLogonDate -lt $cutoff) {
            $days = [int]($now - $u.LastLogonDate).TotalDays
            $detail = "Last logon $($u.LastLogonDate.ToString('yyyy-MM-dd')). $days days ago."
        }

        if ($detail) {
            $severity = 'Medium'
            if ($PrivilegedSet.ContainsKey($u.SamAccountName)) { $severity = 'High' }
            New-AuditFinding -CheckId 'STALE-USERS' -Severity $severity -ObjectName $u.SamAccountName -ObjectType 'User' -Detail $detail
        }
    }

    New-CheckResult -CheckId 'STALE-USERS' `
        -Name 'Stale enabled user accounts' `
        -Description "Enabled accounts with no logon in $($Config.StaleUserDays) days. Nobody notices when an unused account starts authenticating, which is exactly why attackers pick them." `
        -AttackTechniques @('T1078 Valid Accounts') `
        -Recommendation 'Review each account with its owner. Disable and move to a quarantine OU. Automate this check on a schedule so drift cannot accumulate.' `
        -Findings $findings
}
