function Test-PrivilegedGroupSprawl {
    [CmdletBinding()]
    param($Data, $Config, $PrivilegedSet)

    $findings = foreach ($groupName in $Config.PrivilegedGroupThresholds.Keys) {
        $threshold = $Config.PrivilegedGroupThresholds[$groupName]
        $members = @(Get-ResolvedGroupMembers -Data $Data -GroupName $groupName)
        if ($members.Count -le $threshold) { continue }

        $sample = ($members | Sort-Object | Select-Object -First 10) -join ', '
        New-AuditFinding -CheckId 'PRIV-SPRAWL' -Severity 'High' -ObjectName $groupName -ObjectType 'Group' -Detail "$($members.Count) effective members. Threshold is $threshold. Includes nested membership. Members: $sample"
    }

    New-CheckResult -CheckId 'PRIV-SPRAWL' `
        -Name 'Privileged group sprawl' `
        -Description 'Privileged groups whose effective membership, including nesting, exceeds a sane ceiling. Every extra member is another credential that hands over the domain.' `
        -AttackTechniques @('T1078.002 Valid Accounts: Domain Accounts', 'T1098 Account Manipulation') `
        -Recommendation 'Empty the group down to break-glass and true admin accounts. Grant task rights through delegation instead of Tier 0 membership. Watch nested groups. They hide sprawl from casual review.' `
        -Findings $findings
}
