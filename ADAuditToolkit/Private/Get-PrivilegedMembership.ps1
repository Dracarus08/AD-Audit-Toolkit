$script:PrivilegedGroupNames = @(
    'Administrators'
    'Domain Admins'
    'Enterprise Admins'
    'Schema Admins'
    'Account Operators'
    'Backup Operators'
    'Server Operators'
    'Print Operators'
)

function Get-ResolvedGroupMembers {
    <#
    .SYNOPSIS
        Resolves a group's membership to user names, walking nested groups.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data,
        [Parameter(Mandatory)][string]$GroupName
    )

    $groupIndex = @{}
    foreach ($g in @($Data.Groups)) {
        $groupIndex[$g.Name] = $g
    }

    $users = @{}
    $seen = @{}
    $queue = New-Object System.Collections.Queue

    if ($groupIndex.ContainsKey($GroupName)) {
        $queue.Enqueue($GroupName)
    }

    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        if ($seen.ContainsKey($current)) { continue }
        $seen[$current] = $true

        foreach ($member in @($groupIndex[$current].Members)) {
            if ($null -eq $member) { continue }
            if ($groupIndex.ContainsKey($member)) {
                $queue.Enqueue($member)
            }
            else {
                $users[$member] = $true
            }
        }
    }

    @($users.Keys)
}

function Get-PrivilegedUserSet {
    <#
    .SYNOPSIS
        Returns a hashtable set of every user holding membership in a privileged group.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data
    )

    $set = @{}
    foreach ($groupName in $script:PrivilegedGroupNames) {
        foreach ($member in Get-ResolvedGroupMembers -Data $Data -GroupName $groupName) {
            $set[$member] = $true
        }
    }
    $set
}
