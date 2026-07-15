function New-AuditFinding {
    <#
    .SYNOPSIS
        Builds one normalized finding object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][ValidateSet('High', 'Medium', 'Low', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory)][ValidateSet('User', 'Computer', 'Group', 'Policy')][string]$ObjectType,
        [Parameter(Mandatory)][string]$Detail
    )

    [pscustomobject]@{
        CheckId    = $CheckId
        Severity   = $Severity
        ObjectName = $ObjectName
        ObjectType = $ObjectType
        Detail     = $Detail
    }
}
