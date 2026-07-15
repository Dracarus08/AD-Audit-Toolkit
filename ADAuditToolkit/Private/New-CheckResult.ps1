function New-CheckResult {
    <#
    .SYNOPSIS
        Wraps a check's findings with its metadata.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Description,
        [string[]]$AttackTechniques = @(),
        [Parameter(Mandatory)][string]$Recommendation,
        $Findings
    )

    $clean = @(@($Findings) | Where-Object { $null -ne $_ })

    [pscustomobject]@{
        CheckId          = $CheckId
        Name             = $Name
        Description      = $Description
        AttackTechniques = $AttackTechniques
        Recommendation   = $Recommendation
        Findings         = $clean
        FindingCount     = $clean.Count
    }
}
