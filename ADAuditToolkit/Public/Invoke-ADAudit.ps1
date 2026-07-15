function Invoke-ADAudit {
    <#
    .SYNOPSIS
        Audits Active Directory hygiene and produces a scored HTML report.
    .DESCRIPTION
        Runs ten read-only identity security checks against a live domain or the
        bundled synthetic dataset. Nothing in this module writes to Active Directory.
    .PARAMETER Demo
        Use the bundled synthetic dataset instead of a live domain. Needs no RSAT and no domain.
    .PARAMETER Server
        Target a specific domain controller in live mode.
    .PARAMETER OutputPath
        Where to write the HTML report. Defaults to a timestamped file in the current directory.
    .PARAMETER PassThru
        Return the result object in addition to writing the report.
    .EXAMPLE
        Invoke-ADAudit -Demo
        Runs against the synthetic dataset and opens a report you can review in seconds.
    .EXAMPLE
        Invoke-ADAudit -OutputPath C:\Reports\ad.html
        Audits the current domain and writes the report to the given path.
    #>
    [CmdletBinding()]
    param(
        [switch]$Demo,
        [string]$Server,
        [string]$OutputPath,
        [switch]$PassThru
    )

    if ($Demo) {
        Write-Verbose 'Loading synthetic demo dataset.'
        $data = Get-AuditDataFromDemo
    }
    else {
        Write-Verbose 'Collecting from live domain.'
        $data = Get-AuditDataFromDomain -Server $Server
    }

    $checkResults = Invoke-AuditChecks -Data $data

    $allFindings = @($checkResults | ForEach-Object { $_.Findings })
    $high = @($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $medium = @($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $low = @($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $total = $allFindings.Count

    # Hygiene score is a maturity view across the ten control categories, not a raw
    # finding count. Each check is worth ten points. A check loses points based on the
    # severity of its worst finding. This keeps the score readable even when one check
    # produces many findings.
    $checkCount = @($checkResults).Count
    $maxScore = $checkCount * 10
    $penalty = 0
    foreach ($c in $checkResults) {
        if ($c.FindingCount -eq 0) { continue }
        if (@($c.Findings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) { $penalty += 10 }
        elseif (@($c.Findings | Where-Object { $_.Severity -eq 'Medium' }).Count -gt 0) { $penalty += 6 }
        else { $penalty += 3 }
    }
    $score = if ($maxScore -gt 0) { [int][Math]::Round(100 * ($maxScore - $penalty) / $maxScore) } else { 100 }
    $score = [Math]::Max(0, $score)
    $scoreColor = if ($score -ge 80) { '#3fb950' } elseif ($score -ge 50) { '#f5a623' } else { '#e5484d' }

    $summary = [pscustomobject]@{
        Domain        = $data.Domain.Name
        Source        = $data.Source
        High          = $high
        Medium        = $medium
        Low           = $low
        TotalFindings = $total
        Score         = $score
        ScoreColor    = $scoreColor
        UserCount     = @($data.Users).Count
        ComputerCount = @($data.Computers).Count
    }

    if (-not $OutputPath) {
        $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $OutputPath = Join-Path (Get-Location).Path "ADAuditReport-$stamp.html"
    }
    $reportPath = Out-HtmlReport -Summary $summary -CheckResults $checkResults -Path $OutputPath

    Write-Host ''
    Write-Host '  AD Audit Complete' -ForegroundColor Cyan
    Write-Host "  Domain        : $($summary.Domain)"
    Write-Host "  Source        : $($summary.Source)"
    Write-Host "  Users         : $($summary.UserCount)    Computers: $($summary.ComputerCount)"
    Write-Host "  High          : $high" -ForegroundColor Red
    Write-Host "  Medium        : $medium" -ForegroundColor Yellow
    Write-Host "  Low           : $low" -ForegroundColor Blue
    Write-Host "  Hygiene score : $score/100"
    Write-Host "  Report        : $reportPath" -ForegroundColor Green
    Write-Host ''

    if ($PassThru) {
        [pscustomobject]@{
            Summary       = $summary
            Checks        = $checkResults
            ReportPath    = $reportPath
            TotalFindings = $total
        }
    }
}
