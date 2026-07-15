function Out-HtmlReport {
    <#
    .SYNOPSIS
        Renders check results into a self-contained HTML report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Summary,
        [Parameter(Mandatory)]$CheckResults,
        [Parameter(Mandatory)][string]$Path
    )

    $sevColors = @{ High = '#e5484d'; Medium = '#f5a623'; Low = '#4a90d9'; Info = '#8a8f98' }
    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm')

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AD Audit Report</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; background: #0f1115; color: #e6e6e6; }
  .wrap { max-width: 1000px; margin: 0 auto; padding: 32px 20px 64px; }
  header h1 { margin: 0 0 4px; font-size: 24px; }
  header .meta { color: #9aa0a6; font-size: 13px; margin-bottom: 24px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 28px; }
  .card { background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 16px; }
  .card .num { font-size: 30px; font-weight: 700; line-height: 1; }
  .card .lbl { font-size: 12px; color: #9aa0a6; margin-top: 6px; text-transform: uppercase; letter-spacing: .5px; }
  .score { font-size: 30px; font-weight: 700; }
  .check { background: #171a21; border: 1px solid #262b36; border-radius: 10px; margin-bottom: 16px; overflow: hidden; }
  .check h2 { font-size: 16px; margin: 0; padding: 14px 18px; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid #262b36; }
  .pill { font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 20px; color: #fff; }
  .check .body { padding: 14px 18px; }
  .check .desc { color: #b9bec5; font-size: 13px; margin: 0 0 10px; }
  .check .rec { color: #9aa0a6; font-size: 13px; margin: 10px 0 0; }
  .attck { font-size: 11px; color: #7d8590; }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }
  th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #21262e; }
  th { color: #9aa0a6; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .5px; }
  .sev { font-weight: 700; }
  .clean { color: #3fb950; font-size: 13px; padding: 4px 0; }
  footer { margin-top: 32px; color: #6e7681; font-size: 12px; border-top: 1px solid #262b36; padding-top: 16px; }
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>Active Directory Audit Report</h1>
  <div class="meta">Domain: $(ConvertTo-HtmlEncoded $Summary.Domain) &nbsp;|&nbsp; Source: $(ConvertTo-HtmlEncoded $Summary.Source) &nbsp;|&nbsp; Generated: $generated</div>
</header>
<div class="cards">
  <div class="card"><div class="num" style="color:$($sevColors.High)">$($Summary.High)</div><div class="lbl">High</div></div>
  <div class="card"><div class="num" style="color:$($sevColors.Medium)">$($Summary.Medium)</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="num" style="color:$($sevColors.Low)">$($Summary.Low)</div><div class="lbl">Low</div></div>
  <div class="card"><div class="num">$($Summary.TotalFindings)</div><div class="lbl">Total findings</div></div>
  <div class="card"><div class="score" style="color:$($Summary.ScoreColor)">$($Summary.Score)/100</div><div class="lbl">Hygiene score</div></div>
</div>
"@)

    foreach ($check in $CheckResults) {
        $count = $check.FindingCount
        $topSev = 'Info'
        if ($count -gt 0) {
            $order = @('High', 'Medium', 'Low', 'Info')
            foreach ($s in $order) {
                if (@($check.Findings | Where-Object { $_.Severity -eq $s }).Count -gt 0) { $topSev = $s; break }
            }
        }
        $pillColor = $sevColors[$topSev]
        $attck = if ($check.AttackTechniques.Count -gt 0) { 'ATT&amp;CK: ' + (ConvertTo-HtmlEncoded ($check.AttackTechniques -join ', ')) } else { '' }

        [void]$sb.Append("<div class=`"check`"><h2><span class=`"pill`" style=`"background:$pillColor`">$count</span>$(ConvertTo-HtmlEncoded $check.Name)</h2><div class=`"body`">")
        [void]$sb.Append("<p class=`"desc`">$(ConvertTo-HtmlEncoded $check.Description)</p>")
        if ($attck) { [void]$sb.Append("<div class=`"attck`">$attck</div>") }

        if ($count -eq 0) {
            [void]$sb.Append("<div class=`"clean`">No findings. This check passed.</div>")
        }
        else {
            [void]$sb.Append("<table><thead><tr><th>Severity</th><th>Object</th><th>Type</th><th>Detail</th></tr></thead><tbody>")
            foreach ($f in $check.Findings) {
                $c = $sevColors[$f.Severity]
                [void]$sb.Append("<tr><td class=`"sev`" style=`"color:$c`">$(ConvertTo-HtmlEncoded $f.Severity)</td><td>$(ConvertTo-HtmlEncoded $f.ObjectName)</td><td>$(ConvertTo-HtmlEncoded $f.ObjectType)</td><td>$(ConvertTo-HtmlEncoded $f.Detail)</td></tr>")
            }
            [void]$sb.Append("</tbody></table>")
        }
        [void]$sb.Append("<p class=`"rec`"><strong>Recommendation.</strong> $(ConvertTo-HtmlEncoded $check.Recommendation)</p>")
        [void]$sb.Append("</div></div>")
    }

    [void]$sb.Append(@"
<footer>
Generated by AD-Audit-Toolkit. Read-only audit. This report is built through my automated development pipeline, designed, reviewed, and operated by me.
</footer>
</div>
</body>
</html>
"@)

    $sb.ToString() | Out-File -FilePath $Path -Encoding UTF8
    $Path
}
