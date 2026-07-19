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

    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm')

    # severity distribution bar widths
    $barTotal = [double]($Summary.High + $Summary.Medium + $Summary.Low)
    if ($barTotal -le 0) { $barTotal = 1 }
    $hiW = [math]::Round(($Summary.High / $barTotal) * 100, 2)
    $medW = [math]::Round(($Summary.Medium / $barTotal) * 100, 2)
    $lowW = [math]::Round(($Summary.Low / $barTotal) * 100, 2)

    $verdict = switch ($Summary.Score) {
        { $_ -ge 80 } { 'Strong hygiene. Maintain current controls.'; break }
        { $_ -ge 60 } { 'Moderate hygiene. Prioritized remediation advised.'; break }
        { $_ -ge 40 } { 'Weak hygiene. Remediation advised.'; break }
        default { 'Poor hygiene. Immediate remediation advised.' }
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Active Directory Assessment</title>
<style>
  :root {
    --paper: #f4f1ea; --ink: #1c1b18; --muted: #6a655c; --faint: #938d81;
    --rule: #d8d1c3; --rule-soft: #e5e0d5; --stripe: #efebe1;
    --high: #a3302c; --med: #9a7220; --low: #4a6884; --ok: #3f7048;
    --serif: Georgia, 'Iowan Old Style', 'Times New Roman', serif;
    --sans: 'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono: 'Cascadia Mono', 'Consolas', 'DejaVu Sans Mono', monospace;
  }
  * { box-sizing: border-box; }
  body { font-family: var(--sans); margin: 0; background: var(--paper); color: var(--ink); -webkit-font-smoothing: antialiased; }
  .sheet { max-width: 940px; margin: 0 auto; padding: 52px 56px 72px; }

  .wordmark { font-family: var(--mono); font-size: 11.5px; letter-spacing: 2.5px; text-transform: uppercase; color: var(--muted); }
  .wordmark b { color: var(--high); font-weight: 700; }
  h1 { font-family: var(--serif); font-weight: 600; font-size: 31px; letter-spacing: -0.2px; margin: 6px 0 10px; }
  .meta { font-family: var(--mono); font-size: 12px; color: var(--muted); letter-spacing: .2px; }
  .rule-strong { border: none; border-top: 2px solid var(--ink); margin: 18px 0 0; }

  .summary { display: grid; grid-template-columns: 200px 1fr; gap: 40px; padding: 30px 0 6px; align-items: start; }
  .p-score { font-family: var(--serif); font-size: 56px; line-height: 1; font-weight: 600; }
  .p-score .outof { font-size: 24px; color: var(--faint); }
  .p-label { font-family: var(--mono); text-transform: uppercase; letter-spacing: 2px; font-size: 10.5px; color: var(--muted); margin-top: 8px; }
  .p-verdict { font-family: var(--serif); font-style: italic; font-size: 15px; color: var(--ink); margin-top: 12px; max-width: 220px; }

  .dist-head { display: flex; gap: 26px; font-family: var(--mono); font-size: 12px; color: var(--muted); margin-bottom: 10px; }
  .dist-head .n { color: var(--ink); font-weight: 700; }
  .dist-head .sq { display: inline-block; width: 9px; height: 9px; margin-right: 6px; vertical-align: baseline; }
  .bar { display: flex; height: 8px; width: 100%; overflow: hidden; border: 1px solid var(--rule); }
  .bar span { display: block; height: 100%; }
  .dist-total { font-family: var(--mono); font-size: 11.5px; color: var(--faint); margin-top: 8px; }

  .checks { margin-top: 20px; }
  .check { padding: 26px 0 4px; border-top: 1px solid var(--rule); }
  .check:first-child { border-top: 2px solid var(--ink); }
  .c-head { display: flex; align-items: baseline; gap: 14px; }
  .c-num { font-family: var(--serif); font-size: 20px; color: var(--faint); min-width: 30px; }
  .c-name { font-size: 16px; font-weight: 600; letter-spacing: .2px; flex: 1; }
  .c-attck { font-family: var(--mono); font-size: 11.5px; color: var(--muted); letter-spacing: .5px; }
  .c-count { font-family: var(--mono); font-size: 11.5px; color: var(--faint); margin-left: 14px; }
  .c-desc { color: var(--muted); font-size: 13.5px; margin: 8px 0 14px 44px; max-width: 640px; line-height: 1.5; }

  table { width: 100%; border-collapse: collapse; margin: 0 0 0 44px; font-family: var(--mono); font-size: 12.5px; }
  th { text-align: left; padding: 6px 12px 8px 0; color: var(--muted); font-weight: 400; font-size: 10.5px; text-transform: uppercase; letter-spacing: 1.5px; border-bottom: 1px solid var(--rule); }
  td { padding: 6px 12px 6px 0; border-bottom: 1px solid var(--rule-soft); vertical-align: top; }
  tbody tr:nth-child(even) td { background: var(--stripe); }
  .sev { white-space: nowrap; font-weight: 700; }
  .sev .sq { display: inline-block; width: 8px; height: 8px; margin-right: 7px; }
  .sev-high { color: var(--high); } .sev-medium { color: var(--med); } .sev-low { color: var(--low); } .sev-info { color: var(--muted); }
  .bg-high { background: var(--high); } .bg-medium { background: var(--med); } .bg-low { background: var(--low); }
  .rec { font-family: var(--serif); font-style: italic; font-size: 13.5px; color: var(--ink); margin: 14px 0 2px 44px; max-width: 660px; line-height: 1.5; }
  .rec b { font-style: normal; font-variant: small-caps; letter-spacing: .5px; color: var(--muted); }
  .clean { margin: 4px 0 6px 44px; font-family: var(--mono); font-size: 12.5px; color: var(--ok); }

  footer { margin-top: 44px; padding-top: 14px; border-top: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; color: var(--faint); letter-spacing: .3px; }
</style>
</head>
<body>
<div class="sheet">
<header>
  <div class="wordmark">AD-Audit-Toolkit <b>&bull;</b> v1.0.0</div>
  <h1>Active Directory Assessment</h1>
  <div class="meta">$(ConvertTo-HtmlEncoded $Summary.Domain) &nbsp;&middot;&nbsp; $(ConvertTo-HtmlEncoded $Summary.Source) &nbsp;&middot;&nbsp; generated $generated</div>
  <hr class="rule-strong">
</header>

<section class="summary">
  <div>
    <div class="p-score">$($Summary.Score)<span class="outof">/100</span></div>
    <div class="p-label">Posture score</div>
    <div class="p-verdict">$verdict</div>
  </div>
  <div>
    <div class="dist-head">
      <span><span class="sq bg-high"></span>High <span class="n">$($Summary.High)</span></span>
      <span><span class="sq bg-medium"></span>Medium <span class="n">$($Summary.Medium)</span></span>
      <span><span class="sq bg-low"></span>Low <span class="n">$($Summary.Low)</span></span>
    </div>
    <div class="bar">
      <span class="bg-high" style="width:$hiW%"></span>
      <span class="bg-medium" style="width:$medW%"></span>
      <span class="bg-low" style="width:$lowW%"></span>
    </div>
    <div class="dist-total">$($Summary.TotalFindings) findings across $(@($CheckResults).Count) checks</div>
  </div>
</section>

<div class="checks">
"@)

    $idx = 0
    foreach ($check in $CheckResults) {
        $idx++
        $num = '{0:D2}' -f $idx
        $count = $check.FindingCount
        $attck = if ($check.AttackTechniques.Count -gt 0) { ConvertTo-HtmlEncoded ($check.AttackTechniques -join ', ') } else { '' }
        $countLabel = if ($count -eq 1) { '1 finding' } else { "$count findings" }

        [void]$sb.Append("<div class=`"check`"><div class=`"c-head`"><span class=`"c-num`">$num</span><span class=`"c-name`">$(ConvertTo-HtmlEncoded $check.Name)</span>")
        if ($attck) { [void]$sb.Append("<span class=`"c-attck`">$attck</span>") }
        [void]$sb.Append("<span class=`"c-count`">$countLabel</span></div>")
        [void]$sb.Append("<p class=`"c-desc`">$(ConvertTo-HtmlEncoded $check.Description)</p>")

        if ($count -eq 0) {
            [void]$sb.Append("<div class=`"clean`">No findings. Check passed.</div>")
        }
        else {
            [void]$sb.Append("<table><thead><tr><th>Severity</th><th>Object</th><th>Type</th><th>Detail</th></tr></thead><tbody>")
            foreach ($f in $check.Findings) {
                $sevClass = 'sev-' + $f.Severity.ToLower()
                $sqClass = 'bg-' + $f.Severity.ToLower()
                [void]$sb.Append("<tr><td class=`"sev $sevClass`"><span class=`"sq $sqClass`"></span>$(ConvertTo-HtmlEncoded $f.Severity)</td><td>$(ConvertTo-HtmlEncoded $f.ObjectName)</td><td>$(ConvertTo-HtmlEncoded $f.ObjectType)</td><td>$(ConvertTo-HtmlEncoded $f.Detail)</td></tr>")
            }
            [void]$sb.Append("</tbody></table>")
        }
        [void]$sb.Append("<p class=`"rec`"><b>Recommendation.</b> $(ConvertTo-HtmlEncoded $check.Recommendation)</p>")
        [void]$sb.Append("</div>")
    }

    [void]$sb.Append(@"
</div>
<footer>AD-Audit-Toolkit v1.0.0 &middot; read-only audit &middot; synthetic demonstration data &middot; no live directory was queried</footer>
</div>
</body>
</html>
"@)

    $sb.ToString() | Out-File -FilePath $Path -Encoding UTF8
    $Path
}
