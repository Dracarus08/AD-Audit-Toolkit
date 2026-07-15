function ConvertTo-HtmlEncoded {
    <#
    .SYNOPSIS
        Encodes text for safe placement inside HTML.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][AllowNull()][AllowEmptyString()][string]$Text
    )

    process {
        if ([string]::IsNullOrEmpty($Text)) { return '' }
        $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
    }
}
