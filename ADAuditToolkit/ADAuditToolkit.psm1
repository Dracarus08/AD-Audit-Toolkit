Set-StrictMode -Version Latest

$private = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue
$public = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue

foreach ($file in @($private) + @($public)) {
    if ($null -ne $file) {
        . $file.FullName
    }
}

Export-ModuleMember -Function 'Invoke-ADAudit'
