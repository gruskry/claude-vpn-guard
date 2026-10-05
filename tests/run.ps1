#Requires -Version 5.1
$ErrorActionPreference='Stop'
$shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$root=Split-Path $PSScriptRoot -Parent
foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter '*.ps1' -Recurse -File | Where-Object { $_.FullName -notmatch '\\Output\\' })) {
    $parseErrors=$null
    [Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$null,[ref]$parseErrors) | Out-Null
    if ($parseErrors.Count) { throw "PowerShell syntax error in $($file.Name): $parseErrors" }
}
foreach ($test in @('location.tests.ps1','firewall.tests.ps1','runtime.tests.ps1','entrypoint.tests.ps1','launch.tests.ps1','dns.tests.ps1','network.tests.ps1','refresh.tests.ps1','privacy.tests.ps1','discovery.tests.ps1','diagnostics.tests.ps1','shutdown.tests.ps1')) {
    & $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot $test)
    if ($LASTEXITCODE -ne 0) { throw "Test suite failed: $test" }
}
Write-Host 'All isolated regression suites passed; no machine network settings were changed.'
