$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
# Load only the location function on older releases; never execute their launcher.
if (Test-Path "$root\guard-runtime.ps1") { . "$root\guard-runtime.ps1" }
else {
    $ast = [Management.Automation.Language.Parser]::ParseFile("$root\sync-guard.ps1", [ref]$null, [ref]$null)
    $function = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-PublicIPLocation' }, $true)
    Invoke-Expression $function.Extent.Text
}
$script:responses = @()
$script:index = 0
function Invoke-RestMethod { param($Uri, $TimeoutSec, $Headers, $ErrorAction)
    $response = $script:responses[$script:index % $script:responses.Count]
    $script:index++
    if ($response -is [Exception]) { throw $response }
    return $response
}
$failed = 0
function Check-Location($name, $responses, $country) {
    $script:responses = $responses; $script:index = 0
    $actual = Get-PublicIPLocation
    if (($null -eq $country -and $null -ne $actual) -or ($null -ne $country -and $actual.CountryCode -ne $country)) {
        $script:failed++; Write-Host "FAIL: $name" -ForegroundColor Red
    } else { Write-Host "PASS: $name" }
}
Check-Location 'reject missing IP' @([pscustomobject]@{country_code='GE'}) $null
Check-Location 'reject invalid IP' @([pscustomobject]@{country_code='GE';ip='not-an-IP'}) $null
Check-Location 'reject unknown country code' @([pscustomobject]@{country_code='ZZ';ip='8.8.8.8'}) $null
Check-Location 'MyIP uses ISO cc, not full country name' @([pscustomobject]@{country='Belarus';cc='BY';ip='8.8.8.8'}) 'BY'
Check-Location 'reject API error payload' @([pscustomobject]@{country_code='GE';ip='8.8.8.8';error=$true}) $null
Check-Location 'do not combine incomplete endpoint responses' @([pscustomobject]@{country_code='GE'}, [pscustomobject]@{ip='8.8.8.8'}) $null
Check-Location 'valid IPv4 response' @([pscustomobject]@{country_code='ge';ip='8.8.8.8';timezone='Asia/Tbilisi'}) 'GE'
Check-Location 'valid IPv6 response' @([pscustomobject]@{country='GE';ip='2606:4700:4700::1111'}) 'GE'
Check-Location 'fallback after endpoint failure' @([Exception]::new('offline'), [pscustomobject]@{country='DE';ip='8.8.4.4'}) 'DE'
if ($failed) { throw "$failed location regression(s)" }
