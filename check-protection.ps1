#Requires -Version 5.1
param([switch]$Json)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
. "$PSScriptRoot\guard-common.ps1"
try {
    $status = Get-GuardProtectionStatus
    $message = 'Effective firewall rules verified for current Claude executables and physical adapters.'
    if ($Json) { [pscustomobject]@{Ok=$true; Message=$message} | ConvertTo-Json -Compress } else { Write-Host $message }
    exit 0
} catch {
    if ($Json) { [pscustomobject]@{Ok=$false; Message="$($_.Exception.Message)"} | ConvertTo-Json -Compress }
    else { Write-Error $_ -ErrorAction Continue }
    exit 1
}
