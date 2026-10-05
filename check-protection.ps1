#Requires -Version 5.1
param([switch]$Json)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
. "$PSScriptRoot\guard-common.ps1"
. "$PSScriptRoot\guard-privacy.ps1"
try {
    $status = Get-GuardProtectionStatus
    $message = "Effective block rules verified. VPN: $($status.Vpn.Name). Executables: $(@($status.Inventory.Programs).Count); blocked interfaces: $(@($status.Adapters).Count)."
    $privacy=try { Invoke-GuardPrivacy } catch { [pscustomobject]@{Error='Diagnostic scope could not be inspected.'} }
    $details=[pscustomobject]@{Ok=$true; Message=$message; Vpn=$status.Vpn.Name; Programs=@($status.Inventory.Programs); BlockedInterfaces=@($status.Adapters.Name); Privacy=$privacy; Limits='DNS service, local relays, external tools and VM networking require separate checks. Detection is not instantaneous.'}
    if ($Json) { $details | ConvertTo-Json -Depth 6 -Compress } else { $details | Format-List }
    exit 0
} catch {
    if ($Json) { [pscustomobject]@{Ok=$false; Message="$($_.Exception.Message)"} | ConvertTo-Json -Compress }
    else { Write-Error $_ -ErrorAction Continue }
    exit 1
}
