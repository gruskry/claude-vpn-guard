#Requires -Version 5.1
param([switch]$Json)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
# Dot-sourcing guard-privacy.ps1 rebinds its own -Json parameter in this scope.
$asJson=[bool]$Json
. "$PSScriptRoot\guard-common.ps1"
. "$PSScriptRoot\guard-privacy.ps1"
function Get-GuardAutoRefreshSummary {
    try {
        $path=Join-Path $env:ProgramData 'ClaudeVPNGuard\auto-refresh-status.json'
        if (-not (Test-Path -LiteralPath $path)) { return 'Automatic refresh after Claude updates: not running. Rerun setup-firewall.cmd to enable it.' }
        $data=Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $time=([DateTime]::Parse($data.Utc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)).ToLocalTime().ToString('g')
        if ($data.Ok -eq $true) { "Automatic refresh after Claude updates: last check $time succeeded." }
        else { "Automatic refresh after Claude updates: last check $time failed; it retries automatically." }
    } catch { 'Automatic refresh status could not be read.' }
}
try {
    $status = Get-GuardProtectionStatus
    $message = "Effective block rules verified. VPN: $($status.Vpn.Name). Executables: $(@($status.Inventory.Programs).Count); blocked interfaces: $(@($status.Adapters).Count). $(Get-GuardAutoRefreshSummary)"
    $privacy=try { Invoke-GuardPrivacy } catch { [pscustomobject]@{Error='Diagnostic scope could not be inspected.'} }
    $details=[pscustomobject]@{Ok=$true; Message=$message; Vpn=$status.Vpn.Name; Programs=@($status.Inventory.Programs); BlockedInterfaces=@($status.Adapters.Name); Privacy=$privacy; Limits='DNS service, local relays, external tools, WSL and other VM networking require separate checks. Detection is not instantaneous.'}
    if ($asJson) { $details | ConvertTo-Json -Depth 6 -Compress } else { $details | Format-List }
    exit 0
} catch {
    if ($asJson) { [pscustomobject]@{Ok=$false; Message="$($_.Exception.Message)"} | ConvertTo-Json -Compress }
    else { Write-Error $_ -ErrorAction Continue }
    exit 1
}
