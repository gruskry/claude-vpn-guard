#Requires -Version 5.1
#Requires -RunAsAdministrator
# Real firewall-provider smoke test, scoped exclusively to a temporary probe EXE.
# Does not change Claude rules, DNS, timezone, VPN connection or routing.
param([switch]$CheckBoundLocation)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. "$root\setup-firewall.ps1"
$probeDirectory=Join-Path $env:TEMP ('ClaudeGuardLivePolicy-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $probeDirectory | Out-Null
$script:GuardRulePrefix='ClaudeGuard-LiveProbe-'+[guid]::NewGuid().ToString('N')
$probeExe=Join-Path $probeDirectory 'Probe.exe'
try {
    $probeSource=Join-Path $probeDirectory 'Probe.cs'
    'class Probe { static int Main() { return 0; } }' | Set-Content -LiteralPath $probeSource -Encoding UTF8
    & "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:exe "/out:$probeExe" $probeSource
    if ($LASTEXITCODE -ne 0) { throw 'Probe compilation failed.' }
    function Get-GuardInventory { [pscustomobject]@{Programs=@($probeExe);Packages=@();DesktopPaths=@();CliPath=$null} }
    function Get-GuardStatePath { Join-Path $probeDirectory 'unused-state.json' }
    function Save-GuardFirewallState($State) { $script:probeState=$State }
    Invoke-GuardFirewallSetup
    $vpn=Get-GuardVpnAdapter $script:probeState.VpnGuid
    Write-Host "PASS: real effective firewall filters verified for $(@($script:probeState.Adapters).Count) untrusted interfaces; VPN: $($vpn.Name)."
    if ($CheckBoundLocation) {
        $source=Get-GuardVpnSourceAddress $vpn
        $response=Invoke-GuardBoundLocationRequest 'https://api.myip.com' $source $vpn.ifIndex
        if (-not $response.ip -or -not $response.cc) { throw 'Bound location response is incomplete.' }
        Write-Host 'PASS: HTTPS location request bound to the detected VPN IPv4 source; no address printed or saved.'
    }
} finally {
    foreach ($rule in @(Get-GuardRules)) { $rule | Remove-NetFirewallRule -ErrorAction Stop }
    if (@(Get-GuardRules).Count) { throw 'Temporary probe filters remain; remove ClaudeGuard-LiveProbe rules before deleting the probe executable.' }
    if ((Split-Path $probeDirectory -Parent) -eq $env:TEMP) { Remove-Item -LiteralPath $probeDirectory -Recurse -Force }
}
