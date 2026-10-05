$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
if (Test-Path "$root\guard-network.ps1") { . "$root\guard-network.ps1" }
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$script:tunnel=[pscustomobject]@{Name='Tunnel';InterfaceGuid='{11111111-1111-1111-1111-111111111111}';ifIndex=4;HardwareInterface=$false;Status='Up';InterfaceDescription='WireGuard Tunnel'}
$script:physical=[pscustomobject]@{Name='Ethernet';InterfaceGuid='{22222222-2222-2222-2222-222222222222}';ifIndex=5;HardwareInterface=$true;Status='Up';InterfaceDescription='Ethernet'}
$script:virtual=[pscustomobject]@{Name='LAN VPN';InterfaceGuid='{33333333-3333-3333-3333-333333333333}';ifIndex=6;HardwareInterface=$false;Status='Up';InterfaceDescription='Virtual LAN adapter'}
$script:adapters=@($script:tunnel,$script:physical,$script:virtual)
$script:routeIndex=4
function Get-NetAdapter { [CmdletBinding()]param([switch]$IncludeHidden); $script:adapters }
$script:ipInterfaces=@(
    [pscustomobject]@{InterfaceIndex=4;AddressFamily='IPv4'},
    [pscustomobject]@{InterfaceIndex=4;AddressFamily='IPv6'},
    [pscustomobject]@{InterfaceIndex=5;AddressFamily='IPv4'},
    [pscustomobject]@{InterfaceIndex=6;AddressFamily='IPv4'}
)
$script:failIPDiscovery=$false
function Get-NetIPInterface { [CmdletBinding()]param($AddressFamily)
    if ($script:failIPDiscovery) { throw 'Injected IP interface provider failure' }
    @($script:ipInterfaces | Where-Object { -not $AddressFamily -or $_.AddressFamily -eq $AddressFamily })
}
function Find-NetRoute { [CmdletBinding()]param($RemoteIPAddress)
    [pscustomobject]@{InterfaceIndex=$script:routeIndex;IPAddress='10.0.0.2'}
    [pscustomobject]@{InterfaceIndex=$script:routeIndex;DestinationPrefix='0.0.0.0/0'}
}
Assert ([bool](Get-Command Get-GuardVpnAdapter -ErrorAction SilentlyContinue)) 'VPN discovery is available'
$vpn=Get-GuardVpnAdapter
Assert ($vpn.ifIndex -eq 4) 'select the internet tunnel, not another virtual LAN'
$blocked=@(Get-GuardBlockedAdapters $vpn)
Assert ($blocked.Count -eq 2 -and $blocked.ifIndex -contains 6) 'other virtual adapters are blocked too'
$script:adapters+=@(
    [pscustomobject]@{Name='WAN Miniport';InterfaceGuid='{44444444-4444-4444-4444-444444444444}';ifIndex=7;HardwareInterface=$false;Status='Up'},
    [pscustomobject]@{Name='IPv6 tunnel';InterfaceGuid='{55555555-5555-5555-5555-555555555555}';ifIndex=8;HardwareInterface=$false;Status='Up'},
    [pscustomobject]@{Name='Disconnected Wi-Fi';InterfaceGuid='{66666666-6666-6666-6666-666666666666}';ifIndex=9;HardwareInterface=$true;Status='Disconnected'}
)
$script:ipInterfaces+=@(
    [pscustomobject]@{InterfaceIndex=8;AddressFamily='IPv6'},
    [pscustomobject]@{InterfaceIndex=9;AddressFamily='IPv4'}
)
$blocked=@(Get-GuardBlockedAdapters $vpn)
Assert ($blocked.Count -eq 4 -and $blocked.ifIndex -notcontains 7) 'non-IP service devices do not break firewall setup'
Assert ($blocked.ifIndex -contains 8 -and $blocked.ifIndex -contains 9) 'IPv6-only and disconnected IP adapters retain coverage'
$script:ipInterfaces+=[pscustomobject]@{InterfaceIndex=7;AddressFamily='IPv4'}
Assert (@(Get-GuardBlockedAdapters $vpn).ifIndex -contains 7) 'a device acquiring an IP interface requires coverage on the next check'
$script:failIPDiscovery=$true
try { Get-GuardBlockedAdapters $vpn; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'IP interface discovery failure must fail closed' }
$script:failIPDiscovery=$false
$savedInterfaces=$script:ipInterfaces
$script:ipInterfaces=@($savedInterfaces | Where-Object InterfaceIndex -ne 4)
try { Get-GuardBlockedAdapters $vpn; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'a vanished VPN IP interface must fail closed' }
$script:ipInterfaces=$savedInterfaces
Write-Host 'PASS: service-device exclusion, IPv6/disconnected coverage, newly exposed IP interface and discovery failures'
$script:routeIndex=5
try { Get-GuardVpnAdapter; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'direct physical route refuses automatic VPN detection' }
$script:routeIndex=6
try { Get-GuardVpnAdapter; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'unknown virtual driver is not trusted as a VPN' }
$script:routeIndex=4; $script:tunnel.Status='Disconnected'
try { Get-GuardVpnAdapter $script:tunnel.InterfaceGuid; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'pinned VPN disconnect blocks verification' }
$script:tunnel.Status='Up'
$script:routeIndex=6
try { Get-GuardVpnAdapter $script:tunnel.InterfaceGuid; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'route change cannot silently repin the trusted VPN' }
Write-Host 'PASS: automatic VPN discovery, virtual interface isolation, disconnect and route change'
$script:weakHost='Disabled'
function Get-NetIPInterface { [CmdletBinding()]param($AddressFamily); [pscustomobject]@{InterfaceIndex=5;WeakHostSend=$script:weakHost} }
function Get-NetIPAddress { [CmdletBinding()]param($InterfaceIndex,$AddressFamily); [pscustomobject]@{IPAddress='10.0.0.2';AddressState='Preferred';SkipAsSource=$false} }
Assert ((Get-GuardVpnSourceAddress $script:tunnel) -eq '10.0.0.2') 'probe source belongs to the VPN'
$script:weakHost='Enabled'
try { Get-GuardVpnSourceAddress $script:tunnel; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'weak-host fallback outside the VPN blocks location probing' }
$script:weakHost='Disabled'
$originalProxy=$env:HTTPS_PROXY
try {
    $env:HTTPS_PROXY='http://127.0.0.1:1234'
    try { Assert-GuardNoProxy; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'proxy environment blocks launch' }
} finally { $env:HTTPS_PROXY=$originalProxy }
Write-Host 'PASS: bound VPN source, weak-host rejection and configured proxy rejection'
$watchDirectory=Join-Path $env:TEMP ('ClaudeGuardWatcherTest-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $watchDirectory | Out-Null
$monitor=$null
try {
    Assert ([bool](Get-Command New-GuardChangeMonitor -ErrorAction SilentlyContinue)) 'change notifications are available'
    $monitor=New-GuardChangeMonitor ([pscustomobject]@{Programs=@((Join-Path $watchDirectory 'Claude.exe'))})
    $null=$monitor.Consume()
    [IO.File]::WriteAllText((Join-Path $watchDirectory 'Claude.exe'),'new executable')
    $deadline=[DateTime]::UtcNow.AddSeconds(3); $detected=$false
    while ([DateTime]::UtcNow -lt $deadline) { if ($monitor.Consume()) { $detected=$true; break }; Start-Sleep -Milliseconds 50 }
    Assert $detected 'actual executable creation wakes the supervisor'
    Write-Host 'PASS: real filesystem executable-change notification'
} finally {
    if ($monitor) { $monitor.Dispose() }
    if ((Split-Path $watchDirectory -Parent) -eq $env:TEMP) { Remove-Item -LiteralPath $watchDirectory -Recurse -Force }
}
