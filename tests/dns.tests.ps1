$ErrorActionPreference='Stop'
. "$(Split-Path $PSScriptRoot -Parent)\enable-dns-leak-protection.ps1"
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$testDirectory=Join-Path $env:TEMP ('ClaudeGuardDnsTest-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$script:DnsStateDirectory=$testDirectory
$script:DnsStatePath=Join-Path $testDirectory 'dns-state.json'
$script:adapter=[pscustomobject]@{Name='Renamed Ethernet';InterfaceGuid='12345678-1234-1234-1234-123456789012';ifIndex=7}
function Reset-Fixture {
    $script:dns=@{4=[pscustomobject]@{Automatic=$true;Servers=@('9.9.9.9')};6=[pscustomobject]@{Automatic=$false;Servers=@('2001:db8::53','2001:db8::54')}}
    $script:templates=@{'1.1.1.1'=[pscustomobject]@{ServerAddress='1.1.1.1';DohTemplate='https://original.example/dns-query';AutoUpgrade=$false;AllowFallbackToUdp=$true}}
    $script:failSetFamily=0; $script:failRestoreFamily=0; $script:noAdapters=$false; $script:setCalls=0
    if (Test-Path -LiteralPath $script:DnsStatePath) { Remove-Item -LiteralPath $script:DnsStatePath -Force }
}
function Get-GuardAdapters { if (-not $script:noAdapters) { $script:adapter } }
function Get-DnsDhcpMode($Guid,$Family) { $script:dns[[int]$Family].Automatic }
function Write-DnsState($State) { $State | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $script:DnsStatePath -Encoding UTF8 }
function Get-DnsClientServerAddress { [CmdletBinding()]param($InterfaceIndex,[ValidateSet('IPv4','IPv6')][string]$AddressFamily)
    $family=if($AddressFamily -eq 'IPv4'){4}else{6}
    [pscustomobject]@{InterfaceIndex=$InterfaceIndex;Family=$family;ServerAddresses=$script:dns[$family].Servers}
}
function Set-DnsClientServerAddress { [CmdletBinding()]param($InputObject,$ServerAddresses,[switch]$ResetServerAddresses,[switch]$Confirm)
    Assert ($InputObject.InterfaceIndex -eq 7) 'DNS changes use stable current interface index'
    $family=$InputObject.Family
    if ($family -eq $script:failSetFamily -and -not $ResetServerAddresses) { $script:failSetFamily=0; throw 'Injected family setup failure' }
    if ($family -eq $script:failRestoreFamily -and $ResetServerAddresses) { throw 'Injected family restore failure' }
    $script:setCalls++
    if ($ResetServerAddresses) { $script:dns[$family]=[pscustomobject]@{Automatic=$true;Servers=@('9.9.9.9')} }
    else {
        foreach ($server in $ServerAddresses) {
            $version=([Net.IPAddress]::Parse($server)).AddressFamily
            Assert (($family -eq 4 -and "$version" -eq 'InterNetwork') -or ($family -eq 6 -and "$version" -eq 'InterNetworkV6')) 'DNS servers match the requested family'
        }
        $script:dns[$family]=[pscustomobject]@{Automatic=$false;Servers=@($ServerAddresses)}
    }
}
function Get-DnsClientDohServerAddress { [CmdletBinding()]param(); $script:templates.Values }
function Set-DnsClientDohServerAddress { [CmdletBinding()]param($ServerAddress,$DohTemplate,$AutoUpgrade,$AllowFallbackToUdp,[switch]$Confirm)
    Assert ($Confirm -eq $false) 'DoH modification does not prompt'
    Assert ($script:templates.ContainsKey($ServerAddress)) 'Set changes an existing template'
    $script:templates[$ServerAddress]=[pscustomobject]@{ServerAddress=$ServerAddress;DohTemplate=$DohTemplate;AutoUpgrade=$AutoUpgrade;AllowFallbackToUdp=$AllowFallbackToUdp}
}
function Add-DnsClientDohServerAddress { [CmdletBinding()]param($ServerAddress,$DohTemplate,$AutoUpgrade,$AllowFallbackToUdp,[switch]$Confirm)
    Assert (-not $script:templates.ContainsKey($ServerAddress)) 'Add creates only a missing template'
    $script:templates[$ServerAddress]=[pscustomobject]@{ServerAddress=$ServerAddress;DohTemplate=$DohTemplate;AutoUpgrade=$AutoUpgrade;AllowFallbackToUdp=$AllowFallbackToUdp}
}
function Remove-DnsClientDohServerAddress { [CmdletBinding()]param($ServerAddress,[switch]$Confirm); $script:templates.Remove($ServerAddress) }
try {
    Reset-Fixture
    Assert ((Invoke-DnsMain) -eq 0) 'complete DNS setup succeeds'
    Assert ($script:templates.Count -eq 8) 'all IPv4 and IPv6 DoH templates exist'
    Assert (-not $script:dns[4].Automatic -and -not $script:dns[6].Automatic) 'both families have static encrypted DNS servers'
    $saved=Get-Content -LiteralPath $script:DnsStatePath -Raw | ConvertFrom-Json
    Assert ($saved.Adapters[0].Families[0].Automatic) 'snapshot distinguishes automatic DNS from static DNS'
    Assert ($saved.Adapters[0].Families[1].Servers[0] -eq '2001:db8::53') 'static DNS order is preserved'
    try { Invoke-DnsMain; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'repeat enable refuses to overwrite original backup' }
    $script:adapter.Name='Another adapter name'
    Assert ((Invoke-DnsMain -RestoreMode) -eq 0) 'restore uses GUID after adapter rename'
    Assert ($script:dns[4].Automatic) 'IPv4 automatic DNS restored'
    Assert (Test-DnsServerList $script:dns[6].Servers @('2001:db8::53','2001:db8::54')) 'IPv6 static DNS and priority restored'
    Assert ($script:templates.Count -eq 1 -and $script:templates['1.1.1.1'].DohTemplate -eq 'https://original.example/dns-query') 'custom DoH template restored and added templates removed'
    Write-Host 'PASS: IPv4/IPv6, automatic/static, GUID rename, custom/missing DoH templates, repeat enable'
    Reset-Fixture; $script:failSetFamily=6
    try { Invoke-DnsMain; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'partial setup returns failure' }
    Assert ($script:dns[4].Automatic -and (Test-DnsServerList $script:dns[6].Servers @('2001:db8::53','2001:db8::54'))) 'partial failure rolls back changed family without touching untouched static family'
    Assert ($script:templates.Count -eq 1) 'partial failure rolls back all DoH templates'
    Assert (-not (Test-Path -LiteralPath $script:DnsStatePath)) 'complete rollback removes backup'
    Write-Host 'PASS: second-family failure rolls back actual orchestration'
    Reset-Fixture; $null=Invoke-DnsMain
    $script:dns[6]=[pscustomobject]@{Automatic=$false;Servers=@('2001:db8::99')}
    try { Invoke-DnsMain -RestoreMode; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'manual change makes restore incomplete' }
    Assert ($script:dns[6].Servers[0] -eq '2001:db8::99') 'manual DNS setting preserved'
    Assert ($script:dns[4].Automatic -and (Test-Path -LiteralPath $script:DnsStatePath)) 'other family restored and conflict backup retained'
    $script:dns[6]=[pscustomobject]@{Automatic=$false;Servers=$script:DnsServersV6}
    $null=Invoke-DnsMain -RestoreMode
    Assert (-not (Test-Path -LiteralPath $script:DnsStatePath)) 'retry handles already-restored family and templates'
    Write-Host 'PASS: manual conflicts preserve settings; restore is retryable'
    Reset-Fixture; $script:failSetFamily=6; $script:failRestoreFamily=4
    try { Invoke-DnsMain; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'rollback failure propagates' }
    Assert (Test-Path -LiteralPath $script:DnsStatePath) 'failed rollback retains original backup'
    Assert ($script:templates.Count -eq 1) 'failed adapter rollback does not prevent template rollback'
    $script:failRestoreFamily=0; $null=Invoke-DnsMain -RestoreMode
    Write-Host 'PASS: incomplete rollback retains recovery state and continues other components'
    Reset-Fixture; $script:noAdapters=$true
    try { Invoke-DnsMain; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'no adapters is a failure' }
    Assert ($script:setCalls -eq 0 -and $script:templates.Count -eq 1) 'no-adapter failure makes no DNS changes'
    Write-Host 'PASS: no adapters makes no changes'
} finally {
    if ((Split-Path $testDirectory -Parent) -eq $env:TEMP) { Remove-Item -LiteralPath $testDirectory -Recurse -Force }
}
