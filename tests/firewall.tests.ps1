$ErrorActionPreference = 'Stop'
. "$(Split-Path $PSScriptRoot -Parent)\setup-firewall.ps1"
$script:rules = @()
$script:events = @()
$script:failCreate = 0
$script:created = 0
$script:failSave = $false
$script:enabled = $true
function Assert($Condition, $Message) { if (-not $Condition) { throw "FAIL: $Message" } }
function Get-GuardAdapters { @([pscustomobject]@{Name='Ethernet';InterfaceGuid='adapter-1'}) }
function Get-GuardInventory { [pscustomobject]@{Programs=@('C:\Claude\claude.exe');Packages=@([pscustomobject]@{Sid='S-1-15-2-123'});CliPath='C:\Claude\claude.exe'} }
function Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore)
    1..3 | ForEach-Object { [pscustomobject]@{Enabled=$script:enabled;AllowLocalFirewallRules='NotConfigured'} }
}
function Get-NetFirewallRule { [CmdletBinding()]param($Name,$PolicyStore)
    @($script:rules | Where-Object { -not $Name -or $_.Name -like $Name })
}
function New-NetFirewallRule { [CmdletBinding()]param($Name,$DisplayName,$Direction,$Action,$Profile,$InterfaceAlias,$Enabled,$PolicyStore,$Program,$Package)
    $script:created++
    if ($script:failCreate -eq $script:created) { throw 'Injected provider error' }
    Assert (-not $Package -or $Package -like 'S-1-*') 'package filter must be SID'
    $script:events += "create:$Name"
    $script:rules += [pscustomobject]@{Name=$Name;Enabled=$Enabled;Direction=$Direction;Action=$Action;Profile=$Profile;PrimaryStatus='OK';EnforcementStatus='Full';Program=$(if($Program){$Program}else{'Any'});Package=$(if($Package){$Package}else{'Any'});Alias=$InterfaceAlias}
}
function Remove-NetFirewallRule { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { $script:events += "remove:$($InputObject.Name)"; $script:rules = @($script:rules | Where-Object Name -ne $InputObject.Name) }
}
function Get-NetFirewallApplicationFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { [pscustomobject]@{Program=$InputObject.Program;Package=$InputObject.Package} }
}
function Get-NetFirewallInterfaceFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { [pscustomobject]@{InterfaceAlias=@($InputObject.Alias)} }
}
function Get-NetFirewallPortFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { [pscustomobject]@{Protocol='Any';LocalPort='Any';RemotePort='Any'} }
}
function Get-NetFirewallAddressFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { [pscustomobject]@{LocalAddress='Any';RemoteAddress='Any'} }
}
function Get-NetFirewallServiceFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { [pscustomobject]@{Service='Any'} }
}
function Get-NetFirewallInterfaceTypeFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { [pscustomobject]@{InterfaceType='Any'} }
}
function Save-GuardFirewallState($State) {
    if ($script:failSave) { throw 'Injected persistence error' }
    Assert ($script:rules.Name -contains 'Claude-VPN-Guard-Block-old') 'old rules remain until state commit'
    $script:state = $State; $script:events += 'commit'
}
function Reset-Fixture {
    $script:rules=@([pscustomobject]@{Name='Claude-VPN-Guard-Block-old';Enabled='False';Direction='Outbound';Action='Block';Profile='Any';PrimaryStatus='OK';EnforcementStatus='Full';Program='C:\Claude\claude.exe';Package='Any';Alias='Ethernet'})
    $script:events=@(); $script:created=0; $script:failCreate=0; $script:failSave=$false
}
Reset-Fixture
$script:failCreate=2
try { Invoke-GuardFirewallSetup; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'partial setup must fail' }
Assert ($script:rules.Count -eq 1 -and $script:rules[0].Name -like '*-old') 'partial setup must retain old rules and remove partial generation'
Write-Host 'PASS: partial replacement retains previous protection'
Reset-Fixture; $script:failSave=$true
try { Invoke-GuardFirewallSetup; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'failed state write must fail setup' }
Assert ($script:rules.Count -eq 1 -and $script:rules[0].Name -like '*-old') 'failed persistence retains previous generation'
Write-Host 'PASS: state write failure rolls back new generation'
Reset-Fixture
Invoke-GuardFirewallSetup
Assert ($script:rules.Count -eq 2 -and $script:rules.Name -notcontains 'Claude-VPN-Guard-Block-old') 'successful swap removes previous generation'
Assert ($script:events.IndexOf('commit') -lt $script:events.IndexOf('remove:Claude-VPN-Guard-Block-old')) 'commit precedes old removal'
Write-Host 'PASS: complete effective generation is committed before removal'
$script:rules[0].Enabled='False'
try { Assert-GuardCoverage @(Get-GuardSpecifications (Get-GuardInventory) (Get-GuardAdapters)) @($script:state.Rules); throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'disabled rule must fail verification' }
Write-Host 'PASS: disabled program rule blocks verification'
$script:enabled=$false
try { Assert-GuardProfiles; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'disabled firewall must fail verification' }
Write-Host 'PASS: disabled firewall blocks verification'
$script:enabled=$true
$testDirectory=Join-Path $env:TEMP ('ClaudeGuardFirewallTest-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDirectory | Out-Null
function Get-GuardStatePath { Join-Path $testDirectory 'firewall-state.json' }
try {
    Reset-Fixture; Invoke-GuardFirewallSetup
    $script:state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Get-GuardStatePath) -Encoding UTF8
    $null=Get-GuardProtectionStatus
    function Get-GuardAdapters { @([pscustomobject]@{Name='Renamed Ethernet';InterfaceGuid='adapter-1'}) }
    try { Get-GuardProtectionStatus; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'adapter change blocks verification' }
    Write-Host 'PASS: new or renamed adapter blocks launch status'
    function Get-GuardAdapters { @([pscustomobject]@{Name='Ethernet';InterfaceGuid='adapter-1'}) }
    function Get-GuardInventory { [pscustomobject]@{Programs=@('C:\Claude\updated\claude.exe');Packages=@();CliPath=$null} }
    try { Get-GuardProtectionStatus; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'new executable blocks verification' }
    Write-Host 'PASS: application path change requires fresh setup'
    function Restore-GuardDnsConfiguration { throw 'Injected DNS conflict' }
    try { Invoke-GuardFirewallSetup -Uninstall; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'DNS conflict must fail uninstall' }
    Assert ($script:rules.Count -eq 2) 'DNS restore failure retains firewall rules'
    function Restore-GuardDnsConfiguration { $script:events += 'dns-restored' }
    Invoke-GuardFirewallSetup -Uninstall
    Assert ($script:rules.Count -eq 0) 'uninstall actually removes all Guard rules'
    Assert (-not (Test-Path -LiteralPath (Get-GuardStatePath))) 'uninstall removes firewall state after successful removal'
    Write-Host 'PASS: uninstall removes rules only after successful DNS restore'
} finally {
    if ((Split-Path $testDirectory -Parent) -eq $env:TEMP) { Remove-Item -LiteralPath $testDirectory -Recurse -Force }
}
