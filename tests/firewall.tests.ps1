$ErrorActionPreference = 'Stop'
. "$(Split-Path $PSScriptRoot -Parent)\setup-firewall.ps1"
$script:rules = @()
$script:events = @()
$script:failCreate = 0
$script:created = 0
$script:failSave = $false
$script:enabled = $true
$script:deduplicate = $false
$script:applicationReads = 0
$script:failAfterRetirement = $false
function Assert($Condition, $Message) { if (-not $Condition) { throw "FAIL: $Message" } }
function Get-GuardAdapters { @([pscustomobject]@{Name='Ethernet';InterfaceGuid='adapter-1'}) }
function Get-GuardVpnAdapter { [pscustomobject]@{Name='Tunnel';InterfaceGuid='{11111111-1111-1111-1111-111111111111}';ifIndex=4} }
function Assert-GuardNoProxy { }
function Get-GuardInventory { [pscustomobject]@{Programs=@('C:\Claude\claude.exe');Packages=@([pscustomobject]@{Sid='S-1-15-2-123'});CliPath='C:\Claude\claude.exe'} }
function Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore)
    1..3 | ForEach-Object { [pscustomobject]@{Enabled=$script:enabled;AllowLocalFirewallRules='NotConfigured'} }
}
function Get-NetFirewallRule { [CmdletBinding()]param($Name,$PolicyStore)
    if ($script:deduplicate) {
        $seen=@{}
        foreach ($rule in $script:rules) {
            if ($rule.Enabled -ne 'True') { continue }
            $key="$($rule.Program)|$($rule.Package)|$($rule.Alias)|$($rule.RemoteAddress)"
            if ($seen.ContainsKey($key)) { $rule.PrimaryStatus='Inactive'; $rule.EnforcementStatus='Duplicate' }
            else { $seen[$key]=$true; $rule.PrimaryStatus='OK'; $rule.EnforcementStatus='Full' }
        }
    }
    @($script:rules | Where-Object { -not $Name -or $_.Name -like $Name })
}
function New-NetFirewallRule { [CmdletBinding()]param($Name,$DisplayName,$Direction,$Action,$Profile,$InterfaceAlias,$Enabled,$PolicyStore,$Program,$Package,$RemoteAddress)
    $script:created++
    if ($script:failCreate -eq $script:created) { throw 'Injected provider error' }
    Assert (-not $Package -or $Package -like 'S-1-*') 'package filter must be SID'
    $script:events += "create:$Name"
    $script:rules += [pscustomobject]@{Name=$Name;Enabled=$Enabled;Direction=$Direction;Action=$Action;Profile=$Profile;PrimaryStatus='OK';EnforcementStatus='Full';Program=$(if($Program){$Program}else{'Any'});Package=$(if($Package){$Package}else{'Any'});Alias=$(if($InterfaceAlias){$InterfaceAlias}else{'Any'});RemoteAddress=$(if($RemoteAddress){$RemoteAddress}else{'Any'})}
}
function Remove-NetFirewallRule { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process {
        $script:events += "remove:$($InputObject.Name)"; $script:rules = @($script:rules | Where-Object Name -ne $InputObject.Name)
        if ($script:failAfterRetirement -and $InputObject.Name -like '*-old') { foreach ($rule in $script:rules) { $rule.Enabled='False' } }
    }
}
function Get-NetFirewallApplicationFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { $script:applicationReads++; [pscustomobject]@{Program=$InputObject.Program;Package=$InputObject.Package} }
}
function Get-NetFirewallInterfaceFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { [pscustomobject]@{InterfaceAlias=@($InputObject.Alias)} }
}
function Get-NetFirewallPortFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { [pscustomobject]@{Protocol='Any';LocalPort='Any';RemotePort='Any'} }
}
function Get-NetFirewallAddressFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { [pscustomobject]@{LocalAddress='Any';RemoteAddress=$InputObject.RemoteAddress} }
}
function Get-NetFirewallServiceFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { [pscustomobject]@{Service='Any'} }
}
function Get-NetFirewallInterfaceTypeFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { [pscustomobject]@{InterfaceType='Any'} }
}
function Get-NetFirewallSecurityFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { [pscustomobject]@{Authentication='NotRequired';Encryption='NotRequired';LocalUser=$(if($InputObject.LocalUser){$InputObject.LocalUser}else{'Any'});RemoteUser='Any';RemoteMachine='Any'} }
}
function Save-GuardFirewallState($State) {
    if ($script:failSave) { throw 'Injected persistence error' }
    Assert ($script:rules.Name -contains 'Claude-VPN-Guard-Block-old') 'old rules remain until state commit'
    $script:state = $State; $script:events += 'commit'
}
function Reset-Fixture {
    $script:rules=@([pscustomobject]@{Name='Claude-VPN-Guard-Block-old';Enabled='False';Direction='Outbound';Action='Block';Profile='Any';PrimaryStatus='OK';EnforcementStatus='Full';Program='C:\Claude\claude.exe';Package='Any';Alias='Ethernet'})
    $script:events=@(); $script:created=0; $script:failCreate=0; $script:failSave=$false; $script:deduplicate=$false; $script:failAfterRetirement=$false
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
Reset-Fixture
$script:rules[0].Enabled='True'
$script:rules[0] | Add-Member RemoteAddress 'Any'
$script:deduplicate=$true
Invoke-GuardFirewallSetup
Assert ($script:rules.Count -eq 2 -and $script:rules.Name -notcontains 'Claude-VPN-Guard-Block-old') 'duplicate replacement retires the old generation'
Assert ($script:events.IndexOf('commit') -lt $script:events.IndexOf('remove:Claude-VPN-Guard-Block-old')) 'duplicate replacement still commits before retiring the enforced witness'
Assert-GuardCoverage @(Get-GuardSpecifications (Get-GuardInventory) (Get-GuardAdapters)) @($script:state.Rules)
Write-Host 'PASS: Windows duplicate optimization permits a verified transactional refresh'
$savedRules=$script:rules; $savedState=$script:state
Reset-Fixture
$script:failAfterRetirement=$true
try { Invoke-GuardFirewallSetup; throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'setup cannot succeed when committed rules lose enforcement after retirement' }
Assert ($script:rules.Count -eq 2) 'post-retirement failure retains the committed generation for repair'
$script:rules=$savedRules; $script:state=$savedState; $script:failAfterRetirement=$false; $script:deduplicate=$false
Write-Host 'PASS: setup verifies committed coverage again after retiring old rules'
$spec=[pscustomobject]@{Alias='Ethernet';Program='C:\Claude\claude.exe';Package=$null;InterfaceStatus='Up'}
$script:deduplicate=$false
$savedRules=$script:rules
$candidate=$script:rules[0] | Select-Object *
$candidate.PrimaryStatus='Inactive'; $candidate.EnforcementStatus='Duplicate'
$witness=$candidate | Select-Object *
$witness.Name='Claude-VPN-Guard-Block-witness'; $witness.PrimaryStatus='OK'; $witness.EnforcementStatus='Full'
$script:rules=@($candidate,$witness)
Assert (-not (Test-GuardRule $candidate $spec)) 'duplicate status alone is never effective coverage'
try { Assert-GuardCoverage @($spec) @($candidate.Name); throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'steady verification cannot borrow a previous generation' }
Assert-GuardCoverage @($spec) @($candidate.Name) -DuringRefresh
$witness.RemoteAddress='203.0.113.1'
try { Assert-GuardCoverage @($spec) @($candidate.Name) -DuringRefresh; throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'a restricted witness cannot cover a duplicate' }
$witness.RemoteAddress='Any'; $candidate.EnforcementStatus=@('Duplicate','LocalFirewallRulesDisallowed')
try { Assert-GuardCoverage @($spec) @($candidate.Name) -DuringRefresh; throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'duplicate optimization cannot hide a policy rejection' }
$candidate.EnforcementStatus='Duplicate'; $script:rules=@($candidate)
try { Assert-GuardCoverage @($spec) @($candidate.Name) -DuringRefresh; throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'a lone duplicate fails closed' }
$witness.Name='Existing-Claude-Block'; $script:rules=@($candidate,$witness)
Assert-GuardCoverage @($spec) @($candidate.Name)
$witness.Enabled='False'
try { Assert-GuardCoverage @($spec) @($candidate.Name); throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'an existing disabled rule is not an enforced witness' }
$witness.Enabled='True'; $witness.Alias='Other adapter'
try { Assert-GuardCoverage @($spec) @($candidate.Name); throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'existing coverage on another adapter cannot satisfy a duplicate' }
$witness.Alias=$spec.Alias; $witness.PrimaryStatus='Inactive'; $witness.EnforcementStatus=@('ProfileInactive','NoInterface'); $spec.InterfaceStatus='Disconnected'
Assert-GuardCoverage @($spec) @($candidate.Name)
$spec.InterfaceStatus='Up'
try { Assert-GuardCoverage @($spec) @($candidate.Name); throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'a dormant existing witness must become enforced after reconnect' }
$witness.PrimaryStatus='OK'; $witness.EnforcementStatus='Full'
$witness | Add-Member LocalUser 'restricted-user'
try { Assert-GuardCoverage @($spec) @($candidate.Name); throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'a user-scoped existing rule cannot prove unrestricted coverage' }
$witness.LocalUser='Any'
$witness | Add-Member RemoteDynamicKeywordAddresses @('restricted-address-keyword')
try { Assert-GuardCoverage @($spec) @($candidate.Name); throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'dynamic address restrictions cannot prove unrestricted coverage' }
$witness.RemoteDynamicKeywordAddresses=@()
$script:rules=@($witness)
try { Assert-GuardCoverage @($spec) @($candidate.Name); throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'foreign rules cannot replace a missing required Guard rule' }
$script:rules=$savedRules
$script:applicationReads=0
Assert-GuardCoverage @($spec,$spec,$spec) @($script:state.Rules)
Assert ($script:applicationReads -eq 1) 'one verification reads the matching application filter once'
$script:rules[0].Program='C:\Other\other.exe'
try { Assert-GuardCoverage @($spec) @($script:state.Rules); throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'a later verification rereads changed provider filters' }
$script:rules[0].Program=$spec.Program
Write-Host 'PASS: duplicate witnesses are exact, enforced and limited to refresh; filters are reread on later checks'
$spec=[pscustomobject]@{Alias='Ethernet';Program='C:\Claude\claude.exe';Package=$null;InterfaceStatus='Up'}
$providerRule=$script:rules[0] | Select-Object *
$providerRule.Package=''
$providerRule.EnforcementStatus=@('ProfileInactive','Enforced','Enforced')
Assert (Test-GuardRule $providerRule $spec) 'real ActiveStore enforcement array and empty unrestricted package are accepted'
$providerRule.EnforcementStatus=@('ProfileInactive')
Assert (-not (Test-GuardRule $providerRule $spec)) 'inactive profiles alone do not prove active coverage'
$providerRule.EnforcementStatus=@('Enforced','LocalFirewallRulesDisallowed')
Assert (-not (Test-GuardRule $providerRule $spec)) 'a policy rejection is not hidden by another enforced status'
$providerRule.PrimaryStatus='Inactive'; $providerRule.EnforcementStatus=@('ProfileInactive','NoInterface')
Assert (-not (Test-GuardRule $providerRule $spec)) 'a missing interface on an up adapter blocks verification'
$spec.InterfaceStatus='Disconnected'
Assert (Test-GuardRule $providerRule $spec) 'dormant rules on disconnected IP adapters can be prepared'
$spec.InterfaceStatus='Up'
Assert (-not (Test-GuardRule $providerRule $spec)) 'a reconnected adapter needs enforced coverage'
$spec.InterfaceStatus='Disconnected'; $providerRule.EnforcementStatus=@('ProfileInactive','NoInterface','LocalFirewallRulesDisallowed')
Assert (-not (Test-GuardRule $providerRule $spec)) 'disconnected status does not hide a policy failure'
$providerRule.PrimaryStatus='OK'; $providerRule.EnforcementStatus=@('Enforced'); $providerRule.Package='S-1-15-2-999'
Assert (-not (Test-GuardRule $providerRule $spec)) 'a package-scoped program rule does not cover the unrestricted executable'
$providerRule.Package='S-1-15-2-123'; $providerRule.Program=''
$packageSpec=[pscustomobject]@{Alias='Ethernet';Program=$null;Package='S-1-15-2-123';InterfaceStatus='Up'}
Assert (Test-GuardRule $providerRule $packageSpec) 'real empty program filter with an exact package SID is accepted'
$providerRule.Package='S-1-15-2-999'
Assert (-not (Test-GuardRule $providerRule $packageSpec)) 'a different package SID cannot satisfy coverage'
Write-Host 'PASS: real provider representations, disconnected preparation and fail-closed enforcement checks'
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
