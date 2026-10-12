$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. "$root\setup-firewall.ps1"
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$testDirectory=Join-Path $env:TEMP ('ClaudeGuardAutoRefreshTest-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDirectory | Out-Null
try {
    # Background refresh decision: no state, current coverage, repairable change.
    $statePath=Join-Path $testDirectory 'firewall-state.json'
    function Get-GuardStatePath { $statePath }
    function Assert-GuardProfiles { }
    function Get-GuardVpnAdapter { throw 'background refresh must not select a VPN by route' }
    function Get-GuardPinnedVpnAdapter([string]$PinnedGuid) { [pscustomobject]@{Name=$null;InterfaceGuid=$PinnedGuid;ifIndex=-1} }
    function Get-GuardAdapters($Vpn,[switch]$AllowVpnDown) { Assert $AllowVpnDown 'background refresh tolerates a disconnected VPN'; @([pscustomobject]@{Name='Ethernet';InterfaceGuid='adapter-1';Ipv4Present=$true}) }
    function Get-GuardInventory { [pscustomobject]@{Programs=@('C:\Claude\claude.exe');Packages=@()} }
    $script:coverageFailure=$null; $script:setups=@()
    function Assert-GuardCoverage($Specifications,$RuleNames) { if ($script:coverageFailure) { Throw-GuardCoverageChanged $script:coverageFailure } }
    function Invoke-GuardFirewallSetup([switch]$Uninstall,[string]$VpnGuid,[switch]$ReselectVpn,[switch]$Background) { $script:setups+=[pscustomobject]@{VpnGuid=$VpnGuid;Background=[bool]$Background} }
    Assert ((Invoke-GuardBackgroundRefresh) -eq 'no-state' -and -not $script:setups.Count) 'no committed setup means no background changes'
    [pscustomobject]@{Version=2;VpnGuid='{11111111-1111-1111-1111-111111111111}';Rules=@('Claude-VPN-Guard-Block-a-0');Adapters=@([pscustomobject]@{Guid='adapter-1';Alias='Ethernet'})} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding UTF8
    Assert ((Invoke-GuardBackgroundRefresh) -eq 'current' -and -not $script:setups.Count) 'current coverage makes no changes'
    $script:coverageFailure='Missing effective block rule for new claude.exe'
    Assert ((Invoke-GuardBackgroundRefresh) -eq 'refreshed') 'an uncovered executable triggers a refresh'
    Assert ($script:setups.Count -eq 1 -and $script:setups[0].Background -and $script:setups[0].VpnGuid -eq '{11111111-1111-1111-1111-111111111111}') 'refresh keeps the pinned VPN'
    $script:coverageFailure=$null
    function Get-GuardAdapters($Vpn,[switch]$AllowVpnDown) { @([pscustomobject]@{Name='Ethernet';InterfaceGuid='adapter-1';Ipv4Present=$true},[pscustomobject]@{Name='Hotspot';InterfaceGuid='adapter-2';Ipv4Present=$true}) }
    Assert ((Invoke-GuardBackgroundRefresh) -eq 'refreshed' -and $script:setups.Count -eq 2) 'a new adapter triggers a refresh'
    function Assert-GuardCoverage($Specifications,$RuleNames) { throw 'Firewall provider failed' }
    function Get-GuardAdapters($Vpn,[switch]$AllowVpnDown) { @([pscustomobject]@{Name='Ethernet';InterfaceGuid='adapter-1';Ipv4Present=$true}) }
    try { Invoke-GuardBackgroundRefresh; throw 'unexpected success' } catch { Assert ($_.Exception.Message -eq 'Firewall provider failed') 'non-repairable failures are reported, not hidden by a rebuild' }
    Write-Host 'PASS: background refresh changes rules only for uncovered executables or adapters'

    # Task registration copies scripts into an administrator-only folder.
    $source=Join-Path $testDirectory 'source'; $target=Join-Path $testDirectory 'auto-refresh'
    New-Item -ItemType Directory -Path $source | Out-Null
    foreach ($name in @($script:GuardAutoRefreshFiles + 'config.json')) { [IO.File]::WriteAllText((Join-Path $source $name),"fixture $name") }
    New-Item -ItemType Directory -Path $target | Out-Null
    [IO.File]::WriteAllText((Join-Path $target 'guard-common.ps1'),'stale')
    function Get-GuardAutoRefreshDirectory { $target }
    $script:protected=@()
    function Initialize-GuardAdministratorDirectory([string]$Directory) { $script:protected+=$Directory; if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory | Out-Null } }
    # Load the CDXML module first: auto-loading it later would replace these mocks.
    Import-Module ScheduledTasks -ErrorAction Stop
    $script:registered=$null; $script:started=0
    function Register-ScheduledTask { param($TaskName,$Description,$Action,$Trigger,$Principal,$Settings,[switch]$Force,$ErrorAction) $script:registered=[pscustomobject]@{Name=$TaskName;Action=$Action;Trigger=@($Trigger);Principal=$Principal;Settings=$Settings} }
    function Start-ScheduledTask { param($TaskName,$ErrorAction) $script:started++ }
    function Stop-ScheduledTask { param($TaskName,$ErrorAction) }
    Assert (-not (Register-GuardAutoRefresh 'S-1-5-21-1-2-3-500' $source) -and -not $script:registered) 'a different approving administrator does not get the task'
    Assert (Register-GuardAutoRefresh '' $source) 'task registration succeeds'
    Assert ($script:protected -contains $target) 'the task folder is restricted to administrators'
    Assert ((Get-Content -LiteralPath (Join-Path $target 'guard-common.ps1') -Raw) -eq 'fixture guard-common.ps1' -and (Test-Path -LiteralPath (Join-Path $target 'config.json'))) 'scripts and settings are copied fresh'
    Assert ($script:registered.Principal.LogonType -eq 'S4U' -and "$($script:registered.Principal.RunLevel)" -eq 'Highest') 'task runs elevated as the user without a stored password'
    Assert ($script:registered.Action.Arguments -like "*$target\guard-autorefresh.ps1*" -and $script:registered.Action.Arguments -like '*-WindowStyle Hidden*') 'task runs the protected copy without a window'
    Assert ($script:registered.Trigger.Count -eq 2 -and "$($script:registered.Settings.MultipleInstances)" -eq 'IgnoreNew' -and $script:started -eq 1) 'logon and watchdog triggers keep one watcher running'
    try { Register-GuardAutoRefresh '' $target; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'the protected copy cannot reinstall itself' }
    function Get-ScheduledTask { param($TaskName,$ErrorAction) [pscustomobject]@{TaskName=$TaskName} }
    $script:unregistered=0
    function Unregister-ScheduledTask { param($TaskName,[switch]$Confirm,$ErrorAction) $script:unregistered++ }
    Unregister-GuardAutoRefresh
    Assert ($script:unregistered -eq 1 -and -not (Test-Path -LiteralPath $target)) 'removal unregisters the task and deletes its scripts'
    Write-Host 'PASS: auto-refresh task uses a protected copy, the right account and clean removal'

    # Watcher loop: verify on start, on executable changes and on file events.
    . "$root\guard-autorefresh.ps1"
    $script:fingerprints=@('a','a','b','b')
    $script:inventoryCall=0
    function Get-GuardInventory { $value=$script:fingerprints[[Math]::Min($script:inventoryCall,$script:fingerprints.Count-1)]; $script:inventoryCall++; [pscustomobject]@{Programs=@("C:\Claude\$value\claude.exe");Packages=@()} }
    $script:runs=0
    function Invoke-GuardBackgroundSetup { $script:runs++; 0 }
    function Save-GuardAutoRefreshStatus([bool]$Ok,[int]$Programs) { }
    $script:pendingEvent=$false
    function New-GuardChangeMonitor($Inventory) { $monitor=[pscustomobject]@{}; $monitor | Add-Member ScriptMethod Consume { $value=$script:pendingEvent; $script:pendingEvent=$false; $value }; $monitor | Add-Member ScriptMethod Dispose { }; $monitor }
    function Start-Sleep { param($Seconds,$Milliseconds) }
    Start-GuardAutoRefreshLoop -PollSeconds 0 -MaxIterations 3
    Assert ($script:runs -eq 2) "initial verification and an executable change each run setup once (runs=$script:runs)"
    $script:runs=0; $script:fingerprints=@('c'); $script:inventoryCall=0; $script:pendingEvent=$false
    Start-GuardAutoRefreshLoop -PollSeconds 1 -MaxIterations 2
    Assert ($script:runs -eq 1) 'an unchanged installation is not verified again before the periodic check'
    $script:runs=0; $script:pendingEvent=$true
    Start-GuardAutoRefreshLoop -PollSeconds 1 -MaxIterations 2
    Assert ($script:runs -eq 2) 'a file or network event triggers immediate verification'
    function Invoke-GuardBackgroundSetup { $script:runs++; 1 }
    $script:runs=0; $script:fingerprints=@('d','d','d')
    Start-GuardAutoRefreshLoop -PollSeconds 0 -MaxIterations 3
    Assert ($script:runs -eq 1) 'a failed refresh waits for the retry interval instead of looping'
    Write-Host 'PASS: watcher verifies on start, after executable changes and backs off after failures'
} finally {
    if ((Split-Path $testDirectory -Parent) -eq $env:TEMP) { Remove-Item -LiteralPath $testDirectory -Recurse -Force }
}
