$ErrorActionPreference='Stop'
. "$(Split-Path $PSScriptRoot -Parent)\guard-runtime.ps1"
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$script:checks=0; $script:started=0; $script:stoppedNew=$false; $script:restored=0
$script:old=[pscustomobject]@{Programs=@('C:\Claude\old\Claude.exe');DesktopPaths=@('C:\Claude\old\Claude.exe');Packages=@();CliPath=$null}
$script:new=[pscustomobject]@{Programs=@('C:\Claude\new\Claude.exe');DesktopPaths=@('C:\Claude\new\Claude.exe');Packages=@();CliPath=$null}
function Restore-GuardTimezone { $script:restored++ }
function Get-GuardConfig { [pscustomobject]@{auto_detect=$true;change_timezone=$false} }
function Get-PublicIPLocation { [pscustomobject]@{IP='8.8.8.8';CountryCode='GE';IanaTz=''} }
function Get-GuardProtectionStatus {
    $script:checks++
    if ($script:checks -ge 3) { throw 'New executable is unprotected' }
    [pscustomobject]@{Ok=$true;Inventory=$script:old}
}
function Get-GuardInventory { $script:new }
function Get-GuardRunningProcesses($Inventory) {
    if ($script:started) { [pscustomobject]@{Path=$Inventory.Programs[0];Id=102} }
}
function Get-Item { [CmdletBinding()]param($LiteralPath); [pscustomobject]@{LastWriteTimeUtc=[DateTime]::UtcNow} }
function Start-Sleep { param($Milliseconds) }
function Start-GuardNativeProcess($Path,$Arguments) {
    $script:started++
    $process=[pscustomobject]@{Id=101;HasExited=$true}
    $process | Add-Member -MemberType ScriptMethod -Name Dispose -Value {}
    return $process
}
function Stop-GuardRunningProcesses($Inventory,$StartedProcess) {
    $script:stoppedNew = @($Inventory.Programs) -contains 'C:\Claude\new\Claude.exe'
}
$script:progress=@()
function Write-GuardLaunchProgress([string]$Stage,[bool]$Enabled) { if ($Enabled) { $script:progress+= $Stage } }
try { Invoke-GuardLaunch -NoTimezoneChange -ProgressMessages; throw 'unexpected success' }
catch { $launchFailure=$_.Exception.Message; Assert ($launchFailure -ne 'unexpected success') 'unsafe update must fail the session' }
Assert $script:stoppedNew ("shutdown includes updated executable, even after original process exited; failure: $launchFailure")
Assert ($script:restored -eq 2) 'timezone restoration runs after failed protection recheck'
Assert (($script:progress -join ',') -eq 'initializing,discovery,firewall,location,final-check,starting,started') 'GUI stages reflect actual launch boundaries and announce start only after process creation'
Write-Host 'PASS: updated Claude process is stopped on failed coverage verification'
$script:started=0
$script:progress=@()
function Get-GuardProtectionStatus { throw 'Missing block rule' }
try { Invoke-GuardLaunch -NoTimezoneChange -ProgressMessages; throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'incomplete protection blocks launch' }
Assert ($script:started -eq 0) 'preflight failure never starts Claude'
Assert ($script:progress -notcontains 'started') 'failed preflight never dismisses the GUI as a successful launch'
Write-Host 'PASS: incomplete protection blocks process creation'
$script:started=0; $script:stoppedNew=$false
function Get-GuardProtectionStatus { [pscustomobject]@{Ok=$true;Inventory=$script:old} }
function Get-GuardRunningProcesses($Inventory) { if ($script:started) { throw 'Injected process provider failure' } }
try { Invoke-GuardLaunch -NoTimezoneChange; throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'monitor provider failure must fail session' }
Assert $script:stoppedNew 'unexpected monitor failure stops known Claude processes'
Write-Host 'PASS: process inspection failure also stops Claude'
