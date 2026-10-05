$ErrorActionPreference='Stop'
. "$(Split-Path $PSScriptRoot -Parent)\guard-runtime.ps1"
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$inventory=[pscustomobject]@{Programs=@('C:\Claude\Claude.exe','C:\Claude\updated\Claude.exe')}
$first=[pscustomobject]@{Id=101;Path='C:\Claude\Claude.exe';ProcessName='Claude';HasExited=$false}
$second=[pscustomobject]@{Id=102;Path='C:\Claude\updated\Claude.exe';ProcessName='Claude';HasExited=$false}
$unknown=[pscustomobject]@{Id=103;ProcessName='Claude';HasExited=$false}
$unknown | Add-Member -MemberType ScriptProperty -Name Path -Value { throw 'access denied' }
$started=[pscustomobject]@{Id=100;HasExited=$true}
function Get-Process { [CmdletBinding()]param(); $first; $unknown; $second }
$script:stopped=@()
function Stop-GuardProcessTree($Process) { $script:stopped+=$Process.Id; if ($Process.Id -eq 101) { throw 'injected kill denial' } }
try { Stop-GuardRunningProcesses $inventory $started; throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'uninspectable/unstoppable processes are reported' }
Assert ($script:stopped -contains 101 -and $script:stopped -contains 102) 'all accessible known processes are attempted despite discovery and kill failures'
Assert ($script:stopped -notcontains 103) 'unknown process is never killed by display name'
Write-Host 'PASS: shutdown retains known PIDs across discovery errors and continues after a kill failure'
$script:stopped=@()
function Get-Process { [CmdletBinding()]param(); $first; throw 'provider failed after a partial result' }
try { Stop-GuardRunningProcesses $inventory $started; throw 'unexpected success' }
catch { Assert ($_.Exception.Message -ne 'unexpected success') 'partial provider error is reported' }
Assert ($script:stopped -contains 101) 'partial enumeration results are retained for shutdown'
Write-Host 'PASS: shutdown retains partial provider results'
