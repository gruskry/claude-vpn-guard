$ErrorActionPreference='Stop'
. "$(Split-Path $PSScriptRoot -Parent)\guard-runtime.ps1"
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$script:checks=0; $script:repairs=0; $script:deny=$false
function Get-GuardProtectionStatus {
    $script:checks++
    if ($script:checks -eq 1) {
        $error=New-Object InvalidOperationException 'Changed executable path'
        $error.Data['GuardRepairable']=$true
        throw $error
    }
    [pscustomobject]@{Ok=$true;Inventory=[pscustomobject]@{Programs=@('C:\new\Claude.exe')}}
}
function Invoke-GuardFirewallRepair { $script:repairs++; if ($script:deny) { throw 'Permission denied' } }
Assert ([bool](Get-Command Get-GuardVerifiedStatus -ErrorAction SilentlyContinue)) 'verified automatic repair is available'
$status=Get-GuardVerifiedStatus -AutoRepair
Assert ($status.Inventory.Programs[0] -eq 'C:\new\Claude.exe' -and $script:checks -eq 2 -and $script:repairs -eq 1) 'repair is followed by a fresh effective coverage check'
$script:checks=0; $script:deny=$true
try { Get-GuardVerifiedStatus -AutoRepair; throw 'unexpected success' } catch { Assert ($_.Exception.Message -eq 'Permission denied') 'denied elevation blocks launch' }
function Get-GuardProtectionStatus { throw 'Firewall is disabled' }
$before=$script:repairs
try { Get-GuardVerifiedStatus -AutoRepair; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'policy failure blocks launch' }
Assert ($script:repairs -eq $before) 'disabled firewall is never auto-repaired'
function Get-GuardProtectionStatus { $error=New-Object InvalidOperationException 'Still uncovered'; $error.Data['GuardRepairable']=$true; throw $error }
$script:deny=$false; $before=$script:repairs
try { Get-GuardVerifiedStatus -AutoRepair; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'a successful setup exit alone is not trusted' }
Assert ($script:repairs -eq $before+1) 'repair does not loop indefinitely'
Write-Host 'PASS: verified automatic repair, denied permission, policy failure and failed post-check'
