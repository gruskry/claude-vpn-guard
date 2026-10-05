$ErrorActionPreference='Stop'
. "$(Split-Path $PSScriptRoot -Parent)\guard-runtime.ps1"
$repairImplementation=${function:Invoke-GuardFirewallRepair}
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
$reportRoot=Join-Path $env:TEMP ('GuardRepairResultTest-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $reportRoot | Out-Null
function Get-GuardSetupResultPath { Join-Path $reportRoot 'setup-result.json' }
try {
    $requestId=[guid]::NewGuid()
    @{Version=1;RequestId=$requestId.ToString();Ok=$false;Message='Specific provider failure'} | ConvertTo-Json | Set-Content -LiteralPath (Get-GuardSetupResultPath) -Encoding UTF8
    Assert ((Read-GuardSetupResult $requestId).Message -eq 'Specific provider failure') 'matching administrative result is read'
    Assert ($null -eq (Read-GuardSetupResult ([guid]::NewGuid()))) 'a previous operation cannot supply the current error'
    @{Version=1;RequestId=$requestId.ToString();Ok='false';Message='wrong type'} | ConvertTo-Json | Set-Content -LiteralPath (Get-GuardSetupResultPath) -Encoding UTF8
    Assert ($null -eq (Read-GuardSetupResult $requestId)) 'malformed administrative result is rejected'
    Set-Item -Path function:Invoke-GuardFirewallRepair -Value $repairImplementation
    $script:staleResult=$false; $script:disposed=$false
    function Start-Process {
        [CmdletBinding()]param($FilePath,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru)
        Assert ($ArgumentList -match '-ResultId ([a-f0-9-]+)') 'repair sends a correlation ID through the real entry boundary'
        $id=$Matches[1]
        if ($script:staleResult) { $id=[guid]::NewGuid().ToString() }
        @{Version=1;RequestId=$id;Ok=$false;Message='Missing effective rule on Teredo'} | ConvertTo-Json | Set-Content -LiteralPath (Get-GuardSetupResultPath) -Encoding UTF8
        $process=[pscustomobject]@{ExitCode=1}
        $process | Add-Member ScriptMethod Dispose { $script:disposed=$true }
        $process
    }
    try { Invoke-GuardFirewallRepair -CoverageFailure 'Changed adapter'; throw 'unexpected success' }
    catch { Assert ($_.Exception.Message.Contains('Missing effective rule on Teredo') -and $_.Exception.Message.Contains('Changed adapter')) 'repair preserves the real provider reason and original coverage failure' }
    Assert $script:disposed 'repair disposes its process on failure'
    $script:staleResult=$true
    try { Invoke-GuardFirewallRepair; throw 'unexpected success' }
    catch { Assert (-not $_.Exception.Message.Contains('Missing effective rule on Teredo') -and $_.Exception.Message.Contains('Launch blocked')) 'stale reports are not displayed and missing results remain fail closed' }
    Write-Host 'PASS: correlated administrative errors reach Guard; stale and malformed results are rejected'
} finally {
    $resolved=[IO.Path]::GetFullPath($reportRoot)
    if ($resolved.StartsWith([IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'GuardRepairResultTest-*') { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
