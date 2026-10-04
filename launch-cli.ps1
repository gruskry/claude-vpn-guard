#Requires -Version 5.1
# Intentionally no parameter block: native CLI flags such as -p must never bind
# to PowerShell common parameters or to Guard's own switches.
$forwarded=@($args)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\guard-runtime.ps1"
if ($MyInvocation.InvocationName -ne '.') {
    try { $result=Invoke-GuardLaunch -LaunchCLI -CliArguments $forwarded; exit $result }
    catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
