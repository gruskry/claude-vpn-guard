#Requires -Version 5.1
param(
    [switch]$LaunchClaude,
    [switch]$LaunchCLI,
    [string]$TargetTimezone,
    [switch]$NoTimezoneChange,
    [string[]]$CliArguments
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
. "$PSScriptRoot\guard-runtime.ps1"
if ($MyInvocation.InvocationName -ne '.') {
    try {
        if ($LaunchCLI -and $LaunchClaude) { throw 'Choose Desktop or CLI, not both.' }
        if (-not $LaunchCLI -and @($CliArguments).Count) { throw 'Desktop launch does not accept CLI arguments.' }
        $forwarded=@($CliArguments) + @($args)
        $result = Invoke-GuardLaunch -LaunchCLI:$LaunchCLI -CliArguments $forwarded -TargetTimezone $TargetTimezone -NoTimezoneChange:$NoTimezoneChange
        exit $result
    } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
}
