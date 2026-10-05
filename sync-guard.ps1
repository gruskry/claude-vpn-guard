#Requires -Version 5.1
param(
    [switch]$LaunchClaude,
    [switch]$LaunchCLI,
    [string]$TargetTimezone,
    [switch]$NoTimezoneChange,
    [switch]$ProgressMessages,
    [string[]]$CliArguments
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
. "$PSScriptRoot\guard-runtime.ps1"
if ($MyInvocation.InvocationName -ne '.') {
    try {
        if ($LaunchCLI -and $LaunchClaude) { throw 'Choose Desktop or CLI, not both.' }
        # An omitted string[] is $null; @($null).Count is 1 in Windows PowerShell.
        # Remove absent values while preserving real empty-string CLI arguments.
        $forwarded=@(@($CliArguments) + @($args) | Where-Object { $null -ne $_ })
        if (-not $LaunchCLI -and $forwarded.Count) { throw 'Desktop launch does not accept CLI arguments.' }
        $result = Invoke-GuardLaunch -LaunchCLI:$LaunchCLI -CliArguments $forwarded -TargetTimezone $TargetTimezone -NoTimezoneChange:$NoTimezoneChange -ProgressMessages:$ProgressMessages
        exit $result
    } catch {
        $message=$_.Exception.Message
        if ($ProgressMessages) { $message='[ClaudeGuardError]'+$message.Replace("`r",' ').Replace("`n",' ') }
        [Console]::Error.WriteLine($message)
        exit 1
    }
}
