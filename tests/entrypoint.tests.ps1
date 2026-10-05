#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. "$root\guard-runtime.ps1"
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$testDirectory=Join-Path $env:TEMP ('ClaudeGuardEntryTest-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$recordPath=Join-Path $testDirectory 'launch.json'
try {
    # Run the complete production entry scripts through Windows PowerShell 5.1.
    # Replace only the launch boundary so tests cannot start Claude or change Windows settings.
    Copy-Item -LiteralPath "$root\sync-guard.ps1" -Destination $testDirectory
    Copy-Item -LiteralPath "$root\launch-cli.ps1" -Destination $testDirectory
    @'
function Invoke-GuardLaunch([switch]$LaunchCLI, [string[]]$CliArguments, [string]$TargetTimezone, [switch]$NoTimezoneChange) {
    $record=[pscustomobject]@{
        CLI=[bool]$LaunchCLI
        ArgumentCount=$(if ($null -eq $CliArguments) { 0 } else { $CliArguments.Count })
        Arguments=$CliArguments
        TargetTimezone=$TargetTimezone
        NoTimezoneChange=[bool]$NoTimezoneChange
    }
    $record | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'launch.json') -Encoding UTF8
    if ($LaunchCLI) { return 23 }
    return 0
}
'@ | Set-Content -LiteralPath (Join-Path $testDirectory 'guard-runtime.ps1') -Encoding UTF8
    function Run-Entry([string]$Name,[string[]]$Values) {
        if (Test-Path -LiteralPath $recordPath) { Remove-Item -LiteralPath $recordPath -Force }
        $native=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $testDirectory $Name)) + $Values
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $info.Arguments=(@($native | ForEach-Object { ConvertTo-GuardNativeArgument $_ }) -join ' ')
        $info.UseShellExecute=$false
        $info.CreateNoWindow=$true
        $info.RedirectStandardOutput=$true
        $info.RedirectStandardError=$true
        $process=[Diagnostics.Process]::Start($info)
        try {
            $output=$process.StandardOutput.ReadToEnd()
            $errorOutput=$process.StandardError.ReadToEnd()
            $process.WaitForExit()
            $record=if (Test-Path -LiteralPath $recordPath) { Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json } else { $null }
            [pscustomobject]@{ ExitCode=$process.ExitCode; Output=$output; Error=$errorOutput; Record=$record }
        } finally { $process.Dispose() }
    }
    $result=Run-Entry 'sync-guard.ps1' @('-LaunchClaude')
    Assert ($result.ExitCode -eq 0) "Desktop tray invocation accepts absent CLI arguments: $($result.Error)"
    Assert ($null -ne $result.Record -and -not $result.Record.CLI -and $result.Record.ArgumentCount -eq 0) 'Desktop receives no phantom argument'
    Write-Host 'PASS: Desktop tray entry accepts omitted CLI arguments'

    $result=Run-Entry 'sync-guard.ps1' @('-LaunchClaude','-NoTimezoneChange','-TargetTimezone','Georgian Standard Time')
    Assert ($result.ExitCode -eq 0) 'Desktop accepts timezone switches'
    Assert ($result.Record.NoTimezoneChange -and $result.Record.TargetTimezone -eq 'Georgian Standard Time') 'Desktop timezone options survive the entry boundary'
    Write-Host 'PASS: Desktop entry preserves timezone options'

    $result=Run-Entry 'sync-guard.ps1' @('-LaunchClaude','-CliArguments','unexpected')
    Assert ($result.ExitCode -ne 0 -and $null -eq $result.Record) 'Desktop rejects actual CLI arguments before launching'
    $result=Run-Entry 'sync-guard.ps1' @('-LaunchClaude','-LaunchCLI')
    Assert ($result.ExitCode -ne 0 -and $null -eq $result.Record) 'conflicting launch modes cannot launch'
    Write-Host 'PASS: invalid Desktop arguments and conflicting modes are rejected'

    $result=Run-Entry 'sync-guard.ps1' @('-LaunchCLI')
    Assert ($result.ExitCode -eq 23 -and $result.Record.CLI -and $result.Record.ArgumentCount -eq 0) 'CLI entry without arguments preserves runtime exit code and passes no phantom argument'
    $result=Run-Entry 'sync-guard.ps1' @('-LaunchCLI','-CliArguments','hello world')
    Assert ($result.ExitCode -eq 23 -and $result.Record.ArgumentCount -eq 1 -and $result.Record.Arguments[0] -ceq 'hello world') 'declared CLI argument is forwarded unchanged'
    $result=Run-Entry 'sync-guard.ps1' @('-LaunchCLI','-CliArguments','')
    Assert ($result.ExitCode -eq 23 -and $result.Record.ArgumentCount -eq 1 -and $result.Record.Arguments[0] -ceq '') 'an explicitly supplied empty CLI argument is not discarded'
    Write-Host 'PASS: shared CLI entry forwards absent and supplied arguments'

    $values=@('-p','hello world','','quotes "inside"','C:\path with spaces\')
    $result=Run-Entry 'launch-cli.ps1' $values
    Assert ($result.ExitCode -eq 23 -and $result.Record.ArgumentCount -eq 5) 'dedicated native CLI entry preserves all arguments and exit code'
    for ($i=0;$i -lt $values.Count;$i++) { Assert ($result.Record.Arguments[$i] -ceq $values[$i]) "dedicated CLI argument $i survives the actual script" }
    Write-Host 'PASS: complete native CLI entry preserves flags, spaces, empty strings, quotes and trailing backslashes'
} finally {
    $resolved=[IO.Path]::GetFullPath($testDirectory)
    $temporaryRoot=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
    if ($resolved.StartsWith($temporaryRoot,[StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'ClaudeGuardEntryTest-*') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
