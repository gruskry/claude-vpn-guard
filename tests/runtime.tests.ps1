$ErrorActionPreference='Stop'
. "$(Split-Path $PSScriptRoot -Parent)\guard-runtime.ps1"
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$script:testDirectory=Join-Path $env:TEMP ('ClaudeGuardRuntimeTest-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:testDirectory | Out-Null
function Get-GuardTimezoneStatePath { Join-Path $script:testDirectory 'timezone-state.json' }
$script:zone='UTC'; $script:setCount=0; $script:failSet=$false
function Get-TimeZone { [pscustomobject]@{Id=$script:zone} }
function Set-GuardTimezone($Id) {
    $script:setCount++
    if ($script:failSet) { throw 'Injected timezone error' }
    $script:zone=$Id
}
try {
    Start-GuardTimezone 'Georgian Standard Time'
    Assert ($script:zone -eq 'Georgian Standard Time') 'timezone changed'
    Assert (Test-Path -LiteralPath (Get-GuardTimezoneStatePath)) 'original timezone persists before change'
    Restore-GuardTimezone
    Assert ($script:zone -eq 'UTC') 'timezone restored'
    Start-GuardTimezone 'Georgian Standard Time'; $script:zone='Tokyo Standard Time'
    Restore-GuardTimezone
    Assert ($script:zone -eq 'Tokyo Standard Time') 'manual timezone change preserved'
    $script:zone='UTC'; $script:failSet=$true
    try { Start-GuardTimezone 'Georgian Standard Time'; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'failed timezone change propagates' }
    $script:failSet=$false
    Restore-GuardTimezone
    Assert ($script:zone -eq 'UTC') 'failed change recovery keeps original timezone'
    Write-Host 'PASS: timezone persistence, restore, failure, manual-change preservation'
    # Exercise the actual native Windows parser through an isolated argument-dump executable.
    $source=Join-Path $script:testDirectory 'Args.cs'; $exe=Join-Path $script:testDirectory 'Argument Dump.exe'
    @'
using System; using System.IO;
class ArgDump { static int Main(string[] args) { File.WriteAllLines(args[0], Array.ConvertAll(args, x => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(x)))); return 17; } }
'@ | Set-Content -LiteralPath $source -Encoding UTF8
    & "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:exe "/out:$exe" $source
    Assert ($LASTEXITCODE -eq 0) 'argument test executable compiled'
    $output=Join-Path $script:testDirectory 'arguments.txt'
    $unicode=-join @([char]0x43A,[char]0x438,[char]0x440,[char]0x438,[char]0x43B,[char]0x43B,[char]0x438,[char]0x446,[char]0x430)
    $arguments=@($output,'-p','hello world','','quotes "inside"','C:\path with spaces\',$unicode)
    $process=Start-GuardNativeProcess $exe $arguments; $process.WaitForExit()
    Assert ($process.ExitCode -eq 17) 'native exit code preserved'
    $actual=@(Get-Content -LiteralPath $output | ForEach-Object { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_)) })
    Assert ($actual.Count -eq $arguments.Count) 'all arguments forwarded'
    for ($i=0; $i -lt $arguments.Count; $i++) { Assert ($actual[$i] -ceq $arguments[$i]) "argument $i unchanged" }
    Write-Host 'PASS: CLI spaces, quotes, empty arguments, trailing backslash, Unicode, exit code'
    # Also exercise the script entry boundary: an advanced parameter block consumes
    # Claude's -p as PowerShell's PipelineVariable, even if native quoting is correct.
    $entry=Join-Path $script:testDirectory 'CLI entry.ps1'
    $boundaryOutput=Join-Path $script:testDirectory 'boundary.txt'
    $root=Split-Path $PSScriptRoot -Parent
    $ast=[Management.Automation.Language.Parser]::ParseFile("$root\launch-cli.ps1",[ref]$null,[ref]$null)
    $header=if ($ast.ParamBlock) { $ast.ParamBlock.Extent.Text } else { '' }
    $body='[IO.File]::WriteAllLines(' + "'" + $boundaryOutput + "'" + ', @($args | ForEach-Object { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_)) }))'
    $header + "`r`n" + $body | Set-Content -LiteralPath $entry -Encoding UTF8
    $native=@('-p','hello world','--model','opus','--add-dir','C:\path with spaces')
    $process=Start-GuardNativeProcess "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" (@('-NoProfile','-File',$entry)+$native)
    $process.WaitForExit()
    Assert ($process.ExitCode -eq 0) 'CLI script binding fixture succeeds'
    $bound=@(Get-Content -LiteralPath $boundaryOutput | ForEach-Object { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_)) })
    Assert ($bound.Count -eq $native.Count) 'CLI flags survive PowerShell script binding'
    for ($i=0;$i -lt $native.Count;$i++) { Assert ($bound[$i] -ceq $native[$i]) "CLI boundary argument $i unchanged" }
    Write-Host 'PASS: -p and other CLI flags bypass PowerShell common parameter binding'
} finally {
    # Exact GUID-scoped test directory under TEMP; never remove outside this fixture.
    if ((Split-Path $script:testDirectory -Parent) -eq $env:TEMP) { Remove-Item -LiteralPath $script:testDirectory -Recurse -Force }
}
