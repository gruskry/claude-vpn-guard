$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. "$root\guard-privacy.ps1"
if (Test-Path "$root\guard-diagnostics.ps1") { . "$root\guard-diagnostics.ps1" }
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$testDirectory=Join-Path $env:TEMP ('ClaudeGuardDiagnosticsTest-'+[guid]::NewGuid().ToString('N'))
$originalLocal=$env:LOCALAPPDATA
try {
    $env:LOCALAPPDATA=$testDirectory; $script:GuardDiagnosticLoggingEnabled=$true
    Assert ([bool](Get-Command Write-GuardDiagnosticEvent -ErrorAction SilentlyContinue)) 'privacy-safe diagnostic logging is available'
    Write-GuardDiagnosticEvent 'privacy-cleaned' 6
    $path=Join-Path $testDirectory 'ClaudeVPNGuard\guard-events.jsonl'
    $data=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    Assert ($data.Event -eq 'privacy-cleaned' -and $data.Count -eq 6 -and @($data.PSObject.Properties).Count -eq 3) 'logs contain only timestamp, fixed event code and count'
    try { Write-GuardDiagnosticEvent '203.0.113.7'; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'arbitrary/private text is rejected'
    }
    [IO.File]::WriteAllText($path,('x'*65536))
    Write-GuardDiagnosticEvent 'launch-blocked'
    Assert ((Get-Item -LiteralPath $path).Length -lt 1024) 'log rotation keeps the active file bounded'
    Assert (Test-Path -LiteralPath ($path+'.previous')) 'one previous log is retained'
    Write-Host 'PASS: allowlisted diagnostics, no arbitrary messages, bounded rotation'
} finally {
    $env:LOCALAPPDATA=$originalLocal
    if ((Split-Path $testDirectory -Parent) -eq $env:TEMP -and (Test-Path -LiteralPath $testDirectory)) { Remove-Item -LiteralPath $testDirectory -Recurse -Force }
}
