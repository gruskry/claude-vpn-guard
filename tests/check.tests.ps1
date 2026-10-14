$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$testDirectory=Join-Path $env:TEMP ('ClaudeGuardCheckTest-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$oldProgramData=$env:ProgramData
try {
    # The production entry script with stubbed providers: the tray parses its JSON.
    Copy-Item -LiteralPath "$root\check-protection.ps1" -Destination $testDirectory
    @'
function Get-GuardProtectionStatus { [pscustomobject]@{Vpn=[pscustomobject]@{Name='Tunnel'};Inventory=[pscustomobject]@{Programs=@('C:\Claude\claude.exe')};Adapters=@([pscustomobject]@{Name='Ethernet'})} }
'@ | Set-Content -LiteralPath (Join-Path $testDirectory 'guard-common.ps1') -Encoding UTF8
    @'
param([switch]$Clean,[switch]$Json,[string]$RestoreBackup)
function Invoke-GuardPrivacy { [pscustomobject]@{Fields=0} }
'@ | Set-Content -LiteralPath (Join-Path $testDirectory 'guard-privacy.ps1') -Encoding UTF8
    $env:ProgramData=Join-Path $testDirectory 'ProgramData'
    New-Item -ItemType Directory -Path (Join-Path $env:ProgramData 'ClaudeVPNGuard') -Force | Out-Null
    [pscustomobject]@{Version=1;Utc='2026-10-12T16:25:38.2654256Z';Ok=$true;Programs=1} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $env:ProgramData 'ClaudeVPNGuard\auto-refresh-status.json') -Encoding UTF8
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $output=& $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $testDirectory 'check-protection.ps1') -Json
    Assert ($LASTEXITCODE -eq 0) 'protection check succeeds'
    $result=($output -join "`n") | ConvertFrom-Json
    Assert ($result.Ok -eq $true -and @($result.Programs).Count -eq 1) 'the -Json switch survives dot-sourcing guard-privacy.ps1'
    Assert ($result.Message -like '*Automatic refresh after Claude updates: last check * succeeded.*') ("automatic refresh status is reported; message=$($result.Message)")
    Remove-Item -LiteralPath (Join-Path $env:ProgramData 'ClaudeVPNGuard\auto-refresh-status.json')
    $result=((& $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $testDirectory 'check-protection.ps1') -Json) -join "`n") | ConvertFrom-Json
    Assert ($result.Message -like '*not running*') 'missing automatic refresh is reported'
    Write-Host 'PASS: protection check emits JSON for the tray and reports automatic refresh'
} finally {
    $env:ProgramData=$oldProgramData
    if ((Split-Path $testDirectory -Parent) -eq $env:TEMP) { Remove-Item -LiteralPath $testDirectory -Recurse -Force }
}
