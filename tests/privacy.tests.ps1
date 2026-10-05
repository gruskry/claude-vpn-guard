$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
if (Test-Path "$root\guard-privacy.ps1") { . "$root\guard-privacy.ps1" }
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$testDirectory=Join-Path $env:TEMP ('ClaudeGuardPrivacyTest-'+[guid]::NewGuid().ToString('N'))
$previousAppData=$env:APPDATA; $previousLocal=$env:LOCALAPPDATA
try {
    $env:APPDATA=Join-Path $testDirectory 'Roaming'; $env:LOCALAPPDATA=Join-Path $testDirectory 'Local'
    $sentry=Join-Path $env:APPDATA 'Claude\sentry'
    New-Item -ItemType Directory -Path $sentry -Force | Out-Null
    $file=Join-Path $sentry 'scope_v3.json'
    $original='{"scope":{"user":{"ip_address":"203.0.113.7","id":"keep-auth-reference"}},"event":{"contexts":{"culture":{"timezone":"Europe/Minsk","locale":"ru"},"geo":{"city":"private-city","country_code":"BY","latitude":53.9,"longitude":27.5}},"breadcrumbs":[{"message":"Conversation includes 203.0.113.7"}]},"unknown":{"timezone":"keep-other-setting"}}'
    [IO.File]::WriteAllText($file,$original)
    $auth=Join-Path (Split-Path $sentry -Parent) 'credentials.json'; [IO.File]::WriteAllText($auth,'must-not-change')
    function Get-GuardInventory { [pscustomobject]@{Programs=@('C:\Claude\Claude.exe')} }
    $script:active=$false
    function Get-GuardRunningProcesses { if ($script:active) { [pscustomobject]@{Id=99} } }
    Assert ([bool](Get-Command Invoke-GuardPrivacy -ErrorAction SilentlyContinue)) 'privacy audit is available'
    $audit=Invoke-GuardPrivacy
    Assert ($audit.Fields -eq 6 -and $audit.Cleaned -eq 0) 'audit reports only known diagnostic metadata'
    Assert ([IO.File]::ReadAllText($file) -ceq $original) 'audit is read-only'
    $result=Invoke-GuardPrivacy -Clean
    $data=Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
    Assert (-not $data.scope.user.PSObject.Properties['ip_address']) 'diagnostic IP is removed'
    Assert (-not $data.event.contexts.culture.PSObject.Properties['timezone']) 'diagnostic timezone is removed'
    Assert ($data.event.contexts.culture.locale -eq 'ru' -and $data.unknown.timezone -eq 'keep-other-setting') 'unrelated settings survive'
    Assert ($data.event.breadcrumbs[0].message -eq 'Conversation includes 203.0.113.7') 'free-form content is never scrubbed heuristically'
    Assert ([IO.File]::ReadAllText($auth) -eq 'must-not-change') 'authentication files are untouched'
    Assert ($result.Cleaned -eq 1) 'cleanup reports a committed change'
    Add-Type -AssemblyName System.Security
    $backup=Get-ChildItem (Join-Path $env:LOCALAPPDATA 'ClaudeVPNGuard\privacy-backups') -Filter '*.bin' | Select-Object -First 1
    $plain=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($backup.FullName),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    $saved=[Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
    Assert ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($saved.Original)) -ceq $original) 'encrypted backup preserves the exact original bytes'
    $restored=Invoke-GuardPrivacy -RestoreBackup $backup.FullName
    Assert ([IO.File]::ReadAllText($file) -ceq $original) 'backup can restore the exact original diagnostic file'
    $result=Invoke-GuardPrivacy -Clean
    $script:active=$true
    try { Invoke-GuardPrivacy -Clean; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'active Claude blocks cleanup' }
    $script:active=$false
    [IO.File]::WriteAllText($file,'{"later_manual_change":true}')
    try { Invoke-GuardPrivacy -RestoreBackup $backup.FullName; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'later manual data is not overwritten by restoration' }
    Assert ([IO.File]::ReadAllText($file) -eq '{"later_manual_change":true}') 'manual data remains after restoration conflict'
    [IO.File]::WriteAllText($file,'{broken-json')
    try { Invoke-GuardPrivacy -Clean; throw 'unexpected success' } catch {
        Assert ($_.Exception.Message -ne 'unexpected success') 'malformed diagnostics fail without rewriting'
        Assert ($_.Exception.Message -notmatch 'broken-json') 'parser errors do not expose diagnostic document contents'
    }
    Assert ([IO.File]::ReadAllText($file) -eq '{broken-json') 'malformed input retained'
    Write-Host 'PASS: read-only privacy audit, targeted cleanup, encrypted backup, auth/content preservation, active app and malformed data'
} finally {
    $env:APPDATA=$previousAppData; $env:LOCALAPPDATA=$previousLocal
    if ((Split-Path $testDirectory -Parent) -eq $env:TEMP -and (Test-Path -LiteralPath $testDirectory)) { Remove-Item -LiteralPath $testDirectory -Recurse -Force }
}
