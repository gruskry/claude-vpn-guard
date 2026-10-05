$ErrorActionPreference='Stop'
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$root=Split-Path $PSScriptRoot -Parent
$testDirectory=Join-Path $env:TEMP ('ClaudeGuardDiscoveryTest-'+[guid]::NewGuid().ToString('N'))
$oldRoaming=$env:APPDATA; $oldLocal=$env:LOCALAPPDATA; $oldProfile=$env:USERPROFILE
try {
    New-Item -ItemType Directory -Path $testDirectory | Out-Null
    foreach ($name in @('guard-common.ps1','guard-network.ps1')) { Copy-Item -LiteralPath (Join-Path $root $name) -Destination $testDirectory }
    $customDirectory=Join-Path $testDirectory 'Custom App'
    New-Item -ItemType Directory -Path $customDirectory | Out-Null
    $desktop=Join-Path $customDirectory 'Claude.exe'; [IO.File]::WriteAllText($desktop,'fixture')
    [IO.File]::WriteAllText((Join-Path $customDirectory 'helper.exe'),'fixture')
    $configPath=Join-Path $testDirectory 'config.json'
    @{desktop_path=$desktop} | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
    $env:APPDATA=Join-Path $testDirectory 'Roaming'; $env:LOCALAPPDATA=Join-Path $testDirectory 'Local'; $env:USERPROFILE=Join-Path $testDirectory 'Profile'
    . "$testDirectory\guard-common.ps1"
    function Get-AppxPackage { [CmdletBinding()]param(); @() }
    function Get-Command { param($Name,$CommandType,$ErrorAction); $null }
    $inventory=Get-GuardInventory
    # Hosted Windows runners can expose TEMP through a short (8.3) path.
    # Inventory intentionally expands that alias to the executable's full path.
    $canonicalDesktop=[IO.Path]::GetFullPath($desktop)
    Assert ($inventory.Programs.Count -eq 2 -and $inventory.DesktopPaths[0] -eq $canonicalDesktop -and $inventory.PreferredDesktop -eq $canonicalDesktop) 'custom app and helper paths receive coverage'
    foreach ($invalid in @('relative\Claude.exe','\\server\share\Claude.exe',42)) {
        @{desktop_path=$invalid} | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
        try { Get-GuardInventory; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'unsafe custom path is rejected' }
    }
    $link=Join-Path $testDirectory 'Linked App'
    New-Item -ItemType Junction -Path $link -Target $customDirectory | Out-Null
    @{desktop_path=(Join-Path $link 'Claude.exe')} | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
    try { Get-GuardInventory; throw 'unexpected success' } catch { Assert ($_.Exception.Message -ne 'unexpected success') 'junction installation is rejected' }
    Write-Host 'PASS: custom Desktop/helper discovery, relative/UNC/type rejection and junction isolation'
} finally {
    $env:APPDATA=$oldRoaming; $env:LOCALAPPDATA=$oldLocal; $env:USERPROFILE=$oldProfile
    if ((Split-Path $testDirectory -Parent) -eq $env:TEMP) { Remove-Item -LiteralPath $testDirectory -Recurse -Force }
}
