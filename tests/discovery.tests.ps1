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
    $scratch=Join-Path $env:APPDATA 'Claude\scratch-workspaces\project\.venv\Scripts'
    $cache=Join-Path $env:LOCALAPPDATA 'Claude\cache\download'
    $version=Join-Path $env:LOCALAPPDATA 'Claude\app-1.2.3'
    $cliVersion=Join-Path $env:APPDATA 'Claude\claude-code\1.2.3'
    foreach ($directory in @($scratch,$cache,$version,$cliVersion)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $scratchExe=Join-Path $scratch 'python.exe'; [IO.File]::WriteAllText($scratchExe,'workspace fixture')
    $cachedExe=Join-Path $cache 'other-app.exe'; [IO.File]::WriteAllText($cachedExe,'cache fixture')
    foreach ($path in @((Join-Path $version 'Claude.exe'),(Join-Path $version 'helper.exe'),(Join-Path $cliVersion 'claude.exe'))) { [IO.File]::WriteAllText($path,'installation fixture') }
    $scratchExe=(Get-Item -LiteralPath $scratchExe).FullName; $cachedExe=(Get-Item -LiteralPath $cachedExe).FullName
    $versionHelper=(Get-Item -LiteralPath (Join-Path $version 'helper.exe')).FullName
    $versionCli=(Get-Item -LiteralPath (Join-Path $cliVersion 'claude.exe')).FullName
    $inventory=Get-GuardInventory
    Assert ($inventory.Programs -notcontains $scratchExe -and $inventory.Programs -notcontains $cachedExe) 'user workspace and cache executables must not receive Claude rules'
    Assert ($inventory.Programs -contains $versionHelper -and $inventory.Programs -contains $versionCli) 'versioned Desktop helpers and native CLI remain protected'
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
