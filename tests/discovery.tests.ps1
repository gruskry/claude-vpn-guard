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
    $script:runningClaude=@()
    function Get-Process { param($Name,$ErrorAction); $script:runningClaude }
    $script:services=@()
    function Get-CimInstance { param($ClassName,$Filter,$ErrorAction); $script:services }
    $inventory=Get-GuardInventory
    # Hosted Windows runners can expose TEMP through a short (8.3) path.
    # Inventory intentionally expands that alias to the executable's full path.
    $canonicalDesktop=[IO.Path]::GetFullPath($desktop)
    Assert ($inventory.Programs.Count -eq 2 -and $inventory.DesktopPaths[0] -eq $canonicalDesktop -and $inventory.PreferredDesktop -eq $canonicalDesktop) 'custom app and helper paths receive coverage'
    $scratch=Join-Path $env:APPDATA 'Claude\scratch-workspaces\project\.venv\Scripts'
    $cache=Join-Path $env:LOCALAPPDATA 'Claude\cache\download'
    $version=Join-Path $env:LOCALAPPDATA 'Claude\app-1.2.3'
    $cliVersion=Join-Path $env:APPDATA 'Claude\claude-code\1.2.3'
    # Desktop 2.31+ downloads Claude Code into claude-code\<version>\<build hash>\claude.exe.
    $cliBuild=Join-Path $env:APPDATA 'Claude\claude-code\1.2.4\62f544612ca7'
    $thirdPartyBuild=Join-Path $env:LOCALAPPDATA 'Claude-3p\claude-code\1.2.4\d2e29494ec83'
    foreach ($directory in @($scratch,$cache,$version,$cliVersion,$cliBuild,$thirdPartyBuild)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $scratchExe=Join-Path $scratch 'python.exe'; [IO.File]::WriteAllText($scratchExe,'workspace fixture')
    $cachedExe=Join-Path $cache 'other-app.exe'; [IO.File]::WriteAllText($cachedExe,'cache fixture')
    foreach ($path in @((Join-Path $version 'Claude.exe'),(Join-Path $version 'helper.exe'),(Join-Path $cliVersion 'claude.exe'),(Join-Path $cliBuild 'claude.exe'),(Join-Path $thirdPartyBuild 'claude.exe'))) { [IO.File]::WriteAllText($path,'installation fixture') }
    $scratchExe=(Get-Item -LiteralPath $scratchExe).FullName; $cachedExe=(Get-Item -LiteralPath $cachedExe).FullName
    $versionHelper=(Get-Item -LiteralPath (Join-Path $version 'helper.exe')).FullName
    $versionCli=(Get-Item -LiteralPath (Join-Path $cliVersion 'claude.exe')).FullName
    $buildCli=(Get-Item -LiteralPath (Join-Path $cliBuild 'claude.exe')).FullName
    $thirdPartyCli=(Get-Item -LiteralPath (Join-Path $thirdPartyBuild 'claude.exe')).FullName
    $versionDesktop=(Get-Item -LiteralPath (Join-Path $version 'Claude.exe')).FullName
    $inventory=Get-GuardInventory
    Assert ($inventory.Programs -notcontains $scratchExe -and $inventory.Programs -notcontains $cachedExe) 'user workspace and cache executables must not receive Claude rules'
    Assert ($inventory.Programs -contains $versionHelper -and $inventory.Programs -contains $versionCli) ("versioned Desktop helpers and native CLI remain protected; helper='$versionHelper'; cli='$versionCli'; actual="+(@($inventory.Programs) -join '; '))
    Assert ($inventory.Programs -contains $buildCli -and $inventory.Programs -contains $thirdPartyCli) ("Desktop-managed Claude Code builds remain protected; actual="+(@($inventory.Programs) -join '; '))
    Assert ($inventory.Programs.Count -eq 7) 'short path aliases must not duplicate executable coverage'
    Assert ($inventory.DesktopPaths -contains $versionDesktop) 'versioned Desktop remains selectable through short data-root aliases'
    # A running Claude from an unknown layout is enrolled only with Anthropic's signature.
    $futureDirectory=Join-Path $env:LOCALAPPDATA 'AnthropicClaude\future\build'
    New-Item -ItemType Directory -Path $futureDirectory -Force | Out-Null
    $futureCli=Join-Path $futureDirectory 'claude.exe'; [IO.File]::WriteAllText($futureCli,'unsigned fixture')
    $futureCli=(Get-Item -LiteralPath $futureCli).FullName
    $script:runningClaude=@([pscustomobject]@{Path=$futureCli})
    Assert (-not (Test-GuardAnthropicSignature $futureCli)) 'unsigned fixture is not trusted'
    Assert (-not (Test-GuardAnthropicSignature (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'))) 'a valid non-Anthropic signature is not trusted'
    Assert ((Get-GuardInventory).Programs -notcontains $futureCli) 'unsigned running Claude is not enrolled'
    function Test-GuardAnthropicSignature([string]$Path) { $Path -eq $futureCli }
    $inventory=Get-GuardInventory
    Assert ($inventory.Programs -contains $futureCli -and $inventory.Programs.Count -eq 8) 'signed running Claude from a new layout is enrolled once'
    Assert ($inventory.DesktopPaths -notcontains $futureCli) 'enrolled CLI is not offered as Desktop'
    $script:runningClaude=@()
    # The Cowork VM egresses through its service binary, wherever it is installed.
    $serviceDirectory=Join-Path $testDirectory 'Program Files\Claude Service'
    New-Item -ItemType Directory -Path $serviceDirectory -Force | Out-Null
    $serviceExe=Join-Path $serviceDirectory 'cowork-svc.exe'; [IO.File]::WriteAllText($serviceExe,'service fixture')
    $serviceExe=(Get-Item -LiteralPath $serviceExe).FullName
    $otherExe=Join-Path $serviceDirectory 'claude-helper.exe'; [IO.File]::WriteAllText($otherExe,'service fixture')
    $otherExe=(Get-Item -LiteralPath $otherExe).FullName
    $script:services=@([pscustomobject]@{PathName="`"$serviceExe`" --service"},[pscustomobject]@{PathName="$otherExe -k netsvcs"},[pscustomobject]@{PathName='relative\cowork-svc.exe'})
    function Test-GuardAnthropicSignature([string]$Path) { $Path -eq $serviceExe }
    $inventory=Get-GuardInventory
    Assert ($inventory.Programs -contains $serviceExe) ("signed Cowork service binary is covered; actual="+(@($inventory.Programs) -join '; '))
    Assert ($inventory.Programs -notcontains $otherExe -and $inventory.Programs.Count -eq 8) 'unsigned and relative service paths are not enrolled'
    $script:services=@()
    # A junctioned CLI folder is covered under both the link and the resolved path.
    $linkedStore=Join-Path $testDirectory 'Moved Profile\bin'
    New-Item -ItemType Directory -Path $linkedStore -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $linkedStore 'claude.exe'),'installation fixture')
    New-Item -ItemType Directory -Path (Join-Path $env:USERPROFILE '.local') -Force | Out-Null
    New-Item -ItemType Junction -Path (Join-Path $env:USERPROFILE '.local\bin') -Target $linkedStore | Out-Null
    $linkCli=[IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.local\bin\claude.exe'))
    $targetCli=Get-GuardFinalPath $linkCli
    $inventory=Get-GuardInventory
    Assert ($targetCli -ine $linkCli -and $inventory.Programs -contains $linkCli -and $inventory.Programs -contains $targetCli) ("junction and resolved CLI paths are covered; link='$linkCli'; target='$targetCli'; actual="+(@($inventory.Programs) -join '; '))
    [IO.Directory]::Delete((Join-Path $env:USERPROFILE '.local\bin'))
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
