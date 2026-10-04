# Launch orchestration shared by the tray application and terminal launcher.
. "$PSScriptRoot\guard-common.ps1"
$script:GuardBlockedCountries = @('BY','RU','IR','KP','SY','CU')
$script:GuardTimezoneMap = @{
    'Asia/Tbilisi'='Georgian Standard Time'; 'Europe/Warsaw'='Central European Standard Time'
    'Europe/Berlin'='W. Europe Standard Time'; 'Europe/Paris'='Romance Standard Time'
    'Europe/Amsterdam'='W. Europe Standard Time'; 'Europe/London'='GMT Standard Time'
    'Europe/Vilnius'='FLE Standard Time'; 'Europe/Riga'='FLE Standard Time'; 'Europe/Tallinn'='FLE Standard Time'
    'Europe/Kiev'='FLE Standard Time'; 'Europe/Kyiv'='FLE Standard Time'
    'America/New_York'='Eastern Standard Time'; 'America/Chicago'='Central Standard Time'
    'America/Denver'='Mountain Standard Time'; 'America/Los_Angeles'='Pacific Standard Time'
    'Asia/Yerevan'='Caucasus Standard Time'; 'Asia/Almaty'='Central Asia Standard Time'
    'Asia/Tashkent'='West Asia Standard Time'; 'Europe/Istanbul'='Turkey Standard Time'
    'Asia/Istanbul'='Turkey Standard Time'; 'Asia/Dubai'='Arabian Standard Time'
}
function Get-PublicIPLocation {
    foreach ($url in @('https://ipapi.co/json/', 'https://ipinfo.io/json', 'https://api.myip.com')) {
        try {
            $response = Invoke-RestMethod -Uri $url -TimeoutSec 4 -Headers @{'User-Agent'='ClaudeVPNGuard/1.3'} -ErrorAction Stop
            if ($response.error -or $response.bogon) { continue }
            $country = if ($response.country_code) { $response.country_code } elseif ($response.cc) { $response.cc } else { $response.country }
            $address = $null
            if ($country -isnot [string] -or $country -cnotmatch '^[A-Za-z]{2}$' -or $response.ip -isnot [string] -or
                -not [Net.IPAddress]::TryParse($response.ip, [ref]$address) -or [Net.IPAddress]::IsLoopback($address)) { continue }
            try { $null = New-Object Globalization.RegionInfo($country) } catch { continue }
            # Each endpoint must provide its own complete pair of fields.
            return [pscustomobject]@{ IP=$address.ToString(); CountryCode=$country.ToUpperInvariant(); IanaTz=[string]$response.timezone }
        } catch { continue }
    }
    return $null
}
function Get-GuardConfig {
    $config = [pscustomobject]@{ target_timezone=''; auto_detect=$true; change_timezone=$true }
    $path = Join-Path $PSScriptRoot 'config.json'
    if (Test-Path -LiteralPath $path) {
        $data = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        foreach ($key in @('auto_detect','change_timezone')) {
            if ($data.PSObject.Properties[$key]) {
                if ($data.$key -isnot [bool]) { throw "config.json: $key must be a boolean." }
                $config.$key = $data.$key
            }
        }
        if ($data.PSObject.Properties['target_timezone']) {
            if ($data.target_timezone -isnot [string]) { throw 'config.json: target_timezone must be a string.' }
            $config.target_timezone = $data.target_timezone
        }
    }
    return $config
}
function Get-GuardTimezoneStatePath { Join-Path $env:LOCALAPPDATA 'ClaudeVPNGuard\timezone-state.json' }
function Set-GuardTimezone([string]$Id) {
    [TimeZoneInfo]::FindSystemTimeZoneById($Id) | Out-Null
    $output = & "$env:SystemRoot\System32\tzutil.exe" /s $Id 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Windows refused timezone change ($Id)." }
    [TimeZoneInfo]::ClearCachedData()
    if ((Get-TimeZone).Id -ne $Id) { throw "Timezone change was not applied ($Id)." }
}
function Restore-GuardTimezone {
    $path = Get-GuardTimezoneStatePath
    if (-not (Test-Path -LiteralPath $path)) { return }
    $state = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if (-not $state.Original -or -not $state.Applied -or $state.Version -ne 1) { throw 'Invalid saved timezone state; inspect timezone-state.json before continuing.' }
    # Preserve a later manual change rather than overwriting it with our old value.
    if ((Get-TimeZone).Id -eq $state.Applied) { Set-GuardTimezone $state.Original }
    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
}
function Start-GuardTimezone([string]$Id) {
    if (-not $Id -or (Get-TimeZone).Id -eq $Id) { return }
    [TimeZoneInfo]::FindSystemTimeZoneById($Id) | Out-Null
    $path = Get-GuardTimezoneStatePath
    $directory = Split-Path $path -Parent
    New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
    $temporary = "$path.tmp"
    [pscustomobject]@{ Version=1; Original=(Get-TimeZone).Id; Applied=$Id } | ConvertTo-Json | Set-Content -LiteralPath $temporary -Encoding UTF8 -ErrorAction Stop
    Move-Item -LiteralPath $temporary -Destination $path -Force -ErrorAction Stop
    Set-GuardTimezone $Id
}
function ConvertTo-GuardNativeArgument([AllowEmptyString()][string]$Value) {
    # Windows CommandLineToArgv/CRT escaping; preserve spaces, empty args and literal quotes.
    '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}
function Start-GuardNativeProcess([string]$Path, [string[]]$Arguments) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Path
    $info.Arguments = (@($Arguments | ForEach-Object { ConvertTo-GuardNativeArgument $_ }) -join ' ')
    $info.UseShellExecute = $false
    $info.WorkingDirectory = (Get-Location).ProviderPath
    [Diagnostics.Process]::Start($info)
}
function Get-GuardRunningProcesses($Inventory) {
    @(Get-Process -ErrorAction Stop | Where-Object { try { $_.Path -and @($Inventory.Programs) -contains $_.Path } catch { $false } })
}
function Stop-GuardRunningProcesses($Inventory, $StartedProcess) {
    $processes = @(Get-GuardRunningProcesses $Inventory)
    if ($StartedProcess) { $processes += $StartedProcess }
    foreach ($process in $processes | Sort-Object Id -Unique) {
        if (-not $process.HasExited) {
            # Stop only identified Claude trees, never every process sharing a display name.
            & "$env:SystemRoot\System32\taskkill.exe" /PID $process.Id /T /F 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0 -and -not $process.HasExited) { throw "Could not stop Claude PID $($process.Id). Close Claude immediately." }
        }
    }
}
function Invoke-GuardLaunch([switch]$LaunchCLI, [string[]]$CliArguments, [string]$TargetTimezone, [switch]$NoTimezoneChange) {
    $mutex = New-Object Threading.Mutex($false, 'Global\ClaudeVPNGuard_LaunchSession')
    $locked = $false
    $inventory = $null
    $startedProcess = $null
    try {
        try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked=$true }
        if (-not $locked) { throw 'Another guarded session is running. Close it before launching another.' }
        Restore-GuardTimezone
        $config = Get-GuardConfig
        $status = Get-GuardProtectionStatus
        $inventory = $status.Inventory
        if (@(Get-GuardRunningProcesses $inventory).Count) { throw 'Claude is already running. Close it before starting a guarded session.' }
        $location = Get-PublicIPLocation
        if (-not $location) { throw 'Public IP/country could not be verified. Launch blocked.' }
        if ($script:GuardBlockedCountries -contains $location.CountryCode) { throw "Country $($location.CountryCode) is blocked by the local launch policy." }
        Write-Host "Public IP: $($location.IP); country: $($location.CountryCode). This alone does not verify a VPN."
        $target = $TargetTimezone
        if (-not $target) {
            if ($config.auto_detect) { $target = $script:GuardTimezoneMap[$location.IanaTz] }
            else { $target = $config.target_timezone }
        }
        if (-not $NoTimezoneChange -and $config.change_timezone -and $target) { Start-GuardTimezone $target }
        if ($LaunchCLI) {
            if (-not $inventory.CliPath -or @($inventory.Programs) -notcontains $inventory.CliPath) { throw 'A native claude.exe on PATH is required. npm/Node wrappers are not launched by Guard.' }
            $null = Get-GuardProtectionStatus
            $startedProcess = Start-GuardNativeProcess $inventory.CliPath $CliArguments
        } else {
            $desktopPaths = @($inventory.DesktopPaths)
            if (-not $desktopPaths.Count) { throw 'Claude Desktop executable was not found.' }
            $desktop = $desktopPaths | Sort-Object { if ($_ -match '\\app-') { 0 } else { 1 } }, { (Get-Item -LiteralPath $_).LastWriteTimeUtc } -Descending | Select-Object -First 1
            # Recheck after location/timezone work, immediately before creating the process.
            $null = Get-GuardProtectionStatus
            $startedProcess = Start-GuardNativeProcess $desktop @()
        }
        if (-not $startedProcess) { throw 'Claude process could not be started.' }
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        $seen = $false
        $nextCheck = [DateTime]::MinValue
        while ($true) {
            Start-Sleep -Milliseconds 500
            if ($LaunchCLI) {
                if ($startedProcess.HasExited) { return $startedProcess.ExitCode }
            } else {
                $running = @(Get-GuardRunningProcesses $inventory)
                if ($running.Count) { $seen=$true }
            }
            if ([DateTime]::UtcNow -ge $nextCheck -or (-not $LaunchCLI -and -not $running.Count)) {
                try {
                    $current = Get-GuardInventory
                    $inventory.Programs = @(@($inventory.Programs) + @($current.Programs) | Sort-Object -Unique)
                    $null = Get-GuardProtectionStatus
                }
                catch {
                    $coverageFailure = $_
                    # A failing coverage check can itself be caused by an update/new path.
                    # Include newly discovered executables when stopping, even if the old PID has exited.
                    try {
                        $current = Get-GuardInventory
                        $inventory.Programs = @(@($inventory.Programs) + @($current.Programs) | Sort-Object -Unique)
                    } catch { Write-Warning 'Current executable discovery also failed. Close any remaining Claude processes.' }
                    Stop-GuardRunningProcesses $inventory $startedProcess
                    throw "Protection changed; Claude was stopped. $($coverageFailure.Exception.Message)"
                }
                $nextCheck = [DateTime]::UtcNow.AddSeconds(5)
            }
            if (-not $LaunchCLI) {
                $running = @(Get-GuardRunningProcesses $inventory)
                if ($running.Count) { $seen=$true }
                elseif ($seen) { return 0 }
                elseif ([DateTime]::UtcNow -gt $deadline) { throw 'Claude did not become visible as a running process within 15 seconds.' }
            }
        }
    } finally {
        if ($locked) {
            try { Restore-GuardTimezone } finally { $mutex.ReleaseMutex() }
        }
        $mutex.Dispose()
        if ($startedProcess) { $startedProcess.Dispose() }
    }
}
