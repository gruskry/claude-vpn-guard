# Launch orchestration shared by the tray application and terminal launcher.
. "$PSScriptRoot\guard-common.ps1"
. "$PSScriptRoot\guard-privacy.ps1"
. "$PSScriptRoot\guard-diagnostics.ps1"
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
function Get-PublicIPLocation($Vpn) {
    if (-not $Vpn) { throw 'A verified VPN adapter is required before checking location.' }
    $source=Get-GuardVpnSourceAddress $Vpn
    foreach ($url in @('https://ipapi.co/json/', 'https://ipinfo.io/json', 'https://api.myip.com')) {
        try {
            $response = Invoke-GuardBoundLocationRequest $url $source $Vpn.ifIndex
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
    $config = [pscustomobject]@{ target_timezone=''; auto_detect=$true; change_timezone=$true; auto_refresh=$true; disable_cli_telemetry=$true; clean_diagnostics_before_launch=$true; diagnostic_log=$true }
    $path = Join-Path $PSScriptRoot 'config.json'
    if (Test-Path -LiteralPath $path) {
        $data = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        foreach ($key in @('auto_detect','change_timezone','auto_refresh','disable_cli_telemetry','clean_diagnostics_before_launch','diagnostic_log')) {
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
function Read-GuardSetupResult([guid]$RequestId) {
    $path=Get-GuardSetupResultPath
    try {
        if (-not (Test-Path -LiteralPath $path) -or (Get-Item -LiteralPath $path).Length -gt 16KB) { return $null }
        Assert-GuardPrivateFilePath $path
        $result=Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($result.Version -ne 1 -or $result.RequestId -ne $RequestId.ToString() -or $result.Ok -isnot [bool] -or $result.Message -isnot [string] -or $result.Message.Length -gt 2000) { return $null }
        return $result
    } catch { return $null }
}
function Invoke-GuardFirewallRepair([string]$CoverageFailure) {
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $requestId=[guid]::NewGuid()
    $process=Start-Process -FilePath $shell -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSScriptRoot\setup-firewall.ps1`" -NonInteractive -ResultId $requestId" -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
    try {
        $result=Read-GuardSetupResult $requestId
        if ($process.ExitCode -ne 0 -or ($result -and -not $result.Ok)) {
            $reason=if ($result -and $result.Message) { $result.Message } else { 'Administrative permission was denied, or setup did not provide its result.' }
            if ($CoverageFailure) { $reason+=' Initial verification: '+$CoverageFailure }
            throw ('Firewall refresh failed. '+$reason+' Launch blocked.')
        }
    }
    finally { $process.Dispose() }
}
function Get-GuardVerifiedStatus([switch]$AutoRepair) {
    try { return Get-GuardProtectionStatus }
    catch {
        if (-not $AutoRepair -or -not $_.Exception.Data['GuardRepairable']) { throw }
        Write-GuardDiagnosticEvent 'refresh-requested'
        Invoke-GuardFirewallRepair -CoverageFailure $_.Exception.Message
        # A setup exit code is not proof of effective protection.
        $verified=Get-GuardProtectionStatus
        Write-GuardDiagnosticEvent 'refresh-verified'
        return $verified
    }
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
function Start-GuardNativeProcess([string]$Path, [string[]]$Arguments, [switch]$DisableTelemetry) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Path
    $info.Arguments = (@($Arguments | ForEach-Object { ConvertTo-GuardNativeArgument $_ }) -join ' ')
    $info.UseShellExecute = $false
    $info.WorkingDirectory = (Get-Location).ProviderPath
    if ($DisableTelemetry) {
        $info.EnvironmentVariables['DISABLE_TELEMETRY']='1'
        $info.EnvironmentVariables['DISABLE_ERROR_REPORTING']='1'
    }
    [Diagnostics.Process]::Start($info)
}
function Stop-GuardProcessTree($Process) {
    # Stop only an identified Claude tree, never by display name.
    & "$env:SystemRoot\System32\taskkill.exe" /PID $Process.Id /T /F 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -and -not $Process.HasExited) { throw "Could not stop Claude PID $($Process.Id)." }
}
function Stop-GuardRunningProcesses($Inventory, $StartedProcess) {
    try { $snapshot=Get-GuardProcessSnapshot $Inventory }
    catch { $snapshot=[pscustomobject]@{Processes=@();Errors=@('Process discovery failed.')} }
    $processes=@($snapshot.Processes)
    $failures=New-Object 'System.Collections.Generic.List[string]'
    foreach ($failure in @($snapshot.Errors)) { $failures.Add($failure) }
    if ($StartedProcess) { $processes += $StartedProcess }
    foreach ($process in $processes | Sort-Object Id -Unique) {
        try { if (-not $process.HasExited) { Stop-GuardProcessTree $process } }
        catch { $failures.Add("Claude PID $($process.Id) could not be stopped.") }
    }
    if ($failures.Count) { throw (($failures.ToArray() -join ' ')+' Close remaining Claude windows immediately.') }
}
function Write-GuardLaunchProgress([string]$Stage, [bool]$Enabled) {
    if ($Enabled) { Write-Host "[ClaudeGuardProgress]$Stage" }
}
function Invoke-GuardLaunch([switch]$LaunchCLI, [string[]]$CliArguments, [string]$TargetTimezone, [switch]$NoTimezoneChange, [switch]$ProgressMessages) {
    $reportProgress=$ProgressMessages -and -not $LaunchCLI
    $mutex = New-Object Threading.Mutex($false, 'Global\ClaudeVPNGuard_LaunchSession')
    $locked = $false
    $inventory = $null
    $startedProcess = $null
    $changeMonitor = $null
    try {
        try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked=$true }
        if (-not $locked) { throw 'Another guarded session is running. Close it before launching another.' }
        Write-GuardLaunchProgress 'initializing' $reportProgress
        Restore-GuardTimezone
        $config = Get-GuardConfig
        $script:GuardDiagnosticLoggingEnabled=[bool]$config.diagnostic_log
        Write-GuardLaunchProgress 'discovery' $reportProgress
        $discovered=Get-GuardInventory
        if (@(Get-GuardRunningProcesses $discovered).Count) { throw 'Claude is already running. Close it before starting a guarded session.' }
        Write-GuardLaunchProgress 'firewall' $reportProgress
        $status = Get-GuardVerifiedStatus -AutoRepair:$config.auto_refresh
        $inventory = $status.Inventory
        if (@(Get-GuardRunningProcesses $inventory).Count) { throw 'Claude is already running. Close it before starting a guarded session.' }
        if ($config.clean_diagnostics_before_launch) { Write-GuardLaunchProgress 'privacy' $reportProgress; $privacy=Invoke-GuardPrivacy -Clean; Write-GuardDiagnosticEvent 'privacy-cleaned' $privacy.Fields }
        Write-GuardLaunchProgress 'location' $reportProgress
        $location = Get-PublicIPLocation $status.Vpn
        if (-not $location) { throw 'Public IP/country could not be verified. Launch blocked.' }
        if ($script:GuardBlockedCountries -contains $location.CountryCode) { throw "Country $($location.CountryCode) is blocked by the local launch policy." }
        Write-Host "Verified VPN launch preflight; country: $($location.CountryCode)."
        $target = $TargetTimezone
        if (-not $target) {
            if ($config.auto_detect) { $target = $script:GuardTimezoneMap[$location.IanaTz] }
            else { $target = $config.target_timezone }
        }
        if (-not $NoTimezoneChange -and $config.change_timezone -and $target) { Write-GuardLaunchProgress 'timezone' $reportProgress; Start-GuardTimezone $target }
        $changeMonitor=New-GuardChangeMonitor $inventory
        if ($LaunchCLI) {
            if (-not $inventory.CliPath -or @($inventory.Programs) -notcontains $inventory.CliPath) { throw 'A native claude.exe on PATH is required. npm/Node wrappers are not launched by Guard.' }
            $status = Get-GuardVerifiedStatus -AutoRepair:$config.auto_refresh
            $inventory=$status.Inventory
            $startedProcess = Start-GuardNativeProcess $inventory.CliPath $CliArguments -DisableTelemetry:$config.disable_cli_telemetry
            Write-GuardDiagnosticEvent 'cli-started'
        } else {
            $desktopPaths = @($inventory.DesktopPaths)
            if (-not $desktopPaths.Count) { throw 'Claude Desktop executable was not found.' }
            $desktop = if ($inventory.PreferredDesktop) { $inventory.PreferredDesktop } else { $desktopPaths | Sort-Object { if ($_ -match '\\app-') { 0 } else { 1 } }, { (Get-Item -LiteralPath $_).LastWriteTimeUtc } -Descending | Select-Object -First 1 }
            # Recheck after location/timezone work, immediately before creating the process.
            Write-GuardLaunchProgress 'final-check' $reportProgress
            $status = Get-GuardVerifiedStatus -AutoRepair:$config.auto_refresh
            if (@($status.Inventory.DesktopPaths) -notcontains $desktop) { throw 'Claude changed during preflight. Start Guard again.' }
            Write-GuardLaunchProgress 'starting' $reportProgress
            $startedProcess = Start-GuardNativeProcess $desktop @()
            Write-GuardDiagnosticEvent 'desktop-started'
        }
        if (-not $startedProcess) { throw 'Claude process could not be started.' }
        Write-GuardLaunchProgress 'started' $reportProgress
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        $seen = $false
        $nextCheck = [DateTime]::MinValue
        while ($true) {
            Start-Sleep -Milliseconds 500
            if ($LaunchCLI) {
                if ($startedProcess.HasExited) { Write-GuardDiagnosticEvent 'session-ended'; return $startedProcess.ExitCode }
            } else {
                $running = @(Get-GuardRunningProcesses $inventory)
                if ($running.Count) { $seen=$true }
            }
            if ($changeMonitor.Consume() -or [DateTime]::UtcNow -ge $nextCheck -or (-not $LaunchCLI -and -not $running.Count)) {
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
                    throw $coverageFailure
                }
                $nextCheck = [DateTime]::UtcNow.AddSeconds(1)
            }
            if (-not $LaunchCLI) {
                $running = @(Get-GuardRunningProcesses $inventory)
                if ($running.Count) { $seen=$true }
                elseif ($seen) { Write-GuardDiagnosticEvent 'session-ended'; return 0 }
                elseif ([DateTime]::UtcNow -gt $deadline) { throw 'Claude did not become visible as a running process within 15 seconds.' }
            }
        }
    } catch {
        $launchFailure=$_
        Write-GuardDiagnosticEvent 'launch-blocked'
        if ($startedProcess) {
            try {
                try { $current=Get-GuardInventory; $inventory.Programs=@(@($inventory.Programs)+@($current.Programs) | Sort-Object -Unique) } catch { }
                Stop-GuardRunningProcesses $inventory $startedProcess
                if ($config.auto_refresh -and $launchFailure.Exception.Data['GuardRepairable']) { Invoke-GuardFirewallRepair; $null=Get-GuardProtectionStatus }
            } catch { Write-GuardDiagnosticEvent 'shutdown-failed'; Write-Warning 'Claude shutdown or firewall refresh failed. Close Claude and check protection before relaunching.' }
        }
        throw $launchFailure
    } finally {
        try {
            if ($locked) { try { Restore-GuardTimezone } finally { $mutex.ReleaseMutex() } }
        } finally {
            if ($changeMonitor) { $changeMonitor.Dispose() }
            $mutex.Dispose()
            if ($startedProcess) { $startedProcess.Dispose() }
        }
    }
}
