#Requires -Version 5.1
param([switch]$Uninstall, [switch]$NonInteractive, [string]$VpnGuid, [switch]$ReselectVpn, [switch]$ConsoleSetup, [switch]$PauseAfterElevation, [guid]$ResultId=[guid]::Empty, [switch]$Background, [string]$OwnerSid)
[Console]::OutputEncoding=[Text.Encoding]::UTF8
. "$PSScriptRoot\guard-common.ps1"
function Restore-GuardDnsConfiguration {
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSScriptRoot\enable-dns-leak-protection.ps1`" -Restore -NonInteractive"
    $process=Start-Process -FilePath $shell -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
    if ($process.ExitCode -ne 0) { throw 'DNS restore failed. Firewall rules were retained; retry removal.' }
}
function Assert-GuardSetupCoverage($Vpn, $InitialAdapters, [string[]]$RuleNames, [switch]$DuringRefresh, [switch]$AllowVpnDown) {
    for ($attempt=0; $attempt -lt 3; $attempt++) {
        try {
            $current=@(Get-GuardAdapters $Vpn -AllowVpnDown:$AllowVpnDown)
            foreach ($adapter in $current) {
                if ($adapter.Ipv4Present -is [bool] -and -not $adapter.Ipv4Present) { continue }
                if (-not @($InitialAdapters | Where-Object { $_.InterfaceGuid -eq $adapter.InterfaceGuid -and $_.Name -eq $adapter.Name }).Count) {
                    Throw-GuardCoverageChanged 'Adapters changed during setup. Retry with the current adapters.'
                }
            }
            $verification=@($current)
            foreach ($adapter in $InitialAdapters) {
                if (-not @($current | Where-Object { $_.InterfaceGuid -eq $adapter.InterfaceGuid -and $_.Name -eq $adapter.Name }).Count) {
                    $verification += [pscustomobject]@{Name=$adapter.Name;InterfaceGuid=$adapter.InterfaceGuid;Status='Not Present';IpInterfacePresent=$false;Ipv4Present=$adapter.Ipv4Present}
                }
            }
            $specifications=@(Get-GuardSpecifications (Get-GuardInventory) $verification)
            Assert-GuardCoverage $specifications $RuleNames -DuringRefresh:$DuringRefresh
            return
        } catch {
            if (-not $_.Exception.Data['GuardRepairable'] -or $attempt -eq 2) { throw }
            Write-Host 'Adapter or rule state changed during verification; checking the current state again...'
            Start-Sleep -Milliseconds 500
        }
    }
}
function Invoke-GuardFirewallSetup([switch]$Uninstall, [string]$VpnGuid, [switch]$ReselectVpn, [switch]$Background) {
    if ($Uninstall) {
        Write-Host '[1/3] Restoring any saved DNS configuration...'
        Restore-GuardDnsConfiguration
        Write-Host '[2/3] Removing Claude Guard firewall rules...'
        $rules = @(Get-GuardRules)
        foreach ($rule in $rules) { $rule | Remove-NetFirewallRule -ErrorAction Stop }
        if (@(Get-GuardRules).Count) { throw 'Some Guard firewall rules remain. Retry removal.' }
        Write-Host '[3/3] Removing firewall recovery state...'
        $path = Get-GuardStatePath
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
        Write-Host 'Claude Guard rules removed; any saved DNS recovery state was processed.'
        return
    }
    Write-Host '[1/7] Checking Windows Firewall profiles and the selected VPN...'
    Assert-GuardProfiles
    if (-not $VpnGuid -and -not $ReselectVpn -and (Test-Path -LiteralPath (Get-GuardStatePath))) {
        $previous=Get-Content -LiteralPath (Get-GuardStatePath) -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($previous.Version -eq 2) { $VpnGuid=$previous.VpnGuid }
    }
    if ($Background) {
        # Unattended refresh keeps the interactive VPN choice and never repins.
        $vpn=Get-GuardPinnedVpnAdapter $VpnGuid
    } else {
        $vpn=Get-GuardVpnAdapter $VpnGuid
        Assert-GuardNoProxy
    }
    $adapters = @(Get-GuardAdapters $vpn -AllowVpnDown:$Background)
    if (-not $adapters.Count) { throw 'No untrusted adapters found. No rules were changed.' }
    Write-Host '[2/7] Finding installed Claude executables...'
    $inventory = Get-GuardInventory
    if (-not @($inventory.Programs).Count) { throw 'No native Claude executables found. No rules were changed.' }
    $specifications = @(Get-GuardSpecifications $inventory $adapters)
    $oldRules = @(Get-GuardRules)
    $generation = [guid]::NewGuid().ToString('N')
    $newNames = New-Object 'System.Collections.Generic.List[string]'
    try {
        Write-Host "[3/7] Creating $($specifications.Count) rules for $($adapters.Count) adapters; VPN: '$($vpn.Name)'..."
        foreach ($specification in $specifications) {
            $name = "$script:GuardRulePrefix-$generation-$($newNames.Count)"
            $newNames.Add($name)
            $parameters = @{ Name=$name; DisplayName="Claude Guard: block on $($specification.Alias)"; Direction='Outbound'; Action='Block'; Profile='Any'; Enabled='True'; PolicyStore='PersistentStore'; ErrorAction='Stop' }
            if ($specification.Alias -and $specification.Alias -ne 'Any') { $parameters.InterfaceAlias=$specification.Alias }
            if ($specification.RemoteAddress) { $parameters.RemoteAddress=$specification.RemoteAddress }
            if ($specification.Program) { $parameters.Program=$specification.Program } else { $parameters.Package=$specification.Package }
            New-NetFirewallRule @parameters | Out-Null
            if ($newNames.Count % 10 -eq 0 -or $newNames.Count -eq $specifications.Count) { Write-Host "  Created $($newNames.Count)/$($specifications.Count) rules." }
        }
        Write-Host '[4/7] Verifying new rules. Previous rules remain in place...'
        Assert-GuardSetupCoverage $vpn $adapters $newNames.ToArray() -DuringRefresh -AllowVpnDown:$Background
        # Recheck the tunnel before committing. Never repin automatically during a refresh.
        if ($Background) { $null=Get-GuardPinnedVpnAdapter $vpn.InterfaceGuid } else { $null=Get-GuardVpnAdapter $vpn.InterfaceGuid }
        Write-Host '[5/7] Saving the verified rule generation...'
        Save-GuardFirewallState ([pscustomobject]@{ Version=2; VpnGuid="$($vpn.InterfaceGuid)"; Rules=$newNames.ToArray(); Adapters=@($adapters | ForEach-Object { [pscustomobject]@{ Guid="$($_.InterfaceGuid)"; Alias=$_.Name } }) })
    } catch {
        $failure = $_
        Write-Host "Setup failed before commit: $($failure.Exception.Message)"
        Write-Host 'Rolling back new rules; previous rules are retained...'
        foreach ($name in $newNames) { Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
        throw "Setup failed; previous rules retained. $failure"
    }
    Write-Host '[6/7] Retiring the previous Guard rules...'
    foreach ($rule in $oldRules) { $rule | Remove-NetFirewallRule -ErrorAction Stop }
    # Windows may have optimized new rules as duplicates while the old
    # generation existed. Require the committed generation to stand alone now.
    Write-Host '[7/7] Verifying final firewall coverage...'
    Assert-GuardSetupCoverage $vpn $adapters $newNames.ToArray() -AllowVpnDown:$Background
    Write-Host "Verified $($newNames.Count) block rules; VPN pinned to '$($vpn.Name)'."
}
function Invoke-GuardBackgroundRefresh {
    # Rebuild rules only when Claude executables or adapters are no longer covered.
    $path=Get-GuardStatePath
    if (-not (Test-Path -LiteralPath $path)) { Write-Host 'Firewall setup has not completed; nothing to refresh.'; return 'no-state' }
    $state=Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($state.Version -ne 2 -or -not $state.VpnGuid -or -not @($state.Rules).Count) { throw 'Firewall state needs an interactive setup-firewall.cmd run.' }
    Assert-GuardProfiles
    $vpn=Get-GuardPinnedVpnAdapter $state.VpnGuid
    try {
        $adapters=@(Get-GuardAdapters $vpn -AllowVpnDown)
        foreach ($adapter in $adapters) {
            if ($adapter.Ipv4Present -is [bool] -and -not $adapter.Ipv4Present) { continue }
            if (-not @($state.Adapters | Where-Object { $_.Guid -eq "$($adapter.InterfaceGuid)" -and $_.Alias -eq $adapter.Name }).Count) { Throw-GuardCoverageChanged "New or renamed adapter '$($adapter.Name)'." }
        }
        $inventory=Get-GuardInventory
        if (-not @($inventory.Programs).Count) { Write-Host 'No Claude executables found; existing rules retained.'; return 'no-claude' }
        Assert-GuardCoverage @(Get-GuardSpecifications $inventory $adapters) @($state.Rules)
        Write-Host 'Firewall coverage is current.'
        return 'current'
    } catch { if (-not $_.Exception.Data['GuardRepairable']) { throw }; Write-Host "Refreshing rules: $($_.Exception.Message)" }
    Invoke-GuardFirewallSetup -VpnGuid $state.VpnGuid -Background
    return 'refreshed'
}
$script:GuardAutoRefreshTask='ClaudeVPNGuard Auto Refresh'
$script:GuardAutoRefreshFiles=@('guard-common.ps1','guard-network.ps1','setup-firewall.ps1','guard-autorefresh.ps1')
function Get-GuardAutoRefreshDirectory { Join-Path $env:ProgramData 'ClaudeVPNGuard\auto-refresh' }
function Unregister-GuardAutoRefresh {
    $task=Get-ScheduledTask -TaskName $script:GuardAutoRefreshTask -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $script:GuardAutoRefreshTask -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $script:GuardAutoRefreshTask -Confirm:$false -ErrorAction Stop
    }
    $directory=Get-GuardAutoRefreshDirectory
    if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction Stop }
}
function Register-GuardAutoRefresh([string]$OwnerSid, [string]$SourceDirectory=$PSScriptRoot) {
    # The task runs elevated without a prompt, so it must execute only copies in
    # an administrator-only folder, never scripts in a user-writable install.
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if ($OwnerSid -and $OwnerSid -ne $identity.User.Value) {
        Write-Warning 'Setup was approved with a different administrator account. Automatic rule refresh was not enabled; rerun setup from the Windows account that uses Claude.'
        return $false
    }
    $directory=Get-GuardAutoRefreshDirectory
    if ([IO.Path]::GetFullPath($SourceDirectory).TrimEnd('\') -ieq [IO.Path]::GetFullPath($directory).TrimEnd('\')) { throw 'Automatic refresh cannot reinstall itself from its own folder.' }
    Stop-ScheduledTask -TaskName $script:GuardAutoRefreshTask -ErrorAction SilentlyContinue
    Initialize-GuardAdministratorDirectory (Split-Path $directory -Parent)
    Initialize-GuardAdministratorDirectory $directory
    foreach ($name in @($script:GuardAutoRefreshFiles + 'config.json')) {
        $target=Join-Path $directory $name
        # Recreate files so they inherit the folder ACL instead of keeping an old one.
        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force -ErrorAction Stop }
        $source=Join-Path $SourceDirectory $name
        if (Test-Path -LiteralPath $source -PathType Leaf) { Copy-Item -LiteralPath $source -Destination $target -ErrorAction Stop }
        elseif ($name -ne 'config.json') { throw "Automatic refresh file is missing: $name" }
    }
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action=New-ScheduledTaskAction -Execute $shell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$(Join-Path $directory 'guard-autorefresh.ps1')`""
    # The watcher runs for the whole logon; the repeating trigger restarts it if it stopped.
    $triggers=@((New-ScheduledTaskTrigger -AtLogOn -User $identity.Name), (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15)))
    # S4U: the user's own profile and Claude paths, elevated, no stored password, no window.
    $principal=New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType S4U -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $script:GuardAutoRefreshTask -Description 'Refreshes Claude VPN Guard firewall rules after Claude updates.' -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName $script:GuardAutoRefreshTask -ErrorAction Stop
    return $true
}
if ($MyInvocation.InvocationName -ne '.') {
    $executedLocally=$false; $setupOk=$false; $setupMessage=''
    try {
        $arguments = '-NonInteractive'
        # Only a manually opened console waits for a key. Installer and tray
        # maintenance must remain unattended after administrative approval.
        if ($ConsoleSetup) { $arguments += ' -PauseAfterElevation'; Write-Host 'Progress and error details will appear in the administrator window.' }
        if ($Uninstall) { $arguments += ' -Uninstall' }
        if ($VpnGuid) { $arguments += ' -VpnGuid ' + ([guid]$VpnGuid).ToString() }
        if ($ReselectVpn) { $arguments += ' -ReselectVpn' }
        if ($ResultId -ne [guid]::Empty) { $arguments += ' -ResultId '+$ResultId.ToString() }
        if ($Background) {
            # The scheduled task is already elevated. Never show a prompt from it.
            $principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Background refresh requires the elevated scheduled task.' }
        } else {
            # The elevated copy compares this with its own account before creating the task.
            $owner=if ($OwnerSid) { ([Security.Principal.SecurityIdentifier]$OwnerSid).Value } else { [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
            $arguments += ' -OwnerSid '+$owner
            $elevatedExit = Invoke-GuardElevation $PSCommandPath $arguments
            if ($null -ne $elevatedExit) { exit $elevatedExit }
        }
        $executedLocally=$true
        $mutex = New-Object Threading.Mutex($false, 'Global\ClaudeVPNGuard_FirewallSetup')
        $locked = $false
        try {
            # Interactive setup waits for a running background refresh; the
            # background task retries later instead of queueing.
            $wait=if ($Background) { 0 } else { 120000 }
            try { $locked = $mutex.WaitOne($wait) } catch [Threading.AbandonedMutexException] { $locked=$true }
            if (-not $locked) { throw 'Another firewall setup/removal is running.' }
            if ($Background) { $null=Invoke-GuardBackgroundRefresh }
            else {
                # Stop the task first so it cannot recreate rules during removal.
                if ($Uninstall) { Unregister-GuardAutoRefresh }
                Invoke-GuardFirewallSetup -Uninstall:$Uninstall -VpnGuid $VpnGuid -ReselectVpn:$ReselectVpn
                if (-not $Uninstall) {
                    try { if (Register-GuardAutoRefresh $OwnerSid) { Write-Host 'Automatic rule refresh after Claude updates is enabled.' } }
                    catch { Write-Warning "Firewall rules are verified, but automatic refresh could not be enabled: $($_.Exception.Message)" }
                }
            }
        } finally { if ($locked) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
        $setupOk=$true
        exit 0
    } catch { $setupMessage=$_.Exception.Message; Write-Error $_ -ErrorAction Continue; exit 1 }
    finally {
        if ($executedLocally -and $ResultId -ne [guid]::Empty) {
            try { Save-GuardSetupResult $ResultId $setupOk $setupMessage }
            catch { Write-Warning 'The administrative setup result could not be saved.' }
        }
        if ($PauseAfterElevation) {
            Write-Host 'Administrator operation finished. Press any key to close this window.'
            try { $null=[Console]::ReadKey($true) } catch { Write-Warning 'Console input is unavailable; the window cannot be kept open.' }
        }
    }
}
