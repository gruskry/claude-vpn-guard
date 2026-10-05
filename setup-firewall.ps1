#Requires -Version 5.1
param([switch]$Uninstall, [switch]$NonInteractive, [string]$VpnGuid, [switch]$ReselectVpn, [switch]$ConsoleSetup, [switch]$PauseAfterElevation, [guid]$ResultId=[guid]::Empty)
[Console]::OutputEncoding=[Text.Encoding]::UTF8
. "$PSScriptRoot\guard-common.ps1"
function Restore-GuardDnsConfiguration {
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSScriptRoot\enable-dns-leak-protection.ps1`" -Restore -NonInteractive"
    $process=Start-Process -FilePath $shell -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
    if ($process.ExitCode -ne 0) { throw 'DNS restore failed. Firewall rules were retained; retry removal.' }
}
function Assert-GuardSetupCoverage($Vpn, $InitialAdapters, [string[]]$RuleNames, [switch]$DuringRefresh) {
    for ($attempt=0; $attempt -lt 3; $attempt++) {
        try {
            $current=@(Get-GuardAdapters $Vpn)
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
function Invoke-GuardFirewallSetup([switch]$Uninstall, [string]$VpnGuid, [switch]$ReselectVpn) {
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
    $vpn=Get-GuardVpnAdapter $VpnGuid
    Assert-GuardNoProxy
    $adapters = @(Get-GuardAdapters $vpn)
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
        Assert-GuardSetupCoverage $vpn $adapters $newNames.ToArray() -DuringRefresh
        # Recheck the tunnel before committing. Never repin automatically during a refresh.
        $null=Get-GuardVpnAdapter $vpn.InterfaceGuid
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
    Assert-GuardSetupCoverage $vpn $adapters $newNames.ToArray()
    Write-Host "Verified $($newNames.Count) block rules; VPN pinned to '$($vpn.Name)'."
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
        $elevatedExit = Invoke-GuardElevation $PSCommandPath $arguments
        if ($null -ne $elevatedExit) { exit $elevatedExit }
        $executedLocally=$true
        $mutex = New-Object Threading.Mutex($false, 'Global\ClaudeVPNGuard_FirewallSetup')
        $locked = $false
        try {
            try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked=$true }
            if (-not $locked) { throw 'Another firewall setup/removal is running.' }
            Invoke-GuardFirewallSetup -Uninstall:$Uninstall -VpnGuid $VpnGuid -ReselectVpn:$ReselectVpn
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
