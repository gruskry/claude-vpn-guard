#Requires -Version 5.1
param([switch]$Uninstall, [switch]$NonInteractive, [string]$VpnGuid, [switch]$ReselectVpn)
[Console]::OutputEncoding=[Text.Encoding]::UTF8
. "$PSScriptRoot\guard-common.ps1"
function Restore-GuardDnsConfiguration {
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSScriptRoot\enable-dns-leak-protection.ps1`" -Restore -NonInteractive"
    $process=Start-Process -FilePath $shell -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
    if ($process.ExitCode -ne 0) { throw 'DNS restore failed. Firewall rules were retained; retry removal.' }
}
function Invoke-GuardFirewallSetup([switch]$Uninstall, [string]$VpnGuid, [switch]$ReselectVpn) {
    if ($Uninstall) {
        Restore-GuardDnsConfiguration
        $rules = @(Get-GuardRules)
        foreach ($rule in $rules) { $rule | Remove-NetFirewallRule -ErrorAction Stop }
        if (@(Get-GuardRules).Count) { throw 'Some Guard firewall rules remain. Retry removal.' }
        $path = Get-GuardStatePath
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
        Write-Host 'Claude Guard rules removed; any saved DNS recovery state was processed.'
        return
    }
    Assert-GuardProfiles
    if (-not $VpnGuid -and -not $ReselectVpn -and (Test-Path -LiteralPath (Get-GuardStatePath))) {
        $previous=Get-Content -LiteralPath (Get-GuardStatePath) -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($previous.Version -eq 2) { $VpnGuid=$previous.VpnGuid }
    }
    $vpn=Get-GuardVpnAdapter $VpnGuid
    Assert-GuardNoProxy
    $adapters = @(Get-GuardAdapters $vpn)
    if (-not $adapters.Count) { throw 'No untrusted adapters found. No rules were changed.' }
    $inventory = Get-GuardInventory
    if (-not @($inventory.Programs).Count) { throw 'No native Claude executables found. No rules were changed.' }
    $specifications = @(Get-GuardSpecifications $inventory $adapters)
    $oldRules = @(Get-GuardRules)
    $generation = [guid]::NewGuid().ToString('N')
    $newNames = New-Object 'System.Collections.Generic.List[string]'
    try {
        foreach ($specification in $specifications) {
            $name = "$script:GuardRulePrefix-$generation-$($newNames.Count)"
            $newNames.Add($name)
            $parameters = @{ Name=$name; DisplayName="Claude Guard: block on $($specification.Alias)"; Direction='Outbound'; Action='Block'; Profile='Any'; Enabled='True'; PolicyStore='PersistentStore'; ErrorAction='Stop' }
            if ($specification.Alias) { $parameters.InterfaceAlias=$specification.Alias }
            if ($specification.Program) { $parameters.Program=$specification.Program } else { $parameters.Package=$specification.Package }
            New-NetFirewallRule @parameters | Out-Null
        }
        Assert-GuardCoverage $specifications $newNames.ToArray()
        # Recheck the tunnel before committing. Never repin automatically during a refresh.
        $null=Get-GuardVpnAdapter $vpn.InterfaceGuid
        Save-GuardFirewallState ([pscustomobject]@{ Version=2; VpnGuid="$($vpn.InterfaceGuid)"; Rules=$newNames.ToArray(); Adapters=@($adapters | ForEach-Object { [pscustomobject]@{ Guid="$($_.InterfaceGuid)"; Alias=$_.Name } }) })
    } catch {
        $failure = $_
        foreach ($name in $newNames) { Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
        throw "Setup failed; previous rules retained. $failure"
    }
    foreach ($rule in $oldRules) { $rule | Remove-NetFirewallRule -ErrorAction Stop }
    Write-Host "Verified $($newNames.Count) block rules; VPN pinned to '$($vpn.Name)'."
}
if ($MyInvocation.InvocationName -ne '.') {
    try {
        $arguments = '-NonInteractive'
        if ($Uninstall) { $arguments += ' -Uninstall' }
        if ($VpnGuid) { $arguments += ' -VpnGuid ' + ([guid]$VpnGuid).ToString() }
        if ($ReselectVpn) { $arguments += ' -ReselectVpn' }
        $elevatedExit = Invoke-GuardElevation $PSCommandPath $arguments
        if ($null -ne $elevatedExit) { exit $elevatedExit }
        $mutex = New-Object Threading.Mutex($false, 'Global\ClaudeVPNGuard_FirewallSetup')
        $locked = $false
        try {
            try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked=$true }
            if (-not $locked) { throw 'Another firewall setup/removal is running.' }
            Invoke-GuardFirewallSetup -Uninstall:$Uninstall -VpnGuid $VpnGuid -ReselectVpn:$ReselectVpn
        } finally { if ($locked) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
        exit 0
    } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
