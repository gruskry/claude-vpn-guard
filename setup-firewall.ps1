#Requires -Version 5.1
param([switch]$Uninstall, [switch]$NonInteractive)
. "$PSScriptRoot\guard-common.ps1"
function Restore-GuardDnsConfiguration {
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSScriptRoot\enable-dns-leak-protection.ps1`" -Restore -NonInteractive"
    $process=Start-Process -FilePath $shell -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
    if ($process.ExitCode -ne 0) { throw 'DNS restore failed. Firewall rules were retained; retry removal.' }
}
function Invoke-GuardFirewallSetup([switch]$Uninstall) {
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
    $adapters = @(Get-GuardAdapters)
    if (-not $adapters.Count) { throw 'No physical adapters found. No rules were changed.' }
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
            $parameters = @{ Name=$name; DisplayName="Claude Guard: block on $($specification.Alias)"; Direction='Outbound'; Action='Block'; Profile='Any'; InterfaceAlias=$specification.Alias; Enabled='True'; PolicyStore='PersistentStore'; ErrorAction='Stop' }
            if ($specification.Program) { $parameters.Program=$specification.Program } else { $parameters.Package=$specification.Package }
            New-NetFirewallRule @parameters | Out-Null
        }
        Assert-GuardCoverage $specifications $newNames.ToArray()
        Save-GuardFirewallState ([pscustomobject]@{ Version=1; Rules=$newNames.ToArray(); Adapters=@($adapters | ForEach-Object { [pscustomobject]@{ Guid="$($_.InterfaceGuid)"; Alias=$_.Name } }) })
    } catch {
        $failure = $_
        foreach ($name in $newNames) { Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
        throw "Setup failed; previous rules retained. $failure"
    }
    foreach ($rule in $oldRules) { $rule | Remove-NetFirewallRule -ErrorAction Stop }
    Write-Host "Verified $($newNames.Count) block rules. Re-run setup after adapter or Claude installation changes."
}
if ($MyInvocation.InvocationName -ne '.') {
    try {
        $arguments = '-NonInteractive'
        if ($Uninstall) { $arguments += ' -Uninstall' }
        $elevatedExit = Invoke-GuardElevation $PSCommandPath $arguments
        if ($null -ne $elevatedExit) { exit $elevatedExit }
        $mutex = New-Object Threading.Mutex($false, 'Global\ClaudeVPNGuard_FirewallSetup')
        $locked = $false
        try {
            try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked=$true }
            if (-not $locked) { throw 'Another firewall setup/removal is running.' }
            Invoke-GuardFirewallSetup -Uninstall:$Uninstall
        } finally { if ($locked) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
        exit 0
    } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
