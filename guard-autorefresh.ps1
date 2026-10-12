#Requires -Version 5.1
# Elevated scheduled-task watcher. Runs only from the administrator-only copy
# made by setup-firewall.ps1 and refreshes rules after Claude updates.
. "$PSScriptRoot\guard-common.ps1"
function Get-GuardInventoryFingerprint($Inventory) {
    (@($Inventory.Programs) + @($Inventory.Packages | ForEach-Object { "$($_.Sid)|$($_.Root)" })) -join "`n"
}
function Invoke-GuardBackgroundSetup {
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $process=Start-Process -FilePath $shell -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSScriptRoot\setup-firewall.ps1`" -NonInteractive -Background" -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
    try { return $process.ExitCode } finally { $process.Dispose() }
}
function Save-GuardAutoRefreshStatus([bool]$Ok, [int]$Programs) {
    try { Save-GuardAdministratorJson (Join-Path $env:ProgramData 'ClaudeVPNGuard\auto-refresh-status.json') ([pscustomobject]@{Version=1;Utc=[DateTime]::UtcNow.ToString('o');Ok=$Ok;Programs=$Programs}) }
    catch { Write-Warning 'Automatic refresh status could not be saved.' }
}
function Start-GuardAutoRefreshLoop([int]$PollSeconds=30, [int]$CheckMinutes=10, [int]$RetryMinutes=2, [int]$MaxIterations=0) {
    $last=$null; $nextCheck=[DateTime]::MinValue; $monitor=$null; $iteration=0
    try {
        while ($MaxIterations -le 0 -or $iteration -lt $MaxIterations) {
            $iteration++
            $changed=($monitor -and $monitor.Consume())
            try { $inventory=Get-GuardInventory; $fingerprint=Get-GuardInventoryFingerprint $inventory }
            catch { $inventory=$null; $fingerprint=$null }
            # A changed executable set, a file or network event, or the periodic
            # check runs the full verification in a separate setup process.
            if ($fingerprint -ne $last -or $changed -or [DateTime]::UtcNow -ge $nextCheck) {
                $exit=$(try { Invoke-GuardBackgroundSetup } catch { -1 })
                $last=$fingerprint
                $nextCheck=[DateTime]::UtcNow.AddMinutes($(if ($exit -eq 0) { $CheckMinutes } else { $RetryMinutes }))
                Save-GuardAutoRefreshStatus ($exit -eq 0) $(if ($inventory) { @($inventory.Programs).Count } else { 0 })
                if ($inventory) {
                    if ($monitor) { $monitor.Dispose(); $monitor=$null }
                    try { $monitor=New-GuardChangeMonitor $inventory } catch { $monitor=$null }
                }
            }
            if ($MaxIterations -gt 0 -and $iteration -ge $MaxIterations) { break }
            for ($second=0; $second -lt $PollSeconds; $second++) {
                Start-Sleep -Seconds 1
                if ($monitor -and $monitor.Consume()) {
                    # Let an installer finish writing files before verifying.
                    Start-Sleep -Seconds 5
                    $null=$monitor.Consume()
                    $nextCheck=[DateTime]::MinValue
                    break
                }
            }
        }
    } finally { if ($monitor) { $monitor.Dispose() } }
}
if ($MyInvocation.InvocationName -ne '.') { Start-GuardAutoRefreshLoop }
