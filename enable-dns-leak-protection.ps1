#Requires -Version 5.1
param([switch]$Restore, [switch]$NonInteractive)
. "$PSScriptRoot\guard-common.ps1"
$script:DnsStateDirectory=Join-Path $env:ProgramData 'ClaudeVPNGuard'
$script:DnsStatePath=Join-Path $script:DnsStateDirectory 'dns-state.json'
$script:DnsServersV4=@('1.1.1.1','1.0.0.1','8.8.8.8','8.8.4.4')
$script:DnsServersV6=@('2606:4700:4700::1111','2606:4700:4700::1001','2001:4860:4860::8888','2001:4860:4860::8844')

function Get-DnsFamilyName([int]$Family) {
    if ($Family -eq 4) { return 'IPv4' }
    if ($Family -eq 6) { return 'IPv6' }
    throw 'Invalid DNS address family in recovery state.'
}
function Get-DnsServersForFamily([int]$Family) {
    if ($Family -eq 4) { return $script:DnsServersV4 }
    if ($Family -eq 6) { return $script:DnsServersV6 }
    throw 'Invalid DNS address family in recovery state.'
}
function Get-DnsDohTemplateUri([string]$Address) {
    if ($Address -in @('1.1.1.1','1.0.0.1','2606:4700:4700::1111','2606:4700:4700::1001')) { return 'https://cloudflare-dns.com/dns-query' }
    return 'https://dns.google/dns-query'
}
function Get-DnsInterface($Adapter, [int]$Family) {
    $items=@(Get-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -AddressFamily (Get-DnsFamilyName $Family) -ErrorAction Stop)
    if ($items.Count -ne 1) { throw "DNS interface is unavailable for '$($Adapter.Name)' IPv$Family." }
    return $items[0]
}
function Get-DnsDhcpMode([string]$Guid, [int]$Family) {
    $service=if ($Family -eq 4) { 'Tcpip' } elseif ($Family -eq 6) { 'Tcpip6' } else { throw 'Invalid DNS family.' }
    $key="HKLM:\SYSTEM\CurrentControlSet\Services\$service\Parameters\Interfaces\$(([guid]$Guid).ToString('B'))"
    if (-not (Test-Path -LiteralPath $key -ErrorAction Stop)) { return $true }
    $properties=Get-ItemProperty -LiteralPath $key -ErrorAction Stop
    # IP DHCP configuration is independent from DNS automatic/static configuration.
    return [string]::IsNullOrWhiteSpace([string]$properties.NameServer)
}
function Test-DnsServerList($Left, $Right) {
    $first=@($Left | ForEach-Object { ([Net.IPAddress]::Parse([string]$_)).ToString() })
    $second=@($Right | ForEach-Object { ([Net.IPAddress]::Parse([string]$_)).ToString() })
    # Preserve priority as well as the addresses themselves.
    return ($first.Count -eq $second.Count -and ($first -join '|') -eq ($second -join '|'))
}
function Get-DnsTemplates {
    # Query errors differ from an absent template and must abort snapshot/verification.
    @(Get-DnsClientDohServerAddress -ErrorAction Stop)
}
function Test-DnsTemplate($Current, $Expected) {
    return ($null -ne $Current -and $Current.DohTemplate -ceq $Expected.DohTemplate -and
        [bool]$Current.AutoUpgrade -eq [bool]$Expected.AutoUpgrade -and
        [bool]$Current.AllowFallbackToUdp -eq [bool]$Expected.AllowFallbackToUdp)
}
function Get-DnsSnapshot($Adapters) {
    $savedAdapters=@()
    foreach ($adapter in @($Adapters)) {
        $guid=([guid]$adapter.InterfaceGuid).ToString('B')
        $families=@()
        foreach ($family in @(4,6)) {
            $interface=Get-DnsInterface $adapter $family
            $families += [pscustomobject]@{ Family=$family; Automatic=(Get-DnsDhcpMode $guid $family); Servers=@($interface.ServerAddresses); Applied=@(Get-DnsServersForFamily $family) }
        }
        $savedAdapters += [pscustomobject]@{ Guid=$guid; Name=$adapter.Name; Families=$families }
    }
    $templates=Get-DnsTemplates
    $savedTemplates=@()
    foreach ($address in @($script:DnsServersV4 + $script:DnsServersV6)) {
        $existing=@($templates | Where-Object ServerAddress -eq $address)
        if ($existing.Count -gt 1) { throw "Ambiguous DoH template for $address." }
        $original=$null
        if ($existing.Count) { $original=[pscustomobject]@{ DohTemplate=$existing[0].DohTemplate; AutoUpgrade=[bool]$existing[0].AutoUpgrade; AllowFallbackToUdp=[bool]$existing[0].AllowFallbackToUdp } }
        $savedTemplates += [pscustomobject]@{ Address=$address; Original=$original; Applied=[pscustomobject]@{DohTemplate=(Get-DnsDohTemplateUri $address);AutoUpgrade=$true;AllowFallbackToUdp=$false} }
    }
    [pscustomobject]@{ Version=2; Adapters=$savedAdapters; Templates=$savedTemplates }
}
function Assert-DnsStatePath {
    foreach ($path in @($script:DnsStateDirectory,$script:DnsStatePath)) {
        if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'DNS recovery paths must not be links or junctions.' }
    }
}
function Write-DnsState($State) {
    Assert-DnsStatePath
    if (-not (Test-Path -LiteralPath $script:DnsStateDirectory)) { New-Item -ItemType Directory -Path $script:DnsStateDirectory -ErrorAction Stop | Out-Null }
    $directoryAcl=New-Object Security.AccessControl.DirectorySecurity
    $directoryAcl.SetAccessRuleProtection($true,$false)
    $directoryAcl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    foreach ($entry in @(@('S-1-5-18','FullControl'),@('S-1-5-32-544','FullControl'),@('S-1-5-32-545','ReadAndExecute'))) {
        $directoryAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule ([Security.Principal.SecurityIdentifier]$entry[0]),$entry[1],'ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $script:DnsStateDirectory -AclObject $directoryAcl -ErrorAction Stop
    $temporary=Join-Path $script:DnsStateDirectory ([guid]::NewGuid().ToString('N')+'.tmp')
    try {
        $State | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $temporary -Encoding UTF8 -ErrorAction Stop
        $fileAcl=New-Object Security.AccessControl.FileSecurity
        $fileAcl.SetAccessRuleProtection($true,$false)
        $fileAcl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
        foreach ($sid in @('S-1-5-18','S-1-5-32-544')) { $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule ([Security.Principal.SecurityIdentifier]$sid),'FullControl','Allow')) }
        Set-Acl -LiteralPath $temporary -AclObject $fileAcl -ErrorAction Stop
        Move-Item -LiteralPath $temporary -Destination $script:DnsStatePath -Force -ErrorAction Stop
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction Stop } }
}
function Set-DnsTemplates($State) {
    foreach ($template in $State.Templates) {
        $parameters=@{ServerAddress=$template.Address;DohTemplate=$template.Applied.DohTemplate;AutoUpgrade=$true;AllowFallbackToUdp=$false;Confirm=$false;ErrorAction='Stop'}
        if ($template.Original) { Set-DnsClientDohServerAddress @parameters | Out-Null }
        else { Add-DnsClientDohServerAddress @parameters | Out-Null }
    }
}
function Set-DnsAdapters($State, $Adapters) {
    foreach ($saved in $State.Adapters) {
        $adapter=$Adapters | Where-Object { ([guid]$_.InterfaceGuid).ToString('B') -eq $saved.Guid } | Select-Object -First 1
        if (-not $adapter) { throw "Adapter $($saved.Guid) disappeared." }
        foreach ($family in $saved.Families) {
            Set-DnsClientServerAddress -InputObject (Get-DnsInterface $adapter $family.Family) -ServerAddresses $family.Applied -Confirm:$false -ErrorAction Stop | Out-Null
        }
    }
}
function Assert-DnsApplied($State) {
    $adapters=@(Get-GuardAdapters)
    foreach ($saved in $State.Adapters) {
        $adapter=$adapters | Where-Object { ([guid]$_.InterfaceGuid).ToString('B') -eq $saved.Guid } | Select-Object -First 1
        if (-not $adapter) { throw "Adapter $($saved.Guid) disappeared." }
        foreach ($family in $saved.Families) {
            if ((Get-DnsDhcpMode $saved.Guid $family.Family) -or -not (Test-DnsServerList (Get-DnsInterface $adapter $family.Family).ServerAddresses $family.Applied)) { throw "DNS settings were not applied to $($adapter.Name) IPv$($family.Family)." }
        }
    }
    $current=Get-DnsTemplates
    foreach ($template in $State.Templates) {
        if (-not (Test-DnsTemplate ($current | Where-Object ServerAddress -eq $template.Address | Select-Object -First 1) $template.Applied)) { throw "DoH template was not applied for $($template.Address)." }
    }
}
function Restore-DnsSnapshot($State) {
    if ($State.Version -ne 2 -or -not @($State.Adapters).Count -or @($State.Templates).Count -ne 8) { throw 'Unsupported/invalid DNS backup. Retain it for manual recovery.' }
    $conflicts=New-Object 'System.Collections.Generic.List[string]'
    $adapters=@(Get-GuardAdapters)
    foreach ($saved in $State.Adapters) {
        $adapter=$adapters | Where-Object { ([guid]$_.InterfaceGuid).ToString('B') -eq $saved.Guid } | Select-Object -First 1
        if (-not $adapter) { $conflicts.Add("Adapter $($saved.Guid) is missing."); continue }
        foreach ($family in $saved.Families) {
            try {
                $interface=Get-DnsInterface $adapter $family.Family
                $automatic=Get-DnsDhcpMode $saved.Guid $family.Family
                if ($automatic -eq $family.Automatic -and ($automatic -or (Test-DnsServerList $interface.ServerAddresses $family.Servers))) { continue }
                if ($automatic -or -not (Test-DnsServerList $interface.ServerAddresses $family.Applied)) { throw 'Configuration changed manually; not overwritten.' }
                if ($family.Automatic) { Set-DnsClientServerAddress -InputObject $interface -ResetServerAddresses -Confirm:$false -ErrorAction Stop | Out-Null }
                else { Set-DnsClientServerAddress -InputObject $interface -ServerAddresses $family.Servers -Confirm:$false -ErrorAction Stop | Out-Null }
                $mode=Get-DnsDhcpMode $saved.Guid $family.Family
                if ($mode -ne $family.Automatic -or (-not $mode -and -not (Test-DnsServerList (Get-DnsInterface $adapter $family.Family).ServerAddresses $family.Servers))) { throw 'Restore verification failed.' }
            } catch { $conflicts.Add("$($saved.Name) IPv$($family.Family): $($_.Exception.Message)") }
        }
    }
    foreach ($template in $State.Templates) {
        try {
            $current=Get-DnsTemplates | Where-Object ServerAddress -eq $template.Address | Select-Object -First 1
            if (($template.Original -and (Test-DnsTemplate $current $template.Original)) -or (-not $template.Original -and -not $current)) { continue }
            if (-not (Test-DnsTemplate $current $template.Applied)) { throw 'Configuration changed manually; not overwritten.' }
            if ($template.Original) {
                Set-DnsClientDohServerAddress -ServerAddress $template.Address -DohTemplate $template.Original.DohTemplate -AutoUpgrade $template.Original.AutoUpgrade -AllowFallbackToUdp $template.Original.AllowFallbackToUdp -Confirm:$false -ErrorAction Stop | Out-Null
            } else { Remove-DnsClientDohServerAddress -ServerAddress $template.Address -Confirm:$false -ErrorAction Stop | Out-Null }
            $current=Get-DnsTemplates | Where-Object ServerAddress -eq $template.Address | Select-Object -First 1
            if (($template.Original -and -not (Test-DnsTemplate $current $template.Original)) -or (-not $template.Original -and $current)) { throw 'Restore verification failed.' }
        } catch { $conflicts.Add("DoH $($template.Address): $($_.Exception.Message)") }
    }
    return $conflicts.ToArray()
}
function Invoke-DnsMain([switch]$RestoreMode) {
    Assert-DnsStatePath
    if ($RestoreMode) {
        if (-not (Test-Path -LiteralPath $script:DnsStatePath)) { Write-Host 'No saved DNS backup. This restore did not change DNS settings.'; return 0 }
        $state=Get-Content -LiteralPath $script:DnsStatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $conflicts=@(Restore-DnsSnapshot $state)
        if ($conflicts.Count) { throw "DNS recovery is incomplete; backup retained. $($conflicts -join ' ')" }
        Remove-Item -LiteralPath $script:DnsStatePath -Force -ErrorAction Stop
        Write-Host 'Original DNS settings and DoH templates restored.'
        return 0
    }
    if (Test-Path -LiteralPath $script:DnsStatePath) { throw 'A DNS backup already exists. Restore it before enabling again.' }
    $adapters=@(Get-GuardAdapters)
    if (-not $adapters.Count) { throw 'No physical adapters found. No DNS changes were made.' }
    $state=Get-DnsSnapshot $adapters
    Write-DnsState $state
    try {
        Set-DnsTemplates $state
        Set-DnsAdapters $state $adapters
        Assert-DnsApplied $state
    } catch {
        $failure=$_
        $conflicts=@(Restore-DnsSnapshot $state)
        if (-not $conflicts.Count) { Remove-Item -LiteralPath $script:DnsStatePath -Force -ErrorAction Stop }
        throw "DNS setup failed and rollback was attempted. $failure $($conflicts -join ' ')"
    }
    Write-Host 'DNS and DoH settings verified. Original settings saved for restore.'
    return 0
}
if ($MyInvocation.InvocationName -ne '.') {
    try {
        $arguments='-NonInteractive'
        if ($Restore) { $arguments+=' -Restore' }
        $elevatedExit=Invoke-GuardElevation $PSCommandPath $arguments
        if ($null -ne $elevatedExit) { exit $elevatedExit }
        # Serialize DNS enable/restore, including restore requested by the uninstaller.
        $mutex=New-Object Threading.Mutex($false,'Global\ClaudeVPNGuard_DnsSetup')
        $locked=$false
        try {
            try { $locked=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked=$true }
            if (-not $locked) { throw 'Another DNS operation is running.' }
            $result=Invoke-DnsMain -RestoreMode:$Restore
        } finally { if ($locked) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
        exit $result
    } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
