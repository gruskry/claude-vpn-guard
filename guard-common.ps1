# Shared firewall discovery and verification, Windows PowerShell 5.1.
$script:GuardRulePrefix = 'Claude-VPN-Guard-Block'
. "$PSScriptRoot\guard-network.ps1"
function Throw-GuardCoverageChanged([string]$Message) {
    $failure=New-Object InvalidOperationException $Message
    $failure.Data['GuardRepairable']=$true
    throw $failure
}
function Get-GuardStatePath { Join-Path $env:ProgramData 'ClaudeVPNGuard\firewall-state.json' }
function Invoke-GuardElevation([string]$ScriptPath, [string]$ExtraArguments) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return $null }
    $shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $process = Start-Process -FilePath $shell -Verb RunAs -Wait -PassThru -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`" $ExtraArguments" -ErrorAction Stop
    return $process.ExitCode
}
function Get-GuardAdapters($Vpn) {
    if ($Vpn) { return @(Get-GuardBlockedAdapters $Vpn) }
    @(Get-GuardNetworkAdapters | Where-Object { $_.HardwareInterface -eq $true })
}
function Get-GuardRules([string]$PolicyStore='PersistentStore') {
    # Query failure must not be mistaken for an empty rule set (especially on uninstall).
    @(Get-NetFirewallRule -PolicyStore $PolicyStore -ErrorAction Stop | Where-Object { $_.Name -like "$script:GuardRulePrefix*" })
}
function Get-GuardPackageSid([string]$FamilyName) {
    if (-not ('ClaudeGuard.PackageIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace ClaudeGuard {
    public static class PackageIdentity {
        [DllImport("userenv.dll", CharSet=CharSet.Unicode)]
        static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
        [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
        public static string Sid(string name) {
            IntPtr sid;
            int result = DeriveAppContainerSidFromAppContainerName(name, out sid);
            if (result != 0 || sid == IntPtr.Zero) Marshal.ThrowExceptionForHR(result == 0 ? unchecked((int)0x80004005) : result);
            try { return new SecurityIdentifier(sid).Value; } finally { FreeSid(sid); }
        }
    }
}
'@
    }
    [ClaudeGuard.PackageIdentity]::Sid($FamilyName)
}
function Get-GuardCustomDesktopPath {
    $path=Join-Path $PSScriptRoot 'config.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $data=Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if (-not $data.PSObject.Properties['desktop_path'] -or $data.desktop_path -eq '') { return $null }
    $custom=$data.desktop_path
    if ($custom -isnot [string] -or -not [IO.Path]::IsPathRooted($custom) -or $custom.StartsWith('\\') -or (Split-Path $custom -Leaf) -ine 'Claude.exe') { throw 'desktop_path must be an absolute local path to Claude.exe.' }
    if (-not (Test-Path -LiteralPath $custom -PathType Leaf)) { throw 'Configured Claude Desktop executable does not exist.' }
    [IO.Path]::GetFullPath($custom)
}
function Assert-GuardInstallationPath([string]$Path) {
    $current=$Path
    while ($current) {
        if ((Get-Item -LiteralPath $current -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Custom Claude installation must not contain links or junctions.' }
        $parent=Split-Path $current -Parent
        if ($parent -eq $current) { break }
        $current=$parent
    }
}
function Get-GuardProcessSnapshot($Inventory) {
    $known=New-Object 'System.Collections.Generic.List[object]'
    $all=New-Object 'System.Collections.Generic.List[object]'
    $failures=New-Object 'System.Collections.Generic.List[string]'
    try { Get-Process -ErrorAction Stop | ForEach-Object { $all.Add($_) } }
    catch { $failures.Add('Process provider failed; some processes could not be inspected.') }
    foreach ($process in $all) {
        try { $name=$process.ProcessName }
        catch { $failures.Add('A process identity could not be inspected.'); continue }
        try { $path=$process.Path }
        catch { if ($name -ieq 'Claude') { $failures.Add("Cannot inspect Claude PID $($process.Id).") }; continue }
        if ($path -and @($Inventory.Programs) -contains $path) { $known.Add($process) }
        elseif ($name -ieq 'Claude') { $failures.Add("Unknown or inaccessible Claude PID $($process.Id). Close it before launching Guard.") }
    }
    [pscustomobject]@{Processes=$known.ToArray();Errors=$failures.ToArray()}
}
function Get-GuardRunningProcesses($Inventory) {
    $snapshot=Get-GuardProcessSnapshot $Inventory
    if (@($snapshot.Errors).Count) { throw ($snapshot.Errors -join ' ') }
    @($snapshot.Processes)
}
function Get-GuardInventory {
    $programs = New-Object 'System.Collections.Generic.List[string]'
    $packages = @()
    $custom=Get-GuardCustomDesktopPath
    if ($custom) {
        Assert-GuardInstallationPath $custom
        foreach ($file in @(Get-ChildItem -LiteralPath (Split-Path $custom -Parent) -Filter '*.exe' -Recurse -File -ErrorAction Stop)) {
            Assert-GuardInstallationPath $file.FullName
            $programs.Add($file.FullName)
        }
    }
    foreach ($package in @(Get-AppxPackage -ErrorAction Stop | Where-Object { $_.PackageFamilyName -eq 'Claude_pzs8sxrjxfjjc' })) {
        if (-not $package.InstallLocation) { throw 'Claude package installation path is unavailable.' }
        $packages += [pscustomobject]@{ Family=$package.PackageFamilyName; Sid=(Get-GuardPackageSid $package.PackageFamilyName); Root=[IO.Path]::GetFullPath($package.InstallLocation) }
        foreach ($file in @(Get-ChildItem -LiteralPath $package.InstallLocation -Filter '*.exe' -Recurse -File -ErrorAction Stop)) { $programs.Add($file.FullName) }
    }
    $patterns = @(
        "$env:LOCALAPPDATA\Programs\Claude\Claude.exe", "$env:LOCALAPPDATA\Claude\Claude.exe",
        "$env:LOCALAPPDATA\Claude\app-*\*.exe", "$env:APPDATA\Claude\Claude.exe",
        "$env:APPDATA\Claude\claude-code\*\claude.exe", "$env:LOCALAPPDATA\Claude-3p\claude-code\*\claude.exe",
        "$env:USERPROFILE\.local\bin\claude.exe", "$env:USERPROFILE\.claude\local\claude.exe",
        "$env:APPDATA\npm\node_modules\@anthropic-ai\claude-code-*\claude.exe",
        "$env:APPDATA\npm\node_modules\@anthropic-ai\claude-code\node_modules\@anthropic-ai\claude-code-*\claude.exe"
    )
    foreach ($pattern in $patterns) {
        foreach ($path in @(Resolve-Path -Path $pattern -ErrorAction SilentlyContinue)) {
            if (Test-Path -LiteralPath $path.ProviderPath -PathType Leaf) { $programs.Add($path.ProviderPath) }
        }
    }
    $cli = Get-Command claude.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $cliPath=$null
    if ($cli) { $cliPath=[IO.Path]::GetFullPath($cli.Source); $programs.Add($cliPath) }
    # Programs\Claude is an installation root. Claude's data roots also contain
    # user projects, virtual environments and downloads: never recurse over them.
    foreach ($folder in @("$env:LOCALAPPDATA\Programs\Claude")) {
        if (Test-Path -LiteralPath $folder -PathType Container) {
            foreach ($file in @(Get-ChildItem -LiteralPath $folder -Filter '*.exe' -Recurse -File -ErrorAction Stop)) { $programs.Add($file.FullName) }
        }
    }
    foreach ($dataRoot in @("$env:LOCALAPPDATA\Claude", "$env:APPDATA\Claude")) {
        if (-not (Test-Path -LiteralPath $dataRoot -PathType Container)) { continue }
        if (Test-Path -LiteralPath (Join-Path $dataRoot 'Claude.exe') -PathType Leaf) {
            foreach ($file in @(Get-ChildItem -LiteralPath $dataRoot -Filter '*.exe' -File -ErrorAction Stop)) { $programs.Add($file.FullName) }
        }
        foreach ($folder in @(Get-ChildItem -LiteralPath $dataRoot -Filter 'app-*' -Directory -ErrorAction Stop)) {
            if (Test-Path -LiteralPath (Join-Path $folder.FullName 'Claude.exe') -PathType Leaf) {
                foreach ($file in @(Get-ChildItem -LiteralPath $folder.FullName -Filter '*.exe' -Recurse -File -ErrorAction Stop)) { $programs.Add($file.FullName) }
            }
        }
    }
    # Windows PowerShell's full-path normalization expands existing 8.3 aliases.
    # Resolve-Path may preserve them: use one representation for rule scopes,
    # process identities, duplicate removal and Desktop selection.
    $nativePaths=@($programs | ForEach-Object { [IO.Path]::GetFullPath($_) } | Sort-Object -Unique)
    $localInstallRoot=[IO.Path]::GetFullPath("$env:LOCALAPPDATA\Programs\Claude")
    $localDataRoot=[IO.Path]::GetFullPath("$env:LOCALAPPDATA\Claude")
    $roamingDataRoot=[IO.Path]::GetFullPath("$env:APPDATA\Claude")
    $desktop = @($nativePaths | Where-Object {
        $path = $_
        (Split-Path $path -Leaf) -ieq 'Claude.exe' -and (
            $path -ieq "$localInstallRoot\Claude.exe" -or
            $path -ieq "$localDataRoot\Claude.exe" -or
            $path -ieq "$roamingDataRoot\Claude.exe" -or
            ($custom -and $path -ieq $custom) -or
            $path -like "$localDataRoot\app-*\Claude.exe" -or
            $path -like "$roamingDataRoot\app-*\Claude.exe" -or
            @($packages | Where-Object { $path.StartsWith($_.Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
        )
    } | Sort-Object -Unique)
    [pscustomobject]@{ Programs=$nativePaths; DesktopPaths=$desktop; PreferredDesktop=$custom; Packages=@($packages); CliPath=$cliPath }
}
function Assert-GuardProfiles {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if ($profiles.Count -ne 3 -or @($profiles | Where-Object { "$($_.Enabled)" -ne 'True' -or "$($_.AllowLocalFirewallRules)" -eq 'False' }).Count) {
        throw 'Firewall is disabled or policy disallows local rules. Enable all profiles and allow local rules.'
    }
}
function Get-GuardSpecifications($Inventory, $Adapters) {
    foreach ($adapter in @($Adapters)) {
        foreach ($program in @($Inventory.Programs)) { [pscustomobject]@{ Alias=$adapter.Name; Guid="$($adapter.InterfaceGuid)"; InterfaceStatus="$($adapter.Status)"; Program=$program; Package=$null } }
        foreach ($package in @($Inventory.Packages)) { [pscustomobject]@{ Alias=$adapter.Name; Guid="$($adapter.InterfaceGuid)"; InterfaceStatus="$($adapter.Status)"; Program=$null; Package=$package.Sid } }
    }
}
function Get-GuardRuleFilter($Rule, [string]$Kind, [hashtable]$Cache) {
    $key="$($Rule.Name):$Kind"
    if ($null -ne $Cache -and $Cache.ContainsKey($key)) { return $Cache[$key] }
    $filter = switch ($Kind) {
        'Application' { $Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop }
        'Interface' { $Rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop }
        'Port' { $Rule | Get-NetFirewallPortFilter -ErrorAction Stop }
        'Address' { $Rule | Get-NetFirewallAddressFilter -ErrorAction Stop }
        'Service' { $Rule | Get-NetFirewallServiceFilter -ErrorAction Stop }
        'InterfaceType' { $Rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop }
        'Security' { $Rule | Get-NetFirewallSecurityFilter -ErrorAction Stop }
        default { throw 'Unknown firewall filter.' }
    }
    if ($null -ne $Cache) { $Cache[$key]=$filter }
    return $filter
}
function Test-GuardRule($Rule, $Specification, [switch]$AllowDuplicate, [hashtable]$FilterCache) {
    if ("$($Rule.Enabled)" -ne 'True' -or "$($Rule.Direction)" -ne 'Outbound' -or "$($Rule.Action)" -ne 'Block' -or "$($Rule.Profile)" -ne 'Any') { return $false }
    if ("$($Rule.Owner)" -or ($null -ne $Rule.RemoteDynamicKeywordAddresses -and @($Rule.RemoteDynamicKeywordAddresses).Count -gt 0)) { return $false }
    # ActiveStore exposes an array, with profile-specific entries and projected
    # provider enum names such as Enforced rather than the CIM name Full.
    $enforcement=@($Rule.EnforcementStatus | ForEach-Object { "$_" })
    $active=("$($Rule.PrimaryStatus)" -eq 'OK' -and
        @($enforcement | Where-Object { $_ -in @('Enforced','Full','NotApplicable') }).Count -gt 0 -and
        @($enforcement | Where-Object { $_ -notin @('Enforced','Full','NotApplicable','ProfileInactive','InactiveProfile') }).Count -eq 0)
    # A disconnected adapter cannot carry IP traffic, but its rules must be
    # prepared. Once it is up, periodic verification requires active enforcement.
    $dormant=("$($Specification.InterfaceStatus)" -in @('Disconnected','Disabled','Not Present') -and
        "$($Rule.PrimaryStatus)" -eq 'Inactive' -and
        @($enforcement | Where-Object { $_ -in @('NoInterface','InterfaceResolutionEmpty') }).Count -gt 0 -and
        @($enforcement | Where-Object { $_ -notin @('ProfileInactive','InactiveProfile','NoInterface','InterfaceResolutionEmpty') }).Count -eq 0)
    # Duplicate is only a candidate: coverage needs a rule with the same complete
    # scope, enforced now or prepared on a disconnected adapter. A duplicate
    # never proves protection on its own.
    $duplicate=($AllowDuplicate -and "$($Rule.PrimaryStatus)" -eq 'Inactive' -and
        $enforcement -contains 'Duplicate' -and
        @($enforcement | Where-Object { $_ -notin @('Duplicate','ProfileInactive','InactiveProfile') }).Count -eq 0)
    if (-not $active -and -not $dormant -and -not $duplicate) { return $false }
    $app = Get-GuardRuleFilter $Rule 'Application' $FilterCache
    $interface = Get-GuardRuleFilter $Rule 'Interface' $FilterCache
    if (@($interface.InterfaceAlias).Count -ne 1 -or $interface.InterfaceAlias -ne $Specification.Alias) { return $false }
    if ($Specification.Program) {
        if ($app.Program -ne $Specification.Program -or "$($app.Package)" -notin @('','Any')) { return $false }
    } elseif ($app.Package -ne $Specification.Package -or "$($app.Program)" -notin @('','Any')) { return $false }
    $port = Get-GuardRuleFilter $Rule 'Port' $FilterCache
    $address = Get-GuardRuleFilter $Rule 'Address' $FilterCache
    $service = Get-GuardRuleFilter $Rule 'Service' $FilterCache
    $type = Get-GuardRuleFilter $Rule 'InterfaceType' $FilterCache
    if ("$($port.Protocol)" -ne 'Any' -or "$($port.LocalPort)" -ne 'Any' -or "$($port.RemotePort)" -ne 'Any' -or
        "$($address.LocalAddress)" -ne 'Any' -or "$($address.RemoteAddress)" -ne 'Any' -or "$($service.Service)" -ne 'Any' -or "$($type.InterfaceType)" -ne 'Any') { return $false }
    $security = Get-GuardRuleFilter $Rule 'Security' $FilterCache
    if ("$($security.Authentication)" -ne 'NotRequired' -or "$($security.Encryption)" -ne 'NotRequired' -or
        "$($security.LocalUser)" -ne 'Any' -or "$($security.RemoteUser)" -ne 'Any' -or "$($security.RemoteMachine)" -ne 'Any') { return $false }
    return $true
}
function Assert-GuardCoverage($Specifications, [string[]]$RuleNames, [switch]$DuringRefresh) {
    $allRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
    $guardRules = @($allRules | Where-Object { $_.Name -like "$script:GuardRulePrefix*" })
    $rules = $guardRules
    if ($RuleNames) { $rules = @($rules | Where-Object { $RuleNames -contains $_.Name }) }
    # Existing independently managed rules can cause duplicate optimization too.
    # Keep them intact, but require the same complete scope and active enforcement.
    # Retired Guard generations are only eligible during a transactional refresh.
    $witnesses = @($rules) + @($allRules | Where-Object { $_.Name -notlike "$script:GuardRulePrefix*" })
    if ($DuringRefresh) { $witnesses=$allRules }
    # This cache lives for one verification only: every later check rereads the
    # provider, including edits to a rule whose name did not change.
    $filters=@{}
    foreach ($specification in @($Specifications)) {
        $covered = $false
        foreach ($rule in $rules) {
            if (Test-GuardRule $rule $specification -FilterCache $filters) { $covered=$true; break }
            if (-not (Test-GuardRule $rule $specification -AllowDuplicate -FilterCache $filters)) { continue }
            foreach ($witness in $witnesses) {
                if ($witness.Name -ne $rule.Name -and
                    (Test-GuardRule $witness $specification -FilterCache $filters)) { $covered=$true; break }
            }
            if ($covered) { break }
        }
        if (-not $covered) { Throw-GuardCoverageChanged "Missing effective block rule on '$($specification.Alias)' for '$($specification.Program)$($specification.Package)'." }
    }
}
function Save-GuardFirewallState($State) {
    $path = Get-GuardStatePath
    $directory = Split-Path $path -Parent
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null }
    foreach ($target in @($directory,$path)) {
        if ((Test-Path -LiteralPath $target) -and ((Get-Item -LiteralPath $target -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Guard state path must not be a link or junction.' }
    }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    foreach ($entry in @(@('S-1-5-18','FullControl'), @('S-1-5-32-544','FullControl'), @('S-1-5-32-545','ReadAndExecute'))) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule ([Security.Principal.SecurityIdentifier]$entry[0]), $entry[1], 'ContainerInherit,ObjectInherit', 'None', 'Allow'
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $directory -AclObject $acl -ErrorAction Stop
    $temporary = "$path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $temporary -Destination $path -Force -ErrorAction Stop
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
}
function Get-GuardProtectionStatus {
    Assert-GuardProfiles
    $path = Get-GuardStatePath
    if (-not (Test-Path -LiteralPath $path)) { Throw-GuardCoverageChanged 'Firewall setup has not completed.' }
    $state = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($state.Version -eq 1) { Throw-GuardCoverageChanged 'Upgrade the firewall policy to VPN-pinned protection.' }
    if ($state.Version -ne 2 -or -not @($state.Rules).Count -or -not $state.VpnGuid) { throw 'Invalid firewall state. Run setup-firewall.cmd.' }
    $vpn=Get-GuardVpnAdapter $state.VpnGuid
    Assert-GuardNoProxy
    $adapters = @(Get-GuardAdapters $vpn)
    if (-not $adapters.Count) { throw 'No untrusted adapters found; coverage cannot be verified.' }
    foreach ($adapter in $adapters) {
        if (-not @($state.Adapters | Where-Object { $_.Guid -eq "$($adapter.InterfaceGuid)" -and $_.Alias -eq $adapter.Name }).Count) { Throw-GuardCoverageChanged "New or renamed adapter '$($adapter.Name)'." }
    }
    $inventory = Get-GuardInventory
    if (-not @($inventory.Programs).Count) { throw 'No supported native Claude installation found.' }
    Assert-GuardCoverage @(Get-GuardSpecifications $inventory $adapters) @($state.Rules)
    [pscustomobject]@{ Ok=$true; Inventory=$inventory; Adapters=$adapters; Vpn=$vpn }
}
