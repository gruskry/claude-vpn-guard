# Shared firewall discovery and verification, Windows PowerShell 5.1.
$script:GuardRulePrefix = 'Claude-VPN-Guard-Block'
function Get-GuardStatePath { Join-Path $env:ProgramData 'ClaudeVPNGuard\firewall-state.json' }
function Invoke-GuardElevation([string]$ScriptPath, [string]$ExtraArguments) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return $null }
    $shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $process = Start-Process -FilePath $shell -Verb RunAs -Wait -PassThru -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`" $ExtraArguments" -ErrorAction Stop
    return $process.ExitCode
}
function Get-GuardAdapters {
    # Display names are not a security boundary; include every physical interface.
    @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.HardwareInterface -eq $true })
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
function Get-GuardInventory {
    $programs = New-Object 'System.Collections.Generic.List[string]'
    $packages = @()
    foreach ($package in @(Get-AppxPackage -ErrorAction Stop | Where-Object { $_.PackageFamilyName -eq 'Claude_pzs8sxrjxfjjc' })) {
        if (-not $package.InstallLocation) { throw 'Claude package installation path is unavailable.' }
        $packages += [pscustomobject]@{ Family=$package.PackageFamilyName; Sid=(Get-GuardPackageSid $package.PackageFamilyName); Root=$package.InstallLocation }
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
            if (Test-Path -LiteralPath $path.Path -PathType Leaf) { $programs.Add($path.Path) }
        }
    }
    $cli = Get-Command claude.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cli) { $programs.Add($cli.Source) }
    foreach ($folder in @("$env:LOCALAPPDATA\Programs\Claude", "$env:LOCALAPPDATA\Claude", "$env:APPDATA\Claude")) {
        if (Test-Path -LiteralPath $folder -PathType Container) {
            foreach ($file in @(Get-ChildItem -LiteralPath $folder -Filter '*.exe' -Recurse -File -ErrorAction Stop)) { $programs.Add($file.FullName) }
        }
    }
    $desktop = @($programs | Where-Object {
        $path = $_
        (Split-Path $path -Leaf) -ieq 'Claude.exe' -and (
            $path -ieq "$env:LOCALAPPDATA\Programs\Claude\Claude.exe" -or
            $path -ieq "$env:LOCALAPPDATA\Claude\Claude.exe" -or
            $path -ieq "$env:APPDATA\Claude\Claude.exe" -or
            $path -like "$env:LOCALAPPDATA\Claude\app-*\Claude.exe" -or
            @($packages | Where-Object { $path.StartsWith($_.Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
        )
    } | Sort-Object -Unique)
    [pscustomobject]@{ Programs=@($programs | Sort-Object -Unique); DesktopPaths=$desktop; Packages=@($packages); CliPath=$(if ($cli) { $cli.Source } else { $null }) }
}
function Assert-GuardProfiles {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if ($profiles.Count -ne 3 -or @($profiles | Where-Object { "$($_.Enabled)" -ne 'True' -or "$($_.AllowLocalFirewallRules)" -eq 'False' }).Count) {
        throw 'Firewall is disabled or policy disallows local rules. Enable all profiles and allow local rules.'
    }
}
function Get-GuardSpecifications($Inventory, $Adapters) {
    foreach ($adapter in @($Adapters)) {
        foreach ($program in @($Inventory.Programs)) { [pscustomobject]@{ Alias=$adapter.Name; Guid="$($adapter.InterfaceGuid)"; Program=$program; Package=$null } }
        foreach ($package in @($Inventory.Packages)) { [pscustomobject]@{ Alias=$adapter.Name; Guid="$($adapter.InterfaceGuid)"; Program=$null; Package=$package.Sid } }
    }
}
function Test-GuardRule($Rule, $Specification) {
    if ("$($Rule.Enabled)" -ne 'True' -or "$($Rule.Direction)" -ne 'Outbound' -or "$($Rule.Action)" -ne 'Block' -or "$($Rule.Profile)" -ne 'Any') { return $false }
    if ("$($Rule.PrimaryStatus)" -ne 'OK' -or "$($Rule.EnforcementStatus)" -notin @('Full', 'NotApplicable')) { return $false }
    $app = $Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $interface = $Rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
    if (@($interface.InterfaceAlias).Count -ne 1 -or $interface.InterfaceAlias -ne $Specification.Alias) { return $false }
    if ($Specification.Program) {
        if ($app.Program -ne $Specification.Program -or "$($app.Package)" -ne 'Any') { return $false }
    } elseif ($app.Package -ne $Specification.Package -or "$($app.Program)" -ne 'Any') { return $false }
    $port = $Rule | Get-NetFirewallPortFilter -ErrorAction Stop
    $address = $Rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    $service = $Rule | Get-NetFirewallServiceFilter -ErrorAction Stop
    $type = $Rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
    if ("$($port.Protocol)" -ne 'Any' -or "$($port.LocalPort)" -ne 'Any' -or "$($port.RemotePort)" -ne 'Any' -or
        "$($address.LocalAddress)" -ne 'Any' -or "$($address.RemoteAddress)" -ne 'Any' -or "$($service.Service)" -ne 'Any' -or "$($type.InterfaceType)" -ne 'Any') { return $false }
    return $true
}
function Assert-GuardCoverage($Specifications, [string[]]$RuleNames) {
    $rules = @(Get-GuardRules 'ActiveStore')
    if ($RuleNames) { $rules = @($rules | Where-Object { $RuleNames -contains $_.Name }) }
    foreach ($specification in @($Specifications)) {
        $covered = $false
        foreach ($rule in $rules) { if (Test-GuardRule $rule $specification) { $covered=$true; break } }
        if (-not $covered) { throw "Missing effective block rule on '$($specification.Alias)' for '$($specification.Program)$($specification.Package)'. Run setup-firewall.cmd again." }
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
    if (-not (Test-Path -LiteralPath $path)) { throw 'Firewall setup has not completed. Run setup-firewall.cmd.' }
    $state = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($state.Version -ne 1 -or -not @($state.Rules).Count) { throw 'Invalid firewall state. Run setup-firewall.cmd.' }
    $adapters = @(Get-GuardAdapters)
    if (-not $adapters.Count) { throw 'No physical adapters found; coverage cannot be verified.' }
    foreach ($adapter in $adapters) {
        if (-not @($state.Adapters | Where-Object { $_.Guid -eq "$($adapter.InterfaceGuid)" -and $_.Alias -eq $adapter.Name }).Count) { throw "New or renamed adapter '$($adapter.Name)'. Run setup-firewall.cmd." }
    }
    $inventory = Get-GuardInventory
    if (-not @($inventory.Programs).Count) { throw 'No supported native Claude installation found.' }
    Assert-GuardCoverage @(Get-GuardSpecifications $inventory $adapters) @($state.Rules)
    [pscustomobject]@{ Ok=$true; Inventory=$inventory; Adapters=$adapters }
}
