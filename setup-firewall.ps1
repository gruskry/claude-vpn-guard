#Requires -Version 5.1
<#
.SYNOPSIS
    Universal Windows Defender Firewall Kill-Switch for Claude Desktop & Claude Code CLI.
.DESCRIPTION
    Blocks all outbound traffic for Claude executables on physical hardware interfaces (LAN/Wi-Fi),
    ensuring all Claude traffic is forced through virtual VPN adapters (WireGuard, OpenVPN, Outline,
    Amnezia, Tailscale, Proton, etc.). Zero packet leaks if VPN drops.
#>
param(
    [switch]$Uninstall
)

# 1. Administrator Privilege Check & Auto-Elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Requesting Administrator privileges (UAC)..." -ForegroundColor Yellow
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Uninstall) { $argList += " -Uninstall" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "    Claude VPN Guard: Windows Firewall Kill-Switch Setup  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$RulePrefix = "Claude-VPN-Guard-Block"

# 2. Clean previous rules
Write-Host "`n[1/3] Removing previous firewall rules..." -ForegroundColor Gray
Get-NetFirewallRule -Name "$RulePrefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

if ($Uninstall) {
    Write-Host "`nAll Claude firewall block rules have been removed!" -ForegroundColor Green
    Write-Host "Claude can now use any network interface directly." -ForegroundColor Gray
    Write-Host "`nPress any key to exit..."
    $null = [Console]::ReadKey($true)
    exit
}

# Enable dropped connections logging in Windows Defender Firewall
netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null

# 3. Discover Physical Network Adapters (Ethernet / Wi-Fi)
Write-Host "`n[2/3] Detecting physical network interfaces..." -ForegroundColor Gray
$physicalAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { 
    $_.HardwareInterface -eq $true -and 
    $_.InterfaceDescription -notmatch "Virtual|Hyper-V|Bluetooth|WireGuard|Wintun|TAP-|Tunnel|VPN|Miniport"
}

if (-not $physicalAdapters) {
    Write-Warning "No physical network adapters found automatically. Please check network adapters in Device Manager."
    Write-Host "`nPress any key to exit..."
    $null = [Console]::ReadKey($true)
    exit
}

Write-Host "Physical adapters to block for Claude (leak prevention):" -ForegroundColor Yellow
foreach ($adapter in $physicalAdapters) {
    Write-Host "  -> [$($adapter.Name)] ($($adapter.InterfaceDescription))" -ForegroundColor Cyan
}

# 4. Discover all Claude Desktop and Claude Code CLI executables
Write-Host "`n[3/3] Scanning system for Claude executables..." -ForegroundColor Gray
$discoveredExes = [System.Collections.Generic.List[string]]::new()

# A. WindowsApps (MSIX / Store installation)
$windowsAppsFolders = Get-ChildItem "C:\Program Files\WindowsApps" -Filter "*Claude*" -Directory -ErrorAction SilentlyContinue
foreach ($dir in $windowsAppsFolders) {
    $exes = Get-ChildItem $dir.FullName -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    if ($exes) { $discoveredExes.AddRange($exes) }
}

# B. Standard User Installations (Squirrel / LocalAppData)
$standardPaths = @(
    "$env:LOCALAPPDATA\Programs\Claude\Claude.exe",
    "$env:LOCALAPPDATA\Claude\app-*\Claude.exe",
    "$env:APPDATA\Claude\Claude.exe"
)
foreach ($pattern in $standardPaths) {
    $matches = Resolve-Path $pattern -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
    if ($matches) { $discoveredExes.AddRange($matches) }
}

# C. Claude Code CLI (Roaming / Local AppData / npm)
$cliPatterns = @(
    "$env:APPDATA\Claude\claude-code\*\claude.exe",
    "$env:LOCALAPPDATA\Claude-3p\claude-code\*\claude.exe",
    "$env:APPDATA\npm\claude.cmd",
    "$env:APPDATA\npm\node_modules\@anthropic-ai\claude-code\*.exe"
)
foreach ($pattern in $cliPatterns) {
    $matches = Resolve-Path $pattern -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
    if ($matches) { $discoveredExes.AddRange($matches) }
}

# D. Check PATH for claude command
$cmdExe = (Get-Command claude.exe -ErrorAction SilentlyContinue).Source
if ($cmdExe) { $discoveredExes.Add($cmdExe) }

# Deduplicate and filter existing paths
$allExePaths = $discoveredExes | Select-Object -Unique | Where-Object { 
    Test-Path $_ -PathType Leaf -and $_ -match "\.exe$"
}

if ($allExePaths.Count -eq 0) {
    Write-Warning "Could not find any Claude executables. If Claude is installed in a custom location, add its path to this script."
    Write-Host "`nPress any key to exit..."
    $null = [Console]::ReadKey($true)
    exit
}

Write-Host "Found $($allExePaths.Count) Claude executable(s):" -ForegroundColor Yellow
foreach ($p in $allExePaths) {
    Write-Host "  -> $(Split-Path $p -Leaf) ($p)" -ForegroundColor Gray
}

# 5. Create Windows Firewall Outbound Block Rules
Write-Host "`nApplying Outbound Block rules in Windows Defender Firewall..." -ForegroundColor Yellow

$ruleCount = 0
foreach ($adapter in $physicalAdapters) {
    $tag = if ($adapter.Name -eq "Ethernet") { "LAN" } elseif ($adapter.Name -match "Wi-Fi|Беспроводн|Wireless") { "WiFi" } else { "Adapter$($adapter.InterfaceIndex)" }
    $idx = 1
    
    foreach ($exe in $allExePaths) {
        $exeLeaf = Split-Path $exe -Leaf
        $ruleName = "$RulePrefix-$tag-$idx"
        $displayName = "Claude Guard - Block [$($adapter.Name)] ($exeLeaf #$idx)"
        
        try {
            New-NetFirewallRule -Name $ruleName `
                                -DisplayName $displayName `
                                -Description "Claude Kill-Switch: blocks $exeLeaf on $($adapter.Name) (prevents IP leakage outside VPN)." `
                                -Direction Outbound `
                                -Action Block `
                                -Program $exe `
                                -InterfaceAlias $adapter.Name `
                                -Enabled True `
                                -ErrorAction Stop | Out-Null
            
            Write-Host "  [OK] Blocked [$($adapter.Name)] for: $exeLeaf" -ForegroundColor Green
            $ruleCount++
            $idx++
        } catch {
            Write-Host "  [ERROR] Failed to create rule for $exeLeaf on [$($adapter.Name)]: $_" -ForegroundColor Red
        }
    }
}

Write-Host "`n" + ("=" * 58) -ForegroundColor Cyan
if ($ruleCount -gt 0) {
    Write-Host " SUCCESS! Created $ruleCount firewall rule(s)." -ForegroundColor Green -BackgroundColor Black
    Write-Host ("=" * 58) -ForegroundColor Cyan
    Write-Host "`nProtection is now active:" -ForegroundColor White
    Write-Host "1. Claude cannot send any packets through your physical Ethernet or Wi-Fi." -ForegroundColor Gray
    Write-Host "2. If your VPN connection drops, Windows immediately drops all Claude packets." -ForegroundColor Gray
    Write-Host "3. All other programs (browsers, games, background apps) continue working normally." -ForegroundColor Gray
} else {
    Write-Host " WARNING: No rules were created. Please verify administrator rights." -ForegroundColor Red
}

Write-Host "`nPress any key to close this window..."
$null = [Console]::ReadKey($true)
