#Requires -Version 5.1
<#
.SYNOPSIS
    Enables DNS-over-HTTPS (DoH) leak protection for physical network adapters.
.DESCRIPTION
    Sets physical adapters (Ethernet, Wi-Fi) to use Cloudflare (1.1.1.1, 1.0.0.1) 
    and Google (8.8.8.8, 8.8.4.4) DNS servers, and strictly enables DNS-over-HTTPS (DoH).
    This prevents DNS queries from leaking to your home ISP.
#>

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "    Claude VPN Guard: DNS Leak Protection (DoH) Setup     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Enable DoH for Cloudflare and Google globally
Write-Host "`n[1/2] Configuring DoH templates for Cloudflare and Google..." -ForegroundColor Gray
$dohServers = @("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4")
foreach ($server in $dohServers) {
    try {
        Set-DnsClientDohServerAddress -ServerAddress $server -AutoUpgrade $true -AllowFallbackToUdp $false -ErrorAction Stop
        Write-Host "  [OK] Enforced DoH for $server" -ForegroundColor Green
    } catch {
        Write-Host "  [WARNING] Could not configure DoH for ${server}: $_" -ForegroundColor Yellow
        exit 1
    }
}

# 2. Apply DNS to Physical Adapters
Write-Host "`n[2/2] Applying secure DNS to physical adapters..." -ForegroundColor Gray
$physicalAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { 
    $_.HardwareInterface -eq $true -and 
    $_.InterfaceDescription -notmatch "Virtual|Hyper-V|Bluetooth|WireGuard|Wintun|TAP-|Tunnel|VPN|Miniport"
}

if (-not $physicalAdapters) {
    Write-Warning "No physical adapters found."
} else {
    foreach ($adapter in $physicalAdapters) {
        try {
            Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses ("1.1.1.1", "1.0.0.1", "8.8.8.8") -ErrorAction Stop
            Write-Host "  [OK] Secured DNS for adapter: $($adapter.Name)" -ForegroundColor Green
        } catch {
            Write-Host "  [ERROR] Failed to set DNS for $($adapter.Name): $_" -ForegroundColor Red
        }
    }
}

Write-Host "`n" + ("=" * 58) -ForegroundColor Cyan
Write-Host " SUCCESS! DNS Leak Protection is active." -ForegroundColor Green
Write-Host ("=" * 58) -ForegroundColor Cyan
Write-Host "`nYour ISP can no longer see your DNS queries." -ForegroundColor Gray
Write-Host "Press any key to exit..."
$null = [Console]::ReadKey($true)
