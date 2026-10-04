#Requires -Version 5.1
<#
.SYNOPSIS
    Universal Claude VPN Guard & Timezone Synchronizer.
.DESCRIPTION
    Checks active VPN IP/country, prevents launching Claude on forbidden IPs,
    matches and synchronizes Windows timezone to the VPN server location,
    scrubs stale IP/telemetry caches, and restores the original timezone on exit.
#>
param(
    [switch]$LaunchClaude,
    [switch]$LaunchCLI,
    [string]$TargetTimezone,
    [switch]$NoTimezoneChange
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         Claude VPN Guard & Timezone Synchronizer         " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Blocked Countries (Sanctioned / Unsupported regions)
$BlockedCountries = @("BY", "RU", "IR", "KP", "SY", "CU")

# IANA to Windows Timezone mapping
$TzMap = @{
    "Asia/Tbilisi"            = "Georgian Standard Time"
    "Europe/Warsaw"           = "Central European Standard Time"
    "Europe/Berlin"           = "W. Europe Standard Time"
    "Europe/Paris"            = "Romance Standard Time"
    "Europe/Amsterdam"        = "W. Europe Standard Time"
    "Europe/London"           = "GMT Standard Time"
    "Europe/Vilnius"          = "FLE Standard Time"
    "Europe/Riga"             = "FLE Standard Time"
    "Europe/Tallinn"          = "FLE Standard Time"
    "Europe/Kiev"             = "FLE Standard Time"
    "Europe/Kyiv"             = "FLE Standard Time"
    "America/New_York"        = "Eastern Standard Time"
    "America/Chicago"         = "Central Standard Time"
    "America/Denver"          = "Mountain Standard Time"
    "America/Los_Angeles"     = "Pacific Standard Time"
    "Asia/Yerevan"            = "Caucasus Standard Time"
    "Asia/Almaty"             = "Central Asia Standard Time"
    "Asia/Tashkent"           = "West Asia Standard Time"
    "Asia/Istanbul"           = "Turkey Standard Time"
    "Asia/Dubai"              = "Arabian Standard Time"
}

function Get-PublicIPLocation {
    $endpoints = @(
        "https://ipapi.co/json/",
        "https://ipinfo.io/json",
        "https://api.myip.com"
    )
    
    foreach ($url in $endpoints) {
        try {
            $resp = Invoke-RestMethod -Uri $url -TimeoutSec 4 -Headers @{ "User-Agent" = "curl/7.68.0" } -ErrorAction Stop
            if ($resp.country_code -or $resp.country) {
                $countryCode = if ($resp.country_code) { $resp.country_code } else { $resp.country }
                $city = if ($resp.city) { $resp.city } else { "Unknown" }
                $ip = if ($resp.ip) { $resp.ip } else { "Unknown" }
                $iana = if ($resp.timezone) { $resp.timezone } else { "" }
                return [PSCustomObject]@{
                    IP          = $ip
                    CountryCode = $countryCode.ToUpper()
                    City        = $city
                    IanaTz      = $iana
                }
            }
        } catch {
            continue
        }
    }
    return $null
}

function Clean-ClaudeTelemetry {
    $roaming = "$env:APPDATA\Claude"
    $local = "$env:LOCALAPPDATA\Claude"
    
    $targets = @(
        (Join-Path $roaming "Network\Network Persistent State"),
        (Join-Path $roaming "Network\Trust Tokens"),
        (Join-Path $roaming "sentry"),
        (Join-Path $roaming "Local Storage"),
        (Join-Path $local "GPUCache")
    )
    
    foreach ($t in $targets) {
        if (Test-Path $t) {
            try {
                Remove-Item -Path $t -Recurse -Force -ErrorAction SilentlyContinue
            } catch {}
        }
    }
}

# Remember original Windows Timezone to restore upon exit
$originalTz = (Get-TimeZone).Id
Write-Host "`nCurrent Windows Timezone: $originalTz" -ForegroundColor Gray

# Step 1: Detect VPN location
Write-Host "`n[1/4] Checking active public IP and VPN connection..." -ForegroundColor Yellow
$loc = Get-PublicIPLocation

if (-not $loc) {
    Write-Host "`n[ERROR] Unable to reach internet to verify VPN connection!" -ForegroundColor Red
    Write-Host "Please ensure your VPN or internet connection is active." -ForegroundColor Yellow
    Pause
    exit 1
}

Write-Host "Active IP:       $($loc.IP)" -ForegroundColor Cyan
Write-Host "Location:        $($loc.City), $($loc.CountryCode)" -ForegroundColor Cyan
Write-Host "Detected IANA:   $($loc.IanaTz)" -ForegroundColor Cyan

# Check for banned / home country leak
if ($BlockedCountries -contains $loc.CountryCode) {
    Write-Host "`n" + ("!" * 60) -ForegroundColor Red -BackgroundColor Black
    Write-Host " CRITICAL WARNING: UNSUPPORTED REGION DETECTED ($($loc.CountryCode))!" -ForegroundColor Red -BackgroundColor Black
    Write-Host " Your VPN is NOT CONNECTED or is LEAKING your home IP ($($loc.IP))!" -ForegroundColor Red
    Write-Host " Claude launch is BLOCKED to protect your account from bans." -ForegroundColor Yellow
    Write-Host ("!" * 60) -ForegroundColor Red -BackgroundColor Black
    Pause
    exit 2
}

Write-Host "  -> Safe VPN location confirmed ($($loc.CountryCode))." -ForegroundColor Green

# Step 2: Timezone Synchronization
if (-not $NoTimezoneChange) {
    $targetWinTz = $null
    if ($TargetTimezone) {
        $targetWinTz = $TargetTimezone
    } elseif ($loc.IanaTz -and $TzMap.ContainsKey($loc.IanaTz)) {
        $targetWinTz = $TzMap[$loc.IanaTz]
    }
    
    if ($targetWinTz -and $targetWinTz -ne $originalTz) {
        Write-Host "`n[2/4] Synchronizing Windows Timezone to match VPN ($targetWinTz)..." -ForegroundColor Yellow
        try {
            tzutil.exe /s "$targetWinTz"
            Write-Host "  -> Timezone set to: $targetWinTz" -ForegroundColor Green
        } catch {
            Write-Warning "Could not update timezone: $_"
        }
    } else {
        Write-Host "`n[2/4] Timezone is already aligned or matching." -ForegroundColor Green
    }
}

# Step 3: Scrub Telemetry
Write-Host "`n[3/4] Scrubbing stale network & telemetry caches..." -ForegroundColor Yellow
Clean-ClaudeTelemetry
Write-Host "  -> Cache cleaned." -ForegroundColor Green

# Step 4: Launch Claude
Write-Host "`n[4/4] Launching Claude under Guard..." -ForegroundColor Yellow

$launchedProcess = $null
if ($LaunchCLI) {
    Write-Host "Starting Claude Code CLI..." -ForegroundColor Cyan
    $launchedProcess = Start-Process "claude" -PassThru
} else {
    Write-Host "Starting Claude Desktop..." -ForegroundColor Cyan
    $started = $false
    try {
        Start-Process "shell:AppsFolder\Claude_pzs8sxrjxfjjc!Claude" -ErrorAction Stop
        Start-Sleep -Seconds 2
        if (Get-Process -Name "Claude" -ErrorAction SilentlyContinue) { $started = $true }
    } catch {}
    
    if (-not $started) {
        $fallbackPaths = @(
            "$env:LOCALAPPDATA\Programs\Claude\Claude.exe",
            "$env:LOCALAPPDATA\Claude\Claude.exe",
            "$env:APPDATA\Claude\Claude.exe"
        )
        foreach ($p in $fallbackPaths) {
            if (Test-Path $p) {
                Start-Process $p
                $started = $true
                break
            }
        }
    }
    $launchedProcess = Get-Process -Name "Claude" -ErrorAction SilentlyContinue | Select-Object -First 1
}

Write-Host "`nClaude is running safely under VPN Guard." -ForegroundColor Green
Write-Host "When Claude is closed, your original timezone ($originalTz) will be automatically restored." -ForegroundColor Gray

# Wait for Claude to close to restore timezone
if (-not $NoTimezoneChange) {
    while (Get-Process -Name "claude" -ErrorAction SilentlyContinue) {
        Start-Sleep -Seconds 3
    }
    
    Write-Host "`nClaude closed. Restoring original timezone ($originalTz)..." -ForegroundColor Yellow
    tzutil.exe /s "$originalTz"
    Write-Host "Timezone restored successfully. Have a great day!" -ForegroundColor Green
}
