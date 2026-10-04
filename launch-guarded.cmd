@echo off
chcp 65001 >nul
title Claude VPN Guard & Launcher
where pwsh.exe >nul 2>nul
if %ERRORLEVEL% equ 0 (
    pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0sync-guard.ps1" -LaunchClaude %*
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0sync-guard.ps1" -LaunchClaude %*
)
