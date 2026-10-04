@echo off
chcp 65001 >nul
title Claude Code CLI (VPN Guard)
where pwsh.exe >nul 2>nul
if %ERRORLEVEL% equ 0 (
    pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0sync-guard.ps1" -LaunchCLI %*
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0sync-guard.ps1" -LaunchCLI %*
)
