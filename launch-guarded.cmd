@echo off
chcp 65001 >nul
title Claude VPN Guard & Launcher
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0sync-guard.ps1" -LaunchClaude %*
exit /b %ERRORLEVEL%
