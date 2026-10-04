@echo off
chcp 65001 >nul
title Setup Claude Firewall Kill-Switch
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0setup-firewall.ps1" -NonInteractive
exit /b %ERRORLEVEL%
