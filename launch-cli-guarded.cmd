@echo off
chcp 65001 >nul
title Claude Code CLI (VPN Guard)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0launch-cli.ps1" %*
exit /b %ERRORLEVEL%
