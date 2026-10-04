@echo off
:: Enable DNS Leak Protection (DoH) via PowerShell
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0enable-dns-leak-protection.ps1" -NonInteractive %*
exit /b %ERRORLEVEL%
