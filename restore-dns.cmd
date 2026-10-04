@echo off
:: Restore the DNS settings saved by enable-dns-leak-protection.ps1.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0enable-dns-leak-protection.ps1" -Restore -NonInteractive %*
exit /b %ERRORLEVEL%
