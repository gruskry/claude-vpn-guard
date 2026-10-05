@echo off
setlocal
chcp 65001 >nul
title Setup Claude Firewall Kill-Switch
echo Starting Claude Guard firewall setup. Approve the administrator prompt if shown.
echo Rule creation and verification can take several minutes. Keep this window open.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0setup-firewall.ps1" -NonInteractive -ConsoleSetup
set "guard_setup_exit=%ERRORLEVEL%"
echo.
if "%guard_setup_exit%"=="0" (
    echo Setup completed successfully. You can now start Claude ^(VPN Guard^).exe.
) else (
    echo Setup failed with exit code %guard_setup_exit%. Do not start Claude until protection is verified.
)
pause
exit /b %guard_setup_exit%
