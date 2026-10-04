@echo off
chcp 65001 >nul
title Create Desktop Shortcut
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0create-desktop-shortcut.ps1"
pause
