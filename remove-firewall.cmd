@echo off
chcp 65001 >nul
title Remove Claude Firewall Kill-Switch
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Wait -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0setup-firewall.ps1\" -Uninstall'"
