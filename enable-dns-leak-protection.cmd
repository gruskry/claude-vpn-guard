@echo off
:: Enable DNS Leak Protection (DoH) via PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0enable-dns-leak-protection.ps1"
