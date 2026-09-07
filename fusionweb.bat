@echo off
rem FusionWeb interactive menu launcher. All logic lives in fusionweb.ps1 (pure PowerShell, UTF-8 safe).
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0fusionweb.ps1"
exit /b %errorlevel%
