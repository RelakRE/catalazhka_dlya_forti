@echo off
setlocal
powershell.exe -NoLogo -NoProfile -File "%~dp0prepare-work.ps1"
if errorlevel 1 pause
