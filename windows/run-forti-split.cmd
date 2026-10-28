@echo off
setlocal
set "app=%~dp0build\FortiSplit-1.2.1\FortiSplit.exe"
if not exist "%app%" (
 echo Application is missing. Run prepare.cmd first.
 pause
 exit /b 1
)
start "" "%app%"
