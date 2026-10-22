@echo off
rem First-time setup. Installs what is missing, then starts the Scrubber.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\scrubber.ps1" -Action Setup
echo.
pause
