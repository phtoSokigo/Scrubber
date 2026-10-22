@echo off
rem Restarts the Scrubber.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\scrubber.ps1" -Action Restart
echo.
pause
