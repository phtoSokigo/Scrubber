@echo off
rem Stops the Scrubber.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\scrubber.ps1" -Action Stop
echo.
pause
