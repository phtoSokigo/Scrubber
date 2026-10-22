@echo off
rem Starts the Scrubber. Also use after you copy in a new version.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\scrubber.ps1" -Action Start
echo.
pause
