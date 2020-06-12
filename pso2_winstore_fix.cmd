@echo on
cd /d %~dp0
start "Kickstarting PowerShell Script" /wait cmd /C powershell.exe -NoLogo -NoExit -NoProfile -ExecutionPolicy ByPass -File "%~dp0pso2_winstore_fix.ps1"
pause
