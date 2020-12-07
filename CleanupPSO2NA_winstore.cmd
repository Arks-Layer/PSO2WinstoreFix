@echo off
set pathdir=%~dp0
set ffp=%pathdir%%~n0.ps1
IF EXIST "%ffp%" (
 start "Kickstarting PowerShell Script: %~n0" /D "%pathdir%" /LOW /WAIT cmd /C powershell.exe -NoLogo -NoExit -NoProfile -ExecutionPolicy ByPass -File "%ffp%"
) ELSE (
 echo Where is the PowerShell script file?, I could not find: %ffp%
 dir /B "%pathdir%*.ps1"
 pause
)
