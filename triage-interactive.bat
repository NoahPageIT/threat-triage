@echo off
REM Double-click friendly ThreatTriage. Prompts for indicators in a loop.
title ThreatTriage
echo.
echo   ThreatTriage - enter an IP, domain, file hash, or URL to triage.
echo   Leave blank and press Enter to quit.
echo.
:loop
set "ioc="
set /p "ioc=  Indicator^> "
if "%ioc%"=="" goto end
call "%~dp0triage.bat" %ioc%
echo.
goto loop
:end
echo   Bye.
