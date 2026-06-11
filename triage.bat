@echo off
REM Convenience launcher for ThreatTriage.
REM Usage:  triage 8.8.8.8          (or any IP / hash / domain / URL)
REM         triage 1.2.3.4 evil.com --html report.html
pushd "%~dp0"

REM Prefer the py launcher (skips the Microsoft Store python stub)
py -3 -c "import sys" >nul 2>nul
if %errorlevel%==0 (
  py -3 -m threattriage %*
  goto done
)

REM Fall back to a known install path
if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
  "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" -m threattriage %*
  goto done
)

REM Last resort: whatever python is on PATH
python -m threattriage %*

:done
popd
