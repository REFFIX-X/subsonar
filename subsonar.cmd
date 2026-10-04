@echo off
rem subsonar launcher — uses the local virtualenv when present.
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
) else (
    set "PY=python"
)
"%PY%" main.py %*
endlocal
