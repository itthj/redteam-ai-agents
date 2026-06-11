@echo off
REM Double-click to launch the live dashboard. Uses the project's Python 3.12 venv
REM if present, otherwise falls back to whatever `python` is on PATH.
cd /d "%~dp0"
set "VENV=C:\Users\james\venvs\redteam-ai-agents-py312\Scripts\python.exe"
if exist "%VENV%" (
    "%VENV%" scripts\dashboard.py
) else (
    python scripts\dashboard.py
)
pause
