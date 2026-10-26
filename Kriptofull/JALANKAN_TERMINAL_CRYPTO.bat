@echo off
cd /d "%~dp0"
where py >nul 2>&1
if %errorlevel%==0 (
  py terminal_crypto.py
) else (
  python terminal_crypto.py
)
pause
