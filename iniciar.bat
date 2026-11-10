@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>&1
if not errorlevel 1 (
  py -3 app.py
  goto end
)
where python >nul 2>&1
if not errorlevel 1 (
  python app.py
  goto end
)
echo Instale o Python 3: https://www.python.org/downloads/
echo Na instalacao, marque "Add python.exe to PATH".
:end
echo.
pause
