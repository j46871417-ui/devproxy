@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist "%~dp0dist\devproxy-gui.exe" (
    start "" "%~dp0dist\devproxy-gui.exe"
    exit /b 0
)
if exist "%~dp0.venv\Scripts\pythonw.exe" (
    start "" "%~dp0.venv\Scripts\pythonw.exe" "%~dp0devproxy_gui.py"
    exit /b 0
)
if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" "%~dp0devproxy.py" gui
    exit /b 0
)
python "%~dp0devproxy.py" gui
