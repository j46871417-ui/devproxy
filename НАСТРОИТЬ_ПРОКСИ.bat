@echo off
chcp 65001 >nul
title DevProxy
if exist "%~dp0devproxy.exe" (
    "%~dp0devproxy.exe" %*
) else (
    python "%~dp0devproxy.py" %*
)
set "devproxy_exit=%errorlevel%"
if not "%devproxy_exit%"=="0" if "%~1"=="" pause
exit /b %devproxy_exit%
