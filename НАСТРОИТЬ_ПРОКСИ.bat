@echo off
chcp 65001 >nul
title DevProxy
if exist "%~dp0devproxy.exe" (
    "%~dp0devproxy.exe" %*
) else (
    python "%~dp0devproxy.py" %*
)
exit /b %errorlevel%
