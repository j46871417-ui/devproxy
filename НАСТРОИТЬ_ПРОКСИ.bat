@echo off
chcp 65001 >nul
title DevProxy CLI
if exist "%~dp0devproxy.exe" (
    "%~dp0devproxy.exe" %*
) else (
    python "%~dp0devproxy.py" %*
)
pause
