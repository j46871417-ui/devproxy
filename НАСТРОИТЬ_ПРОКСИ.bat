@echo off
chcp 65001 >nul
title IDE Proxy Injector
if exist "%~dp0ide-proxy-injector.exe" (
    "%~dp0ide-proxy-injector.exe" %*
) else (
    python "%~dp0ide_proxy_injector.py" %*
)
pause
