@echo off
title Aion2 TLS Capture (Frida)

echo ============================================
echo   Aion2 TLS Capture - Frida Hook
echo   Must run as ADMINISTRATOR!
echo ============================================
echo.

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Not running as Administrator!
    echo Right-click this file and select "Run as administrator"
    pause
    exit /b 1
)

if "%1"=="" (
    echo Usage: run_frida.bat [SERVER_URL]
    echo.
    echo   Local test:  run_frida.bat --dump
    echo   Server:      run_frida.bat wss://xxxx.ngrok-free.app/capture
    echo.
    set /p INPUT="Server URL (or --dump): "
) else (
    set INPUT=%1
)

if "%INPUT%"=="--dump" (
    echo Starting in dump mode...
    python frida_hook.py --dump
) else (
    echo Connecting to: %INPUT%
    python frida_hook.py --server %INPUT%
)

pause
