@echo off
title Aion2 Merchant - Frida TLS Hook Setup

echo ============================================
echo   Aion2 Merchant - Frida TLS Hook Setup
echo ============================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    pause
    exit /b 1
)
echo [OK] Python found.

echo.
echo Installing Frida + dependencies...
pip install frida frida-tools websockets
if errorlevel 1 (
    echo [ERROR] Install failed.
    pause
    exit /b 1
)

echo.
echo [OK] Setup complete!
echo.
echo ============================================
echo   IMPORTANT: Run as Administrator!
echo   Frida needs admin rights to attach to game.
echo ============================================
echo.
echo Usage:
echo   python frida_hook.py --dump
echo     (local test - no server needed)
echo.
echo   python frida_hook.py --server wss://xxxx.ngrok-free.app/capture
echo     (send to Mac server)
echo.
pause
