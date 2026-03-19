@echo off
title Aion2 Merchant - Capture Agent Setup

echo ============================================
echo   Aion2 Merchant - Capture Agent Setup
echo ============================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    echo Download: https://www.python.org/downloads/
    echo IMPORTANT: Check "Add Python to PATH" during install!
    pause
    exit /b 1
)
echo [OK] Python found.

REM Check Npcap
if not exist "C:\Windows\System32\Npcap\wpcap.dll" (
    if not exist "C:\Windows\System32\wpcap.dll" (
        echo [ERROR] Npcap not found.
        echo Download: https://npcap.com/#download
        echo IMPORTANT: Check "WinPcap API-compatible Mode" during install!
        pause
        exit /b 1
    )
)
echo [OK] Npcap found.

echo.
echo [1/2] Installing packages...
pip install scapy websockets psutil
if errorlevel 1 (
    echo [ERROR] Package install failed.
    pause
    exit /b 1
)
echo [OK] Packages installed.

echo.
echo [2/2] Setup complete!
echo.
echo ============================================
echo   Enter server URL:
echo.
echo   LAN:      ws://MAC_IP:8080/capture
echo   External: wss://xxxx.ngrok-free.app/capture
echo ============================================
set /p SERVER_URL="Server URL: "

echo.
echo Connecting to: %SERVER_URL%
echo Make sure Aion2 is running.
echo Press Ctrl+C to stop.
echo.

python capture_agent.py --server %SERVER_URL%

pause
