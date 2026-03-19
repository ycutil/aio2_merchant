@echo off
title Aion2 Packet Capture

if "%1"=="" (
    echo Usage: run.bat [SERVER_URL]
    echo.
    echo   LAN:      run.bat ws://MAC_IP:8080/capture
    echo   External: run.bat wss://xxxx.ngrok-free.app/capture
    echo.
    set /p SERVER_URL="Server URL: "
) else (
    set SERVER_URL=%1
)

echo Connecting to: %SERVER_URL%
echo Press Ctrl+C to stop.
echo.

python capture_agent.py --server %SERVER_URL%
pause
