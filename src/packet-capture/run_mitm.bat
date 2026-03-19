@echo off
title Aion2 MITM Capture

echo ============================================
echo   Aion2 MITM TLS Capture
echo   Must run as ADMINISTRATOR!
echo ============================================
echo.

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Not running as Administrator!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo Starting MITM proxy on port 8888...
echo.
echo IMPORTANT: Use Proxifier to route Aion2.exe through this proxy:
echo   1. Download Proxifier from https://www.proxifier.com/
echo   2. Add proxy: SOCKS5 127.0.0.1:8888
echo   3. Add rule: Aion2.exe -> use this proxy
echo.
echo OR set Windows proxy: Settings -> Network -> Proxy -> 127.0.0.1:8888
echo.
echo Game server traffic will be decrypted and shown below.
echo Press Ctrl+C to stop.
echo.

mitmdump --mode socks5 -p 8888 --set stream_large_bodies=0 -s mitm_capture.py

pause
