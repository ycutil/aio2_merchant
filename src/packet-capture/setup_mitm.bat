@echo off
title Aion2 MITM Proxy Setup

echo ============================================
echo   Aion2 MITM TLS Proxy Setup
echo ============================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    pause
    exit /b 1
)

echo [1/3] Installing mitmproxy...
pip install mitmproxy websockets
echo.

echo [2/3] Generating CA certificate...
echo (Press Ctrl+C after you see "Proxy server listening")
start /wait /b mitmdump --mode regular -p 18888 -q
echo.

echo [3/3] Installing CA certificate...
echo.
echo Open this file and install it:
echo   %USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer
echo.
echo Steps:
echo   1. Double-click the .cer file
echo   2. Click "Install Certificate"
echo   3. Select "Local Machine"
echo   4. Select "Place in: Trusted Root Certification Authorities"
echo   5. Finish
echo.
echo After installing the cert, run:
echo   run_mitm.bat
echo.
pause
