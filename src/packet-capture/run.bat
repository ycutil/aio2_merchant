@echo off
chcp 65001 >nul
title Aion2 Packet Capture

if "%1"=="" (
    echo 사용법: run.bat [서버URL]
    echo.
    echo   같은 네트워크:  run.bat ws://맥IP:8080/capture
    echo   외부 네트워크:  run.bat wss://xxxx.ngrok-free.app/capture
    echo.
    set /p SERVER_URL="서버 URL: "
) else (
    set SERVER_URL=%1
)

echo 연결: %SERVER_URL%
echo 종료: Ctrl+C
echo.

python capture_agent.py --server %SERVER_URL%
pause
