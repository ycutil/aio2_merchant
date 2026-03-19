@echo off
chcp 65001 >nul
title Aion2 Packet Capture

if "%1"=="" (
    echo 사용법: run.bat [Mac서버IP]
    echo 예시:   run.bat 192.168.0.10
    echo.
    set /p SERVER_IP="Mac IP: "
) else (
    set SERVER_IP=%1
)

echo 연결: ws://%SERVER_IP%:8765
echo 종료: Ctrl+C
echo.

python capture_agent.py --server ws://%SERVER_IP%:8765
pause
