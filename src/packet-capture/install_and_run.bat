@echo off
chcp 65001 >nul
title Aion2 Merchant - Packet Capture Agent

echo ============================================
echo   Aion2 Merchant - 패킷 캡처 에이전트 설치
echo ============================================
echo.

:: Python 확인
python --version >nul 2>&1
if errorlevel 1 (
    echo [오류] Python이 설치되어 있지 않습니다.
    echo https://www.python.org/downloads/ 에서 설치하세요.
    echo 설치 시 "Add Python to PATH" 반드시 체크!
    pause
    exit /b 1
)

:: Npcap 확인
if not exist "C:\Windows\System32\Npcap\wpcap.dll" (
    if not exist "C:\Windows\System32\wpcap.dll" (
        echo [경고] Npcap이 설치되어 있지 않습니다.
        echo https://npcap.com/#download 에서 설치하세요.
        echo 설치 시 "WinPcap API-compatible Mode" 체크!
        echo.
        echo Npcap 설치 후 이 스크립트를 다시 실행하세요.
        pause
        exit /b 1
    )
)

:: 의존성 설치
echo [1/2] 패키지 설치 중...
pip install scapy websockets psutil
if errorlevel 1 (
    echo [오류] 패키지 설치 실패
    pause
    exit /b 1
)

echo.
echo [2/2] 설치 완료!
echo.
echo ============================================
echo   Mac 서버 IP를 입력하세요
echo   (예: 192.168.0.10)
echo ============================================
set /p SERVER_IP="Mac IP: "

echo.
echo 서버: ws://%SERVER_IP%:8765 로 연결합니다.
echo Aion2를 실행한 상태에서 진행하세요.
echo 종료: Ctrl+C
echo.

:: 관리자 권한으로 캡처 실행
python capture_agent.py --server ws://%SERVER_IP%:8765

pause
