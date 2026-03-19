@echo off
chcp 65001 >nul
title Aion2 Packet Dump (로컬 확인용)

echo 서버 전송 없이 패킷을 콘솔에 출력합니다.
echo Aion2를 실행한 상태에서 진행하세요.
echo 종료: Ctrl+C
echo.

python capture_agent.py --dump
pause
