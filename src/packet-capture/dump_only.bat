@echo off
title Aion2 Packet Dump (Local)

echo Dump mode - no server connection, console output only.
echo Make sure Aion2 is running.
echo Press Ctrl+C to stop.
echo.

python capture_agent.py --dump
pause
