@echo off
rem ============================================================
rem  ZapretFix launcher - English text only (ASCII-safe batch)
rem ============================================================
setlocal
chcp 437 > nul
title ZapretFix - DPI bypass for YouTube / Discord / Telegram

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights ^(UAC^)...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo Running with administrator rights.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Fix-Zapret.ps1" -NoElevate
echo.
echo ------------------------------------------------------------
echo Done. Logs and backups: C:\ProgramData\ZapretFix
echo ------------------------------------------------------------
pause
