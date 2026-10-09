@echo off
setlocal enabledelayedexpansion
title STweak Launcher

:: Find the first .ps1 file sitting next to this launcher, whatever it's named
set "SCRIPT="
for %%f in ("%~dp0*.ps1") do (
    set "SCRIPT=%%f"
    goto :found
)

:found
if "%SCRIPT%"=="" (
    echo [ERROR] No .ps1 file was found in this folder:
    echo   %~dp0
    echo Make sure the STweak .ps1 file is in the SAME folder as this launcher.
    echo.
    pause
    exit /b
)

echo Found script: %SCRIPT%
echo.

:: Check for Administrator rights; if missing, relaunch elevated
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running as Administrator. Starting STweak...
    echo.
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
    echo.
    echo STweak window closed. Press any key to exit this console.
    pause >nul
) else (
    echo Requesting Administrator privileges, please click "Yes" on the prompt...
    powershell.exe -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)