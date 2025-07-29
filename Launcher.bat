@echo off
setlocal enabledelayedexpansion

:: 0. Перехід у каталог, звідки запущено .bat
cd /D "%~dp0"

:: 1. Заголовок вікна
title Windows Telemetry Disabler

:: 2. Перевірка наявності PowerShell 5
set "PS5_PATH=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "PS_EXE="
if exist "%PS5_PATH%" (
    set "PS_EXE=%PS5_PATH%"
    set "PS_VERSION=PowerShell 5"
    goto :psFound
)
echo [ERROR] PowerShell 5 not found.
pause
exit /b 1
:psFound
echo [INFO] Using %PS_VERSION%

:: 3. Визначення архітектури CPU
set "ARCH="
if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64"        set "ARCH=x64"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" (
    if /i "%PROCESSOR_ARCHITEW6432%"=="AMD64"    set "ARCH=x64"
    if not defined ARCH                          set "ARCH=win32"
)
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64"        set "ARCH=arm64"
if not defined ARCH (
    echo [ERROR] Unsupported CPU architecture ^(%PROCESSOR_ARCHITECTURE%^).
    pause
    exit /b 1
)

:: 4. Формування повних шляхів
set "NSUDO_DIR=%~dp0script\Tools\NSudo"
set "NSUDO=%NSUDO_DIR%\%ARCH%\NSudoLG.exe"
set "PS_SCRIPT=%~dp0script\telemetry-win.ps1"

:: 5. Перевірка наявності NSudo та скрипта
if not exist "%NSUDO%" (
    echo [ERROR] NSudoLG.exe not found for %ARCH%:
    echo           %NSUDO%
    pause
    exit /b 1
)
if not exist "%PS_SCRIPT%" (
    echo [ERROR] Script not found: %PS_SCRIPT%
    pause
    exit /b 1
)

:: 6. Запуск
cls
echo.
echo [INFO] Detected %ARCH%, launching via NSudo (TrustedInstaller)...
echo.
echo =========================================================
echo           Windows Telemetry Disabler Launcher
echo.
echo                  by EXLOUD aka BOBER
echo               https://github.com/EXLOUD
echo =========================================================
echo.

cd /d "%~dp0script"

"%NSUDO%" -U:T -P:E -ShowWindowMode:Show "%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"

pause
exit /b 0