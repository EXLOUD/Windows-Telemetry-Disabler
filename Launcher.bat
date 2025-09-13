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
:: 3. Визначення архітектури CPU та назви файлу superUser
set "ARCH="
set "SUPERUSER_FILE="
if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set "ARCH=x64"
    set "SUPERUSER_FILE=superUser64.exe"
)
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" (
    if /i "%PROCESSOR_ARCHITEW6432%"=="AMD64" (
        set "ARCH=x64"
        set "SUPERUSER_FILE=superUser64.exe"
    ) else (
        set "ARCH=win32"
        set "SUPERUSER_FILE=superUser32.exe"
    )
)
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" (
    set "ARCH=arm64"
    set "SUPERUSER_FILE=superUserA64.exe"
)
if not defined ARCH (
    echo [ERROR] Unsupported CPU architecture ^(%PROCESSOR_ARCHITECTURE%^).
    pause
    exit /b 1
)
:: 4. Формування повних шляхів
set "SUPERUSER_DIR=%~dp0script\Tools\%ARCH%"
set "SUPERUSER=%SUPERUSER_DIR%\%SUPERUSER_FILE%"
set "PS_SCRIPT=%~dp0script\telemetry-win.ps1"
:: 5. Перевірка наявності superUser та скрипта
if not exist "%SUPERUSER%" (
    echo [ERROR] %SUPERUSER_FILE% not found for %ARCH%:
    echo           %SUPERUSER%
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
echo [INFO] Detected %ARCH%, launching via superUser (TrustedInstaller)...
echo.
echo =========================================================
echo           Windows Telemetry Disabler Launcher
echo.
echo                  by EXLOUD aka BOBER
echo               https://github.com/EXLOUD
echo =========================================================
echo.
cd /d "%~dp0script"
"%SUPERUSER%" /ws "%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"
pause
exit /b 0
