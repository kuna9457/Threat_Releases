@echo off
setlocal EnableDelayedExpansion
title ICICI Bank - CAN-wise Threat Scanner
set "BASE=%~dp0"
set "BACKEND_DIR=%BASE%Threat_Backend"
if not exist "%BACKEND_DIR%" (
    echo [ERROR] Threat_Backend folder not found next to this file.
    pause
    exit /b 1
)
if not exist "%BASE%CAN_Merged.xlsx" (
    echo [ERROR] CAN_Merged.xlsx not found next to this file.
    pause
    exit /b 1
)

set "PYTHON_EXE="
if exist "%BACKEND_DIR%\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%BACKEND_DIR%\venv\Scripts\python.exe"
) else if exist "%BACKEND_DIR%\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%BACKEND_DIR%\.venv\Scripts\python.exe"
) else (
    for /f "tokens=*" %%P in ('where python 2^>nul') do (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%P"
    )
)
if not defined PYTHON_EXE (
    echo [ERROR] Python not found.
    pause
    exit /b 1
)

set "PYTHONHTTPSVERIFY=0"
set "PYTHONWARNINGS=ignore::urllib3.exceptions.InsecureRequestWarning"
set "REQUESTS_CA_BUNDLE="
set "CURL_CA_BUNDLE="
set "PYTHONIOENCODING=utf-8"

"!PYTHON_EXE!" "%BASE%run_can_reports.py"
echo.
pause
endlocal
