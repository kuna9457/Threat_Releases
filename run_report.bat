@echo off
setlocal EnableDelayedExpansion
title ICICI Bank — URL Threat Scanner & Report Generator

:: ============================================================
::   ICICI BANK  |  URL THREAT SCANNER  |  REPORT GENERATOR
::   Single-batch runner — no web server, no EXE needed
::   Fixes Zscaler / corporate-proxy SSL interception issues
:: ============================================================

echo.
echo  ============================================================
echo    ICICI BANK  ^|  URL THREAT SCANNER  ^|  REPORT GENERATOR
echo  ============================================================
echo.

:: ----------------------------------------------------------
:: 0. Locate Threat_Backend next to this batch file
:: ----------------------------------------------------------
set "BATCH_DIR=%~dp0"
set "BACKEND_DIR=%BATCH_DIR%Threat_Backend"

if not exist "%BACKEND_DIR%" (
    echo [ERROR] Threat_Backend folder not found next to this batch file.
    echo         Expected: %BACKEND_DIR%
    pause
    exit /b 1
)

:: ----------------------------------------------------------
:: 1. Find Python (venv preferred, then system python)
:: ----------------------------------------------------------
set "PYTHON_EXE="

if exist "%BACKEND_DIR%\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%BACKEND_DIR%\venv\Scripts\python.exe"
    echo [INFO] Using virtual environment Python: !PYTHON_EXE!
) else if exist "%BACKEND_DIR%\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%BACKEND_DIR%\.venv\Scripts\python.exe"
    echo [INFO] Using .venv Python: !PYTHON_EXE!
) else (
    where python >nul 2>&1
    if !errorlevel! == 0 (
        for /f "tokens=*" %%P in ('where python') do (
            if not defined PYTHON_EXE set "PYTHON_EXE=%%P"
        )
        echo [INFO] Using system Python: !PYTHON_EXE!
    ) else (
        echo [ERROR] Python not found. Install Python 3.9+ or create a venv in Threat_Backend.
        pause
        exit /b 1
    )
)

echo.
"!PYTHON_EXE!" --version
echo.

:: ----------------------------------------------------------
:: 2. SSL / Zscaler Fix
:: ----------------------------------------------------------
set "PYTHONHTTPSVERIFY=0"
set "PYTHONWARNINGS=ignore::urllib3.exceptions.InsecureRequestWarning"
set "REQUESTS_CA_BUNDLE="
set "CURL_CA_BUNDLE="

echo [INFO] Zscaler/proxy SSL bypass active for outbound API calls.
echo.

:: ----------------------------------------------------------
:: 3. Collect URLs from user
:: ----------------------------------------------------------
echo ============================================================
echo   STEP 1 of 3  --  Enter URLs to scan
echo ============================================================
echo.
echo  Enter URLs ONE PER LINE.  Type END when done.
echo  Example:
echo    https://example-bank.com
echo    https://suspicious-site.co
echo    END
echo.

set "URL_FILE=%TEMP%\icici_scan_urls_%RANDOM%.txt"
if exist "%URL_FILE%" del "%URL_FILE%"

:url_loop
set "URL_INPUT="
set /p "URL_INPUT=  URL > "
if /i "!URL_INPUT!"=="END" goto url_loop_done
if "!URL_INPUT!"=="" goto url_loop
echo !URL_INPUT!>>"%URL_FILE%"
goto url_loop

:url_loop_done
if not exist "%URL_FILE%" (
    echo [ERROR] No URLs entered.
    pause
    exit /b 1
)

:: Count URLs
set "URL_COUNT=0"
for /f %%A in ("%URL_FILE%") do set /a URL_COUNT+=1
for /f "tokens=*" %%L in (%URL_FILE%) do set /a URL_COUNT+=1
set "URL_COUNT=0"
for /f %%L in (%URL_FILE%) do set /a URL_COUNT+=1

echo.
echo [OK] !URL_COUNT! URL(s) captured.
echo.

:: ----------------------------------------------------------
echo ============================================================
echo   STEP 2 of 3  --  Report Details
echo   (Press Enter to skip any field)
echo ============================================================
echo.

set "APP_NAME="
set "CAN_ID="
set "SERVER_IP="
set "REQUEST_ID="

set /p "APP_NAME=  Application Name        : "
set /p "CAN_ID=    CAN ID                  : "
set /p "SERVER_IP= Server IP               : "
set /p "REQUEST_ID=Request ID (SNs)        : "

echo.
echo ============================================================
echo   STEP 3 of 3  --  Scanning + Generating PDF...
echo ============================================================
echo.

:: ----------------------------------------------------------
:: 4. Write embedded Python runner to temp file
:: ----------------------------------------------------------
set "PY_RUNNER=%TEMP%\icici_runner_%RANDOM%.py"
set "ICICI_OUT_PATH_FILE=%TEMP%\icici_out_%RANDOM%.txt"

echo import sys, os, warnings, time > "%PY_RUNNER%"
echo from datetime import datetime >> "%PY_RUNNER%"
echo warnings.filterwarnings("ignore") >> "%PY_RUNNER%"
echo try: >> "%PY_RUNNER%"
echo     import urllib3 >> "%PY_RUNNER%"
echo     urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) >> "%PY_RUNNER%"
echo except Exception: >> "%PY_RUNNER%"
echo     pass >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo # Zscaler SSL fix - patch requests to skip verify >> "%PY_RUNNER%"
echo try: >> "%PY_RUNNER%"
echo     from requests import adapters as _ra >> "%PY_RUNNER%"
echo     _orig = _ra.HTTPAdapter.send >> "%PY_RUNNER%"
echo     def _send(self, req, **kw): >> "%PY_RUNNER%"
echo         kw['verify'] = False >> "%PY_RUNNER%"
echo         return _orig(self, req, **kw) >> "%PY_RUNNER%"
echo     _ra.HTTPAdapter.send = _send >> "%PY_RUNNER%"
echo except Exception as e: >> "%PY_RUNNER%"
echo     print(f"[WARN] Could not patch requests: {e}") >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo BACKEND_ROOT = r"%BACKEND_DIR%" >> "%PY_RUNNER%"
echo sys.path.insert(0, BACKEND_ROOT) >> "%PY_RUNNER%"
echo os.chdir(BACKEND_ROOT) >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo try: >> "%PY_RUNNER%"
echo     from dotenv import load_dotenv >> "%PY_RUNNER%"
echo     load_dotenv(os.path.join(BACKEND_ROOT, ".env")) >> "%PY_RUNNER%"
echo except Exception: >> "%PY_RUNNER%"
echo     pass >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo from app.services.scanner import scan_url_service >> "%PY_RUNNER%"
echo from app.services.pdf_report import generate_pdf_report >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo def pv(v): >> "%PY_RUNNER%"
echo     return None if not v or v.strip().upper() in ("NA","N/A","","NONE") else v.strip() >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo url_file      = os.environ.get("ICICI_URL_FILE","") >> "%PY_RUNNER%"
echo app_name      = pv(os.environ.get("ICICI_APP_NAME","")) >> "%PY_RUNNER%"
echo can_id        = pv(os.environ.get("ICICI_CAN_ID","")) >> "%PY_RUNNER%"
echo server_ip     = pv(os.environ.get("ICICI_SERVER_IP","")) >> "%PY_RUNNER%"
echo request_id    = pv(os.environ.get("ICICI_REQUEST_ID","")) >> "%PY_RUNNER%"
echo final_comment = "" >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo with open(url_file,"r") as f: >> "%PY_RUNNER%"
echo     urls = [l.strip() for l in f if l.strip()] >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo if not urls: >> "%PY_RUNNER%"
echo     print("[ERROR] No URLs found.") >> "%PY_RUNNER%"
echo     sys.exit(1) >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo total = len(urls) >> "%PY_RUNNER%"
echo print(f"\n  Total URLs to scan: {total}") >> "%PY_RUNNER%"
echo print("  " + "-" * 56) >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo # Scan each URL one-by-one and show live progress >> "%PY_RUNNER%"
echo results = [] >> "%PY_RUNNER%"
echo for i, url in enumerate(urls, 1): >> "%PY_RUNNER%"
echo     bar_done  = int((i-1) / total * 20) >> "%PY_RUNNER%"
echo     bar_left  = 20 - bar_done >> "%PY_RUNNER%"
echo     bar_str   = "[" + "#" * bar_done + "-" * bar_left + "]" >> "%PY_RUNNER%"
echo     print(f"  [{i}/{total}] {bar_str} Scanning: {url}") >> "%PY_RUNNER%"
echo     print(f"         Please wait - querying VirusTotal, AbuseIPDB, SSLyze, WHOIS...") >> "%PY_RUNNER%"
echo     t_start = time.time() >> "%PY_RUNNER%"
echo     try: >> "%PY_RUNNER%"
echo         res = scan_url_service(url) >> "%PY_RUNNER%"
echo         t_elapsed = time.time() - t_start >> "%PY_RUNNER%"
echo         level = res.get("final_risk_level","Unknown") >> "%PY_RUNNER%"
echo         score = res.get("score", "?") >> "%PY_RUNNER%"
echo         bar_done2 = int(i / total * 20) >> "%PY_RUNNER%"
echo         bar_left2 = 20 - bar_done2 >> "%PY_RUNNER%"
echo         bar_str2  = "[" + "#" * bar_done2 + "-" * bar_left2 + "]" >> "%PY_RUNNER%"
echo         print(f"  [{i}/{total}] {bar_str2} Done in {t_elapsed:.1f}s  |  Risk: {level}  |  Score: {score}") >> "%PY_RUNNER%"
echo         results.append(res) >> "%PY_RUNNER%"
echo     except Exception as e: >> "%PY_RUNNER%"
echo         t_elapsed = time.time() - t_start >> "%PY_RUNNER%"
echo         print(f"  [{i}/{total}] ERROR after {t_elapsed:.1f}s: {e}") >> "%PY_RUNNER%"
echo     print() >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo print("  " + "-" * 56) >> "%PY_RUNNER%"
echo print(f"  All {len(results)} URL(s) scanned.\n") >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo # Summary table >> "%PY_RUNNER%"
echo print("  SCAN SUMMARY") >> "%PY_RUNNER%"
echo print("  " + "=" * 56) >> "%PY_RUNNER%"
echo print(f"  {'#':<4} {'URL':<42} {'RISK'}") >> "%PY_RUNNER%"
echo print("  " + "-" * 56) >> "%PY_RUNNER%"
echo for idx, r in enumerate(results, 1): >> "%PY_RUNNER%"
echo     u = r.get("url","")[:41] >> "%PY_RUNNER%"
echo     lvl = r.get("final_risk_level","?") >> "%PY_RUNNER%"
echo     print(f"  {idx:<4} {u:<42} {lvl}") >> "%PY_RUNNER%"
echo print("  " + "=" * 56) >> "%PY_RUNNER%"
echo print() >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo # Generate PDF >> "%PY_RUNNER%"
echo print("  Generating PDF report...") >> "%PY_RUNNER%"
echo try: >> "%PY_RUNNER%"
echo     pdf = generate_pdf_report( >> "%PY_RUNNER%"
echo         results, >> "%PY_RUNNER%"
echo         final_comment=final_comment, >> "%PY_RUNNER%"
echo         app_name=app_name, >> "%PY_RUNNER%"
echo         can_id=can_id, >> "%PY_RUNNER%"
echo         server_ip=server_ip, >> "%PY_RUNNER%"
echo         request_id=request_id >> "%PY_RUNNER%"
echo     ) >> "%PY_RUNNER%"
echo except Exception as e: >> "%PY_RUNNER%"
echo     print(f"[ERROR] PDF failed: {e}") >> "%PY_RUNNER%"
echo     sys.exit(1) >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo ts       = datetime.now().strftime("%%Y%%m%%d_%%H%%M%%S") >> "%PY_RUNNER%"
echo safe_app = (app_name or "ICICI").replace(" ","_").replace("/","_")[:30] >> "%PY_RUNNER%"
echo safe_can = (can_id or "").replace(" ","_").replace("/","_")[:20] >> "%PY_RUNNER%"
echo parts    = [p for p in [safe_app, safe_can] if p] >> "%PY_RUNNER%"
echo fname    = "_".join(parts) + f"_RiskAssessmentReport_{ts}.pdf" >> "%PY_RUNNER%"
echo rdir     = os.path.abspath(os.path.join(BACKEND_ROOT,"..","Reports")) >> "%PY_RUNNER%"
echo os.makedirs(rdir, exist_ok=True) >> "%PY_RUNNER%"
echo fpath    = os.path.join(rdir, fname) >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo with open(fpath,"wb") as f: >> "%PY_RUNNER%"
echo     f.write(pdf) >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo size_kb = len(pdf) // 1024 >> "%PY_RUNNER%"
echo print("  " + "=" * 56) >> "%PY_RUNNER%"
echo print("  REPORT SAVED SUCCESSFULLY") >> "%PY_RUNNER%"
echo print("  " + "=" * 56) >> "%PY_RUNNER%"
echo print(f"  File  : {fname}") >> "%PY_RUNNER%"
echo print(f"  Folder: {rdir}") >> "%PY_RUNNER%"
echo print(f"  Size  : {size_kb} KB") >> "%PY_RUNNER%"
echo print("  " + "=" * 56) >> "%PY_RUNNER%"
echo. >> "%PY_RUNNER%"
echo opf = os.environ.get("ICICI_OUT_PATH_FILE","") >> "%PY_RUNNER%"
echo if opf: >> "%PY_RUNNER%"
echo     with open(opf,"w") as f: f.write(fpath) >> "%PY_RUNNER%"

:: ----------------------------------------------------------
:: 5. Export inputs as env vars for Python
:: ----------------------------------------------------------
set "ICICI_URL_FILE=%URL_FILE%"
set "ICICI_APP_NAME=%APP_NAME%"
set "ICICI_CAN_ID=%CAN_ID%"
set "ICICI_SERVER_IP=%SERVER_IP%"
set "ICICI_REQUEST_ID=%REQUEST_ID%"

:: ----------------------------------------------------------
:: 6. Run
:: ----------------------------------------------------------
"!PYTHON_EXE!" "%PY_RUNNER%"
set "PY_EXIT=%errorlevel%"

:: ----------------------------------------------------------
:: 7. Cleanup
:: ----------------------------------------------------------
del "%URL_FILE%" 2>nul
del "%PY_RUNNER%" 2>nul

if "%PY_EXIT%" neq "0" (
    echo.
    echo  [ERROR] Scanner failed. See output above for details.
    del "%ICICI_OUT_PATH_FILE%" 2>nul
    echo.
    pause
    exit /b %PY_EXIT%
)

:: ----------------------------------------------------------
:: 8. Open the PDF automatically
:: ----------------------------------------------------------
if exist "%ICICI_OUT_PATH_FILE%" (
    set /p "REPORT_PATH="<"%ICICI_OUT_PATH_FILE%"
    del "%ICICI_OUT_PATH_FILE%" 2>nul
    echo.
    echo  Opening PDF report...
    start "" "!REPORT_PATH!"
) else (
    del "%ICICI_OUT_PATH_FILE%" 2>nul
)

echo.
echo  Press any key to close this window...
pause >nul
endlocal
