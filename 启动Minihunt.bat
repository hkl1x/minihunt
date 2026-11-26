@echo off
setlocal
cd /d "%~dp0"

:: ============================================================
::  Minihunt one-click start: one UAC, kill old instance -> admin restart -> proxy+debug ready
::  step 2 launches WeChat itself (wechat_exe in minihunt_config.json)
::  service runs in minimized console (title: MinihuntService), log in _server_log.txt
::  launcher output in _boot_log.txt
::  NOTE: keep this file ASCII-only (no Chinese comments) - cmd parses batch files
::  in the OEM/GBK codepage and UTF-8 Chinese bytes can break parsing.
:: ============================================================

set "BOOTLOG=%~dp0_boot_log.txt"
echo [%date% %time%] boot start > "%BOOTLOG%"

:: ---- 0) locate python absolute path (PATH unreliable after elevation) ----
set "PYEXE="
for /f "delims=" %%i in ('where.exe python 2^>nul') do if not defined PYEXE set "PYEXE=%%i"
if not defined PYEXE (
    echo [X] python.exe not found, please install Python and add to PATH
    echo [%date% %time%] ERROR: python not found >> "%BOOTLOG%"
    pause
    exit /b 1
)
echo [%date% %time%] python=%PYEXE% >> "%BOOTLOG%"

:: ---- not admin yet: relaunch self via UAC (one prompt) ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [%date% %time%] not admin, relaunch via UAC >> "%BOOTLOG%"
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
echo [%date% %time%] admin ok, boot phase begins >> "%BOOTLOG%"

:BOOT
set "ROOT=%~dp0"
cd /d "%ROOT%"
echo [%date% %time%] elevated instance started >> "%BOOTLOG%"

echo [1/5] killing old service instances...
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -match 'webapp_server' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
timeout /t 2 /nobreak >nul

echo [2/5] launching WeChat (wechat_exe in minihunt_config.json)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; try { $cfg = Get-Content -Raw -Encoding UTF8 '%ROOT%minihunt_config.json' | ConvertFrom-Json; $wx = [string]$cfg.wechat_exe; if(-not $wx){ throw 'wechat_exe not set in minihunt_config.json' }; $wx = [Environment]::ExpandEnvironmentVariables($wx); if(-not (Test-Path -LiteralPath $wx)){ throw \"wechat_exe not found: $wx\" }; Start-Process -FilePath $wx; Write-Host ('[2/5] WeChat launched: ' + $wx) } catch { Write-Host ('[X] WeChat launch failed: ' + $_.Exception.Message); exit 1 }"
if %errorlevel% neq 0 (
    echo [%date% %time%] ERROR: WeChat launch failed >> "%BOOTLOG%"
    pause
    exit /b 1
)
echo [%date% %time%] WeChat launched >> "%BOOTLOG%"
timeout /t 3 /nobreak >nul

echo [3/5] starting service (minimized window, log to _server_log.txt)...
start "MinihuntService" /min /d "%ROOT%" cmd /c ""%PYEXE%" webapp_server.py > "%ROOT%_server_log.txt" 2>&1"
echo [%date% %time%] service spawned, root=%ROOT% >> "%BOOTLOG%"

echo [4/5] waiting for service ready, then auto-start proxy and debug engine...
powershell -NoProfile -Command "$ok=$false; for($i=0;$i -lt 25;$i++){ try { Invoke-WebRequest 'http://127.0.0.1:8800/api/status' -UseBasicParsing -TimeoutSec 2 | Out-Null; $ok=$true; break } catch { Start-Sleep -m 1000 } }; if($ok){ try { Invoke-WebRequest 'http://127.0.0.1:8800/api/proxy/start' -Method POST -ContentType 'application/json' -Body '{\"mode\":\"local\"}' -UseBasicParsing -TimeoutSec 120 | Out-Null } catch {}; try { Invoke-WebRequest 'http://127.0.0.1:8800/api/engine/start' -Method POST -ContentType 'application/json' -Body '{}' -UseBasicParsing -TimeoutSec 60 | Out-Null } catch {}; Start-Process 'http://127.0.0.1:8800' } else { Write-Host '[X] service not ready in 25s, check _server_log.txt and _boot_log.txt' }"
if %errorlevel% neq 0 echo [%date% %time%] wait-ready powershell failed >> "%BOOTLOG%"

echo [5/5] done. if browser did not open, visit http://127.0.0.1:8800
echo [%date% %time%] boot end >> "%BOOTLOG%"
timeout /t 3 >nul
exit /b
