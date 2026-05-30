@echo off
setlocal enabledelayedexpansion
title Hidekey - Super Box Controller

:: =========================================================================
:: AUTO-ELEVATE TO ADMINISTRATOR (required for Wintun TUN adapter)
:: =========================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [Hidekey] Requesting Administrator privileges ^(required for Wintun TUN^)...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"

:: =========================================================================
:: LOAD OR CREATE SETTINGS
:: =========================================================================
if exist settings.bat call settings.bat

:: Default values for all settings
if not defined SUBSCRIBE_URL         set "SUBSCRIBE_URL=hidekey://YOUR_UUID_HERE@YOUR_SERVER_IP:8443#Default"
if not defined DEBUG_MODE           set "DEBUG_MODE=false"
if not defined BUILD_MODE           set "BUILD_MODE=release"
if not defined DNS_OVERRIDE         set "DNS_OVERRIDE=false"
if not defined DNS_SERVER           set "DNS_SERVER=8.8.8.8"
if not defined TUN_ADDR             set "TUN_ADDR=10.0.0.2"
if not defined TUN_MTU              set "TUN_MTU=9000"
if not defined TUN_STACK            set "TUN_STACK=smoltcp"
if not defined TUN_NAME             set "TUN_NAME=hidekey_tun"

:: =========================================================================
:: MAIN MENU
:: =========================================================================
:menu
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|        Super Box  -  Hidekey Polymorphic VPN Core        ^|
echo  ^|        Pure Rust. Zero-Legacy. WebRTC steganography.    ^|
echo  +----------------------------------------------------------+
echo.

:: Live status check
tasklist /fi "imagename eq super_box.exe" 2>nul | findstr /i "super_box.exe" >nul
if errorlevel 1 (
    echo   Status : [OFFLINE]
) else (
    echo   Status : [ONLINE]  ^<-- Core is running!
)

:: Show Link (truncated to 55 chars)
set "DISP_URL=!SUBSCRIBE_URL:~0,55!"
if not "!SUBSCRIBE_URL!"=="!SUBSCRIBE_URL:~0,55!" set "DISP_URL=!DISP_URL!..."
echo   Link   : !DISP_URL!
echo   Build  : !BUILD_MODE!  ^|  Stack: !TUN_STACK!  ^|  MTU: !TUN_MTU!  ^|  DNS: !DNS_SERVER!
echo   UI     : Running on http://127.0.0.1:8082

echo.
echo  +----------------------------------------------------------+
echo.
echo   [1] Start Hidekey TUN Core  [2] Stop Core
echo   [3] Restart Core            [4] Set Hidekey Link manually
echo   [5] Rebuild Binary          [6] Auto-Connect via Hide-UI
echo   [7] Open Hide-UI Panel      [8] DNS Settings
echo   [9] Toggle Debug Mode       [0] Exit
echo.
echo  +----------------------------------------------------------+
echo.
set "choice="
set /p "choice=  Select [0-9]: "

if /i "!choice!"=="1" goto :start_core
if /i "!choice!"=="2" goto :stop_core
if /i "!choice!"=="3" goto :restart_core
if /i "!choice!"=="4" goto :set_link
if /i "!choice!"=="5" goto :compile_core
if /i "!choice!"=="6" goto :auto_install
if /i "!choice!"=="7" goto :open_ui
if /i "!choice!"=="8" goto :dns_settings
if /i "!choice!"=="9" goto :toggle_debug
if /i "!choice!"=="0" goto :exit
goto :menu

:: =========================================================================
:: START CORE
:: =========================================================================
:start_core
echo.
echo [*] Stopping any previous Super Box instance...
taskkill /f /im super_box.exe >nul 2>&1
echo [*] Cleaning up old settings...
powershell -NoProfile -NonInteractive -Command "Get-NetAdapter | Where-Object Status -eq 'Up' | Set-DnsClientServerAddress -ResetServerAddresses" >nul 2>&1
call :restore_dns_silent

:: Select binary
set "BIN=target\release\super_box.exe"
if "!BUILD_MODE!"=="debug" set "BIN=target\debug\super_box.exe"

echo [*] Building/checking !BUILD_MODE! binary...
call :do_build
if errorlevel 1 (
    echo [ERROR] Build failed! Cannot start.
    pause
    goto :menu
)

:: DNS override
if "!DNS_OVERRIDE!"=="true" call :set_dns_for_tun

:: Log level
set "RUST_LOG=info"
if "!DEBUG_MODE!"=="true" set "RUST_LOG=debug"

echo [*] Launching Super Box Hidekey Core...
echo     Binary : !BIN!
echo     Link   : !SUBSCRIBE_URL:~0,65!...
echo.

start "Super Box - Hidekey Core" cmd /k "set RUST_LOG=!RUST_LOG!&set "DNS_SERVER=!DNS_SERVER!"&echo.&echo [Super Box is running]&echo.&"!BIN!" "!SUBSCRIBE_URL!"&echo.&echo [Core stopped. Press any key to close]&pause"

:: Verify launch
ping 127.0.0.1 -n 3 >nul
tasklist /fi "imagename eq super_box.exe" 2>nul | findstr /i "super_box.exe" >nul
if errorlevel 1 (
    echo.
    echo [ERROR] Core failed to start. Check the Core window for errors.
    echo         Make sure you ran this script as Administrator!
    call :restore_dns_silent
) else (
    echo [OK] Core is running successfully.
    echo [OK] Hide-UI panel is active at http://127.0.0.1:8082
)
echo.
pause
goto :menu

:: =========================================================================
:: STOP CORE
:: =========================================================================
:stop_core
echo.
echo [*] Stopping Super Box Core...
taskkill /f /im super_box.exe >nul 2>&1
call :restore_dns_silent
echo [OK] Core stopped. DNS restored.
ping 127.0.0.1 -n 2 >nul
goto :menu

:: =========================================================================
:: RESTART
:: =========================================================================
:restart_core
echo [*] Restarting...
taskkill /f /im super_box.exe >nul 2>&1
call :restore_dns_silent
ping 127.0.0.1 -n 2 >nul
goto :start_core

:: =========================================================================
:: BUILD BINARY
:: =========================================================================
:compile_core
echo.
echo [*] Stopping core before build...
taskkill /f /im super_box.exe >nul 2>&1
call :do_build
echo.
if %errorlevel% neq 0 (
    echo [ERROR] Build failed!
) else (
    echo [OK] Build successful!
)
pause
goto :menu

:do_build
echo [*] Building Super Box Core (!BUILD_MODE!)... Please wait ~30 seconds.
if "!BUILD_MODE!"=="release" (
    cargo build --release
) else (
    cargo build
)
exit /b %errorlevel%

:: =========================================================================
:: SET LINK
:: =========================================================================
:set_link
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|                SET HIDEKEY LINK MANUALLY                 ^|
echo  +----------------------------------------------------------+
echo.
echo  Current:
echo  !SUBSCRIBE_URL!
echo.
echo  Paste your hidekey:// config link.
echo  (Press Enter with no input to keep current value)
echo.
set "NEW_URL="
set /p "NEW_URL=  New Link: "
if defined NEW_URL (
    set "SUBSCRIBE_URL=!NEW_URL!"
    call :save_settings
    echo.
    echo [OK] Link saved!
) else (
    echo [--] Unchanged.
)
ping 127.0.0.1 -n 2 >nul
goto :menu

:: =========================================================================
:: AUTO INSTALL VIA HIDE-UI
:: =========================================================================
:auto_install
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|               HIDE-UI AUTOMATIC INSTALLATION             ^|
echo  ^|       Connect to remote Ubuntu Panel to fetch config     ^|
echo  +----------------------------------------------------------+
echo.
set "PANEL_IP="
set /p "PANEL_IP=  Enter Server IP: "
if not defined PANEL_IP goto :menu

set "PANEL_PORT="
set /p "PANEL_PORT=  Enter Panel Port [8082]: "
if not defined PANEL_PORT set "PANEL_PORT=8082"

set "PANEL_USER="
set /p "PANEL_USER=  Enter Admin Username [admin]: "
if not defined PANEL_USER set "PANEL_USER=admin"

set "PANEL_PASS="
set /p "PANEL_PASS=  Enter Admin Password: "
if not defined PANEL_PASS set "PANEL_PASS=hidekey2026"

echo.
echo  [*] Reaching panel at http://!PANEL_IP!:!PANEL_PORT!...
echo  [*] Authenticating as !PANEL_USER!...

:: Write a temporary PowerShell script to avoid all CMD quoting hell
set "PS_TEMP=%TEMP%\hk_auto_install_%RANDOM%.ps1"
(
echo $ErrorActionPreference = 'Stop'
echo $ip   = '!PANEL_IP!'
echo $port = '!PANEL_PORT!'
echo $user = '!PANEL_USER!'
echo $pass = '!PANEL_PASS!'
echo try {
echo     $authBody = ConvertTo-Json @{ username = $user; password = $pass }
echo     $authResp = Invoke-RestMethod -Method Post -Uri "http://${ip}:${port}/api/auth" -ContentType 'application/json' -Body $authBody -TimeoutSec 15
echo     $peerBody = ConvertTo-Json @{ name = "Windows-$(hostname)" }
echo     $peerResp = Invoke-RestMethod -Method Post -Uri "http://${ip}:${port}/api/peers" -ContentType 'application/json' -Body $peerBody -TimeoutSec 15
echo     Write-Output ("SUCCESS:" + $peerResp.config_url)
echo } catch {
echo     Write-Output ("ERROR:" + $_.Exception.Message)
echo }
) > "%PS_TEMP%"

set "RESP="
for /f "usebackq delims=" %%K in (`powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%PS_TEMP%" 2^>^&1`) do (
    if "!RESP!"=="" set "RESP=%%K"
)
del "%PS_TEMP%" >nul 2>&1

if "!RESP:~0,8!"=="SUCCESS:" (
    set "NEW_LINK=!RESP:~8!"
    set "SUBSCRIBE_URL=!NEW_LINK!"
    call :save_settings
    echo.
    echo  [OK] Successfully connected to Hide-UI panel!
    echo  [OK] Generated Hidekey config has been automatically saved:
    echo.
    echo  !SUBSCRIBE_URL!
    echo.
    echo  You can now press [1] to start the core.
) else (
    echo.
    echo  [ERROR] Auto-install failed:
    echo  !RESP!
    echo.
    echo  Troubleshooting:
    echo    1. Make sure panel is running at http://!PANEL_IP!:!PANEL_PORT!
    echo    2. Default credentials  ^|  user: admin  ^|  pass: hidekey2026
    echo    3. Or paste link manually with option [4]
    echo.
)
pause
goto :menu

:: =========================================================================
:: OPEN UI DASHBOARD
:: =========================================================================
:open_ui
echo [*] Opening Hide-UI Dashboard in your default browser...
start http://127.0.0.1:8082
ping 127.0.0.1 -n 2 >nul
goto :menu

:: =========================================================================
:: DNS SETTINGS
:: =========================================================================
:dns_settings
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|                  DNS SETTINGS                            ^|
echo  +----------------------------------------------------------+
echo.
echo  Current settings:
echo    DNS Override : !DNS_OVERRIDE!
echo    DNS Server   : !DNS_SERVER!
echo.
set "T="
set /p "T=  Enable physical DNS override? (true/false) [!DNS_OVERRIDE!]: "
if not "!T!"=="" set "DNS_OVERRIDE=!T!"

set "D="
set /p "D=  DNS Server IP [!DNS_SERVER!]: "
if not "!D!"=="" set "DNS_SERVER=!D!"

call :save_settings
echo.
echo [OK] DNS settings saved!
ping 127.0.0.1 -n 2 >nul
goto :menu

:: =========================================================================
:: TOGGLE DEBUG
:: =========================================================================
:toggle_debug
if "!DEBUG_MODE!"=="true" (
    set "DEBUG_MODE=false"
    set "BUILD_MODE=release"
) else (
    set "DEBUG_MODE=true"
    set "BUILD_MODE=debug"
)
call :save_settings
echo.
echo [OK] Debug=!DEBUG_MODE! / Build mode=!BUILD_MODE!
ping 127.0.0.1 -n 2 >nul
goto :menu

:: =========================================================================
:: DNS HELPER FUNCTIONS
:: =========================================================================
:set_dns_for_tun
set "PHYS_IF="
for /f "skip=1 delims=" %%A in ('powershell -NoProfile -NonInteractive -Command "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceAlias -ne 'hidekey_tun' } | Sort-Object Speed -Descending | Select-Object -First 1 -ExpandProperty InterfaceAlias" 2^>nul') do (
    if "!PHYS_IF!"=="" set "PHYS_IF=%%A"
)
if "!PHYS_IF!"=="" goto :eof

set "ORIG_DNS="
for /f "delims=" %%B in ('powershell -NoProfile -NonInteractive -Command "try { $a = (Get-DnsClientServerAddress -InterfaceAlias '!PHYS_IF!' -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses; if ($a) { $a -join ',' } else { 'DHCP' } } catch { 'DHCP' }" 2^>nul') do set "ORIG_DNS=%%B"
if "!ORIG_DNS!"=="" set "ORIG_DNS=DHCP"

(
    echo set "ORIG_DNS=!ORIG_DNS!"
    echo set "PHYS_IF=!PHYS_IF!"
) > dns_backup.bat

powershell -NoProfile -NonInteractive -Command "Set-DnsClientServerAddress -InterfaceAlias '!PHYS_IF!' -ServerAddresses '!DNS_SERVER!'" >nul 2>&1
goto :eof

:restore_dns_silent
if not exist dns_backup.bat goto :eof
call dns_backup.bat
if "!ORIG_DNS!"=="DHCP" (
    powershell -NoProfile -NonInteractive -Command "Set-DnsClientServerAddress -InterfaceAlias '!PHYS_IF!' -ResetServerAddresses" >nul 2>&1
) else (
    for /f "tokens=1,2 delims=," %%X in ("!ORIG_DNS!") do (
        powershell -NoProfile -NonInteractive -Command "Set-DnsClientServerAddress -InterfaceAlias '!PHYS_IF!' -ServerAddresses @('%%X','%%Y')" >nul 2>&1
    )
)
del dns_backup.bat >nul 2>&1
goto :eof

:: =========================================================================
:: SAVE SETTINGS
:: =========================================================================
:save_settings
(
    echo set "SUBSCRIBE_URL=!SUBSCRIBE_URL!"
    echo set "DEBUG_MODE=!DEBUG_MODE!"
    echo set "BUILD_MODE=!BUILD_MODE!"
    echo set "DNS_OVERRIDE=!DNS_OVERRIDE!"
    echo set "DNS_SERVER=!DNS_SERVER!"
    echo set "TUN_ADDR=!TUN_ADDR!"
    echo set "TUN_MTU=!TUN_MTU!"
    echo set "TUN_STACK=!TUN_STACK!"
    echo set "TUN_NAME=!TUN_NAME!"
) > settings.bat
goto :eof

:: =========================================================================
:: EXIT
:: =========================================================================
:exit
call :restore_dns_silent
echo.
echo Goodbye!
exit /b 0
