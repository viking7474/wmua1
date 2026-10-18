@echo off
setlocal EnableExtensions
rem fix_driver.cmd - Install the winra1n_mobile_device (libusbK) driver package.
rem After install, Windows auto-binds libusbK to USB\VID_05AC&PID_1227 (DFU),
rem PID_1338 and PID_4141 (PongoOS) on every enumeration: no Zadig needed,
rem binding survives reboots and USB port changes.
rem Needs the kit produced by: tools\extract_driver_kit.ps1
rem Usage:  fix_driver.cmd [kit_dir]

set "KIT=%~1"
if not "%KIT%"=="" goto :have_kit
if not "%MYJB_DRIVER_KIT%"=="" set "KIT=%MYJB_DRIVER_KIT%"
if not "%KIT%"=="" goto :have_kit

set "KIT=%~dp0..\driver_kit"
if exist "%KIT%\libusbK\winra1n_mobile_device.inf" goto :have_kit
set "KIT=%~dp0driver_kit"
if exist "%KIT%\libusbK\winra1n_mobile_device.inf" goto :have_kit
set "KIT=%CD%\driver_kit"
if exist "%KIT%\libusbK\winra1n_mobile_device.inf" goto :have_kit

echo [fix_driver] driver_kit not found (need libusbK\winra1n_mobile_device.inf).
echo Run first:  powershell -ExecutionPolicy Bypass -File "%~dp0extract_driver_kit.ps1"
echo Or pass the kit folder:  fix_driver.cmd D:\path\to\winra1n_driver_kit
pause
exit /b 1

:have_kit
if not exist "%KIT%\libusbK\winra1n_mobile_device.inf" (
    echo [fix_driver] invalid kit dir: %KIT%
    pause
    exit /b 1
)

net session >nul 2>&1
if errorlevel 1 (
    echo [fix_driver] requesting administrator rights...
    set "MYJB_DRIVER_KIT=%KIT%"
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

echo [fix_driver] kit: %KIT%
certutil -addstore -f Root "%KIT%\trust\winra1n_mobile_device.cer" || goto :fail
certutil -addstore -f TrustedPublisher "%KIT%\trust\winra1n_mobile_device.cer" || goto :fail
pnputil /add-driver "%KIT%\libusbK\winra1n_mobile_device.inf" /install || goto :fail

echo.
echo [fix_driver] done. Replug the iPhone / re-enter DFU, then run myjb_ktool.exe
echo Verify (PowerShell):
echo   Get-PnpDevice ^| Where-Object { $_.InstanceId -match 'VID_05AC' } ^| Format-Table Status,Class,FriendlyName,InstanceId -AutoSize
pause
exit /b 0

:fail
echo.
echo [fix_driver] FAILED - see the error above.
pause
exit /b 1
