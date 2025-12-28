@echo off
REM Batch script to open Windows Firewall port for PocketBridge backend
REM Run this as Administrator

echo Opening Windows Firewall port 3001 for PocketBridge backend...

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator!
    echo Right-click this file and select "Run as Administrator"
    pause
    exit /b 1
)

REM Remove existing rule if it exists
netsh advfirewall firewall delete rule name="PocketBridge Backend Port 3001" >nul 2>&1

REM Add new firewall rule
netsh advfirewall firewall add rule name="PocketBridge Backend Port 3001" dir=in action=allow protocol=TCP localport=3001 profile=domain,private,public

if %errorLevel% equ 0 (
    echo.
    echo [SUCCESS] Firewall rule added successfully!
    echo Port 3001 is now open for incoming connections.
    echo.
    echo You can now access the backend from other devices on your network:
    echo   http://192.168.18.8:3001/health
    echo.
) else (
    echo.
    echo [ERROR] Failed to add firewall rule.
    echo.
)

pause



