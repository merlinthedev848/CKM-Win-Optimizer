@echo off
:: KISS launcher for CKMWinFix.ps1
:: Forces PowerShell to run as Administrator and execute the script

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% == 0 (
    :: Already admin
    powershell.exe -ExecutionPolicy Bypass -File "%~dp0CKMWinFix.ps1"
) else (
    :: Relaunch as admin
    echo Requesting administrator privileges...
    powershell.exe Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -File "%~dp0CKMWinFix.ps1"' -Verb RunAs
)
