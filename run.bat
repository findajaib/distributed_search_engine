@echo off
setlocal enabledelayedexpansion

:: Configuration
set "BUILD_DIR=build"
set "LOG_DIR=logs"
set "MAIN_PORT=50050"
set "REGISTRY_PORT=50052"
set "WORKER_START_PORT=50051"
set "REGISTRY_ADDRESS=localhost:50052"

:: Create required directories
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

:menu
cls
echo ===================================
echo    Search Engine Service Manager
echo ===================================
echo.
echo 1. Build All Services
echo 2. Start All Services
echo.
set /p choice="Enter your choice (1-2): "

if "%choice%"=="1" goto build
if "%choice%"=="2" goto start_all

echo Invalid choice. Please try again.
timeout /t 2 >nul
goto menu

:build
echo.
echo Building all services...
go build -o "%BUILD_DIR%\main.exe" .
go build -o "%BUILD_DIR%\registry.exe" ./registry
go build -o "%BUILD_DIR%\worker.exe" ./worker
echo Build complete!
echo.
pause
goto menu

:start_all
echo.
set /p worker_count="Enter number of workers (default: 1): "
if "%worker_count%"=="" set worker_count=1
echo Starting all services with %worker_count% workers...

:: Start Registry
start /B "" "%BUILD_DIR%\registry.exe" --port %REGISTRY_PORT% > "%LOG_DIR%\registry.log" 2>&1
timeout /t 2 >nul

:: Start Main
start /B "" "%BUILD_DIR%\main.exe" --port %MAIN_PORT% --registry %REGISTRY_ADDRESS% > "%LOG_DIR%\main.log" 2>&1
timeout /t 2 >nul

:: Start Workers
for /L %%i in (0,1,%worker_count%-1) do (
    set /a port=%WORKER_START_PORT% + %%i
    call start /B "" "%BUILD_DIR%\worker.exe" --port !port! --db "search_engine.db" --registry %REGISTRY_ADDRESS% > "%LOG_DIR%\worker_%%i.log" 2>&1
    timeout /t 1 >nul
)

echo All services started!
echo http://localhost:8080/
echo.
pause
goto menu 