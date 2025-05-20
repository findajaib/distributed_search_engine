@echo off
setlocal enabledelayedexpansion

:: Configuration
set "BUILD_DIR=build"
set "LOG_DIR=logs"
set "MAIN_PORT=8080"
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
echo 3. Stop All Services
echo 4. Exit
echo.
set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" goto build
if "%choice%"=="2" goto start_all
if "%choice%"=="3" goto stop_all
if "%choice%"=="4" goto end

echo Invalid choice. Please try again.
timeout /t 2 >nul
goto menu

:build
echo.
echo Building all services...
go build -o "%BUILD_DIR%\main.exe"  ./cmd/server
if errorlevel 1 (
    echo Error building main service
    pause
    goto menu
)
go build -o "%BUILD_DIR%\registry.exe" ./registry
if errorlevel 1 (
    echo Error building registry service
    pause
    goto menu
)
go build -o "%BUILD_DIR%\worker.exe" ./worker
if errorlevel 1 (
    echo Error building worker service
    pause
    goto menu
)
echo Build complete!
echo.
pause
goto menu

:stop_all
echo.
echo Stopping all services...
taskkill /F /IM main.exe /T >nul 2>&1
taskkill /F /IM registry.exe /T >nul 2>&1
taskkill /F /IM worker.exe /T >nul 2>&1
echo Waiting for services to stop...
timeout /t 5 >nul
echo All services stopped!
echo.
goto :eof

:start_all
echo.
:: Stop any existing services first
call :stop_all
echo.
set /p worker_count="Enter number of workers (default: 1): "
if "%worker_count%"=="" set worker_count=1
echo Starting all services with %worker_count% workers...

:: Start Registry
echo Starting registry service...
start /B "" "%BUILD_DIR%\registry.exe" --port %REGISTRY_PORT% > "%LOG_DIR%\registry.log" 2>&1
timeout /t 5 >nul

:: Check if registry started successfully
netstat -an | find ":%REGISTRY_PORT%" >nul
if errorlevel 1 (
    echo Error: Registry service failed to start
    echo Check %LOG_DIR%\registry.log for details
    pause
    goto menu
)
echo Registry service started successfully.

:: Start Main
echo Starting main service...
start /B "" "%BUILD_DIR%\main.exe" --port %MAIN_PORT% --registry %REGISTRY_ADDRESS% > "%LOG_DIR%\main.log" 2>&1
timeout /t 5 >nul

:: Check if main service started successfully
netstat -an | find ":%MAIN_PORT%" >nul
if errorlevel 1 (
    echo Error: Main service failed to start
    echo Check %LOG_DIR%\main.log for details
    pause
    goto menu
)
echo Main service started successfully.

:: Start Workers
echo Starting worker services...
for /L %%i in (1,1,%worker_count%) do (
    set /a port=%WORKER_START_PORT% + %%i - 1
    echo Starting worker %%i on port !port!...
    start /B "" "%BUILD_DIR%\worker.exe" --port !port! --db "search_engine.db" --registry %REGISTRY_ADDRESS% > "%LOG_DIR%\worker_%%i.log" 2>&1
    timeout /t 5 >nul
    
    :: Check if worker started successfully
    netstat -an | find ":!port!" >nul
    if errorlevel 1 (
        echo Error: Worker %%i failed to start
        echo Check %LOG_DIR%\worker_%%i.log for details
        pause
        goto menu
    )
    echo Worker %%i started successfully.
)

echo.
echo All services started successfully!
echo http://localhost:8080/
echo.
pause
goto menu

:end
exit /b 0 