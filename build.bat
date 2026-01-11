REM CXA Build Script for Windows
REM This script builds all CXA components for Windows distribution

@echo off
setlocal enabledelayedexpansion

echo ==========================================
echo CXA Cryptographic System - Windows Build
echo ==========================================

set "RED=[0;31m"
set "GREEN=[0;32m"
set "YELLOW=[1;33m"
set "NC=[0m"

set BUILD_GO=true
set BUILD_RUST=true

REM Check prerequisites
echo [BUILD] Checking prerequisites...

REM Check Rust
where rustc >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Rust not found. Please install Rust 1.70 or later.
    exit /b 1
)

REM Check Go
where go >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Go not found. Skipping Go service build.
    set BUILD_GO=false
)

REM Check Python
where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.10 or later.
    exit /b 1
)

echo [BUILD] Prerequisites check complete.

REM Build Rust core modules
if "%BUILD_RUST%"=="true" (
    echo [BUILD] Building Rust core modules...
    cd rust-core
    cargo clean
    cargo build --release
    cd ..
    
    if exist "rust-core\target\release" (
        echo [BUILD] Rust build complete.
    ) else (
        echo [ERROR] Rust build failed.
        exit /b 1
    )
)

REM Build Go services
if "%BUILD_GO%"=="true" (
    echo [BUILD] Building Go services...
    cd go-services
    
    echo [BUILD] Building API server...
    CGO_ENABLED=0 GOOS=windows go build -o bin/api-server.exe .\api-server
    
    echo [BUILD] Building event monitor...
    CGO_ENABLED=0 GOOS=windows go build -o bin/event-monitor.exe .\event-monitor
    
    if exist "bin" (
        echo [BUILD] Go build complete.
    ) else (
        echo [ERROR] Go build failed.
        exit /b 1
    )
    
    cd ..
)

REM Build Python package
echo [BUILD] Building Python package...
cd python-core
python -m pip install --upgrade pip setuptools wheel
python setup.py sdist bdist_wheel
cd ..

REM Create distribution package
echo [BUILD] Creating distribution package...

set "DIST_DIR=dist"
if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"

set "PACKAGE_NAME=cxa-windows-x86_64-%date:~-4,4%%date:~-10,2%%date:~-7,2%-%time:~0,2%%time:~3,2%"
set "PACKAGE_NAME=%PACKAGE_NAME: =0%"
set "PKG_DIR=%DIST_DIR%\%PACKAGE_NAME%"
mkdir "%PKG_DIR%"

REM Copy Rust binaries
if exist "rust-core\target\release\*.dll" copy "rust-core\target\release\*.dll" "%PKG_DIR%" >nul

REM Copy Go binaries
if exist "go-services\bin" (
    mkdir "%PKG_DIR%\bin"
    copy "go-services\bin\*.exe" "%PKG_DIR%\bin\" >nul
)

REM Copy Python package
mkdir "%PKG_DIR%\python"
if exist "python-core\dist" copy "python-core\dist\*" "%PKG_DIR%\python\" >nul

REM Copy configuration
copy "config\default.yml" "%PKG_DIR%\" >nul

REM Copy documentation
mkdir "%PKG_DIR%\docs"
copy "README.md" "%PKG_DIR%\" >nul
xcopy "docs\*" "%PKG_DIR%\docs\" /E /I /Q >nul

REM Create archive
echo [BUILD] Creating archive...
powershell -Command "Compress-Archive -Path '%PKG_DIR%\*' -DestinationPath '%DIST_DIR%\%PACKAGE_NAME%.zip' -Force"
rmdir /s /q "%PKG_DIR%"

echo [BUILD] Distribution created: %DIST_DIR%\%PACKAGE_NAME%.zip

endlocal
exit /b 0
