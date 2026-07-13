@echo off
REM Build sm3native.dll for Windows x64 with AVX2
REM Requires: MinGW-w64 gcc in PATH
REM JDK: auto-detect or set manually below

set SCRIPT_DIR=%~dp0
if "%SCRIPT_DIR:~-1%"=="\" set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%

set JDK=
if defined JAVA_HOME set JDK=%JAVA_HOME%
if "%JDK%"=="" if exist "D:\jdk\jdk-21.0.6" set JDK=D:\jdk\jdk-21.0.6
if "%JDK%"=="" if exist "D:\jdk\jdk-17.0.5" set JDK=D:\jdk\jdk-17.0.5
if "%JDK%"=="" if exist "D:\jdk\jdk-8u291" set JDK=D:\jdk\jdk-8u291
if "%JDK%"=="" for /f "delims=" %%i in ('where java 2^>nul') do set JDK=%%~dpi..

set INC=%JDK%\include
set INC_WIN=%JDK%\include\win32

set SRC=%SCRIPT_DIR%\sm3_native.c
set OUT=%SCRIPT_DIR%\..\src\main\resources\native\win-x86_64\sm3native.dll

if not exist "%INC%\jni.h" (
    echo ERROR: JDK not found. Set JAVA_HOME or edit this script.
    echo Tried: %JDK%
    exit /b 1
)

set GCC=
where gcc >nul 2>&1 && set GCC=gcc
if "%GCC%"=="" if exist "C:\msys64\mingw64\bin\gcc.exe" set GCC=C:\msys64\mingw64\bin\gcc.exe
if "%GCC%"=="" if exist "C:\msys64\ucrt64\bin\gcc.exe" set GCC=C:\msys64\ucrt64\bin\gcc.exe
if "%GCC%"=="" if exist "C:\MinGW\bin\gcc.exe" set GCC=C:\MinGW\bin\gcc.exe
if "%GCC%"=="" if exist "C:\mingw64\bin\gcc.exe" set GCC=C:\mingw64\bin\gcc.exe
if "%GCC%"=="" if exist "E:\mingw64\bin\gcc.exe" set GCC=E:\mingw64\bin\gcc.exe
if "%GCC%"=="" if exist "C:\TDM-GCC-64\bin\gcc.exe" set GCC=C:\TDM-GCC-64\bin\gcc.exe
if "%GCC%"=="" (
    echo ERROR: gcc not found. Install MinGW-w64: msys2 -^> pacman -S mingw-w64-x86_64-gcc
    exit /b 1
)

mkdir "%SCRIPT_DIR%\..\src\main\resources\native\win-x86_64" 2>nul

echo Using GCC: %GCC%
echo Using JDK: %JDK%
echo Building %OUT% (C + AVX2 SIMD) ...
"%GCC%" -shared -O3 -fPIC -mavx2 -mtune=generic -funroll-loops -flto -I"%INC%" -I"%INC_WIN%" -o "%OUT%" "%SRC%"

if %ERRORLEVEL% neq 0 (
    echo Build failed.
    exit /b 1
)

echo Build OK: %OUT%
