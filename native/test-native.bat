@echo off
setlocal

set SCRIPT_DIR=%~dp0
if "%SCRIPT_DIR:~-1%"=="\" set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%

set JDK=
if defined JAVA_HOME set JDK=%JAVA_HOME%
if "%JDK%"=="" if exist "C:\Program Files\Java\jdk-21" set JDK=C:\Program Files\Java\jdk-21
if "%JDK%"=="" if exist "D:\jdk\jdk-17.0.5" set JDK=D:\jdk\jdk-17.0.5
if "%JDK%"=="" if exist "D:\jdk\jdk-8u291" set JDK=D:\jdk\jdk-8u291

set GCC=
where gcc >nul 2>&1 && set GCC=gcc
if "%GCC%"=="" if exist "C:\msys64\mingw64\bin\gcc.exe" set GCC=C:\msys64\mingw64\bin\gcc.exe
if "%GCC%"=="" if exist "C:\msys64\ucrt64\bin\gcc.exe" set GCC=C:\msys64\ucrt64\bin\gcc.exe
if "%GCC%"=="" if exist "C:\MinGW\bin\gcc.exe" set GCC=C:\MinGW\bin\gcc.exe
if "%GCC%"=="" if exist "C:\mingw64\bin\gcc.exe" set GCC=C:\mingw64\bin\gcc.exe
if "%GCC%"=="" if exist "E:\mingw64\bin\gcc.exe" set GCC=E:\mingw64\bin\gcc.exe
if "%GCC%"=="" if exist "C:\TDM-GCC-64\bin\gcc.exe" set GCC=C:\TDM-GCC-64\bin\gcc.exe

if not exist "%JDK%\include\jni.h" (
    echo ERROR: JDK not found. Set JAVA_HOME.
    exit /b 1
)
if "%GCC%"=="" (
    echo ERROR: gcc not found.
    exit /b 1
)

set OUT_DIR=%SCRIPT_DIR%\..\target\native-tests
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

echo Building native Montgomery differential test ...
"%GCC%" -O3 -march=x86-64 -mtune=generic -funroll-loops -I"%JDK%\include" -I"%JDK%\include\win32" -o "%OUT_DIR%\native_mul_test.exe" "%SCRIPT_DIR%\native_mul_test.c"
if errorlevel 1 exit /b 1

"%OUT_DIR%\native_mul_test.exe" %*
exit /b %ERRORLEVEL%
