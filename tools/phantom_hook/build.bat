@echo off
REM ──────────────────────────────────────────────────────
REM  phantom_hook build script
REM  Builds a 32-bit DLL for injection into ge.exe (32-bit PE)
REM ──────────────────────────────────────────────────────

setlocal

REM ── Locate MSVC ──
set "VCVARSALL=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"

if not exist "%VCVARSALL%" (
    echo [ERROR] vcvarsall.bat not found at:
    echo   %VCVARSALL%
    echo.
    echo Install Visual Studio 2019 Build Tools or update the path.
    exit /b 1
)

REM ── Set up x86 environment ──
echo [*] Setting up MSVC x86 environment...
call "%VCVARSALL%" x86 >nul 2>nul

if errorlevel 1 (
    echo [ERROR] Failed to initialize MSVC x86 environment
    exit /b 1
)

REM ── Build DLL ──
echo [*] Compiling phantom_hook.dll (32-bit)...

cl /nologo /LD /O2 /W3 ^
    /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_USRDLL" ^
    phantom_hook.c ^
    /link /DLL /OUT:phantom_hook.dll ^
    ws2_32.lib user32.lib kernel32.lib

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed!
    exit /b 1
)

REM ── Clean up intermediate files ──
if exist phantom_hook.obj del phantom_hook.obj
if exist phantom_hook.exp del phantom_hook.exp

echo.
echo [OK] Built: phantom_hook.dll
echo [OK] Import lib: phantom_hook.lib
echo.
echo Usage:
echo   python ../dll_injector.py inject --dll phantom_hook.dll

endlocal
