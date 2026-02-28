@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86 >nul 2>nul
cd /d D:\Project\GE_Phantom\tools\phantom_hook
echo [*] Building phantom_hook.dll (32-bit)...
cl /nologo /LD /O2 /W3 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_USRDLL" phantom_hook.c /link /DLL /OUT:phantom_hook.dll ws2_32.lib user32.lib kernel32.lib ole32.lib
if errorlevel 1 (
    echo [ERROR] Build failed!
    exit /b 1
)
if exist phantom_hook.obj del phantom_hook.obj
if exist phantom_hook.exp del phantom_hook.exp
echo [OK] Built phantom_hook.dll
