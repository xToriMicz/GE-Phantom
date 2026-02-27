@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86
cd /d D:\Project\GE_Phantom\tools\phantom_hook
echo [*] Building phantom_hook_v8.dll (Phase 5: Investigation + UpdateItemTable)...
echo     New commands: CMD_DUMP_MEM, CMD_SCAN_XREF_STR, CMD_UPDATE_ITEM_TABLE
echo     Chat safety guard: requires param1=0xCAFE
cl /nologo /LD /O2 /W3 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_USRDLL" /D "_CRT_SECURE_NO_WARNINGS" phantom_hook.c /link /DLL /OUT:phantom_hook_v8.dll ws2_32.lib user32.lib kernel32.lib
if errorlevel 1 (
    echo [ERROR] Build failed!
    exit /b 1
)
if exist phantom_hook.obj del phantom_hook.obj
if exist phantom_hook.exp del phantom_hook.exp
echo [OK] Built phantom_hook_v8.dll
