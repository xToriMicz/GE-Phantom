# Handoff: SysMsg Working, Chat Needs Investigation

**Date**: 2026-02-27 23:50
**Context**: ~60%

## What We Did
- Added CMD_CHAT (0x40) and CMD_SYSMSG (0x41) to phantom_hook DLL
- Both commands defer to main game thread (same pattern as GET_PROP/SET_PROP)
- Fixed 3 bugs during debugging:
  1. **SysMsg address off-by-4**: `0x0050C6F8` was epilogue of previous function, corrected to `0x0050C6FC` (verified via byte dump: `55 8B EC` = valid prologue)
  2. **detour hooks missing main-thread exec**: `detour_send`/`detour_recv` never called `try_execute_mainthread_cmd()` — IAT hooks fail on this ge.exe so detour is always used
  3. **Race condition**: poll thread kept re-deferring commands and overwriting DONE status with BUSY. Fixed with reentrancy guard (`InterlockedCompareExchange`) + early command claim
- **SysMsg confirmed working in-game**: `[23:46] Hello from phantom!` displayed in chat window
- **Chat causes disconnect**: function at `0x004FAB43` returns OK but server disconnects immediately after — likely wrong parameters or packet format

## Pending
- [ ] Investigate Chat function parameters (prologue `55 8B EC 6A 00 6A 00 FF` suggests more params than just `const char*`)
- [ ] Chat address `0x004FAB43` has valid prologue but may need channel/type args or be __thiscall
- [ ] Consider disabling Chat command until parameters are understood
- [ ] build_v7.bat still points to v7d.dll (artifact of iterative debugging) — clean up

## Next Session
- [ ] Disassemble Chat function at `0x004FAB43` to understand full signature (push 0, push 0 before call suggests 3+ params)
- [ ] Look at how AIgeHS script engine calls Chat() — may pass additional context
- [ ] Try SysMsg for practical use cases (debug overlay, status messages during property manipulation)
- [ ] Investigate UpdateItemTable — the real target for property manipulation (per AIgeHS breakthrough)

## Key Files
- `tools/phantom_hook/phantom_hook.h` — CMD_CHAT/CMD_SYSMSG defines, function addresses
- `tools/phantom_hook/phantom_hook.c` — main-thread handlers, detour fix, reentrancy guard
- `tools/range_control.py` — Python chat/sysmsg commands
- `tools/phantom_hook/phantom_hook_v7d.dll` — working build (SysMsg confirmed)
- `tools/phantom_hook/phantom_hook_v7d.log` — log with successful SysMsg call

## Key Discoveries
- **IAT hooks always fail** on this ge.exe → detour hooks used → any main-thread code MUST also be in detour_send/detour_recv
- **Function address verification**: dump first 8 bytes at address — `55 8B EC` = valid function start, anything else (like `5F 5E C9 C3`) = epilogue/wrong offset
- **SysMsg is local-only** (safe to call), Chat sends to server (dangerous — can cause disconnect)
