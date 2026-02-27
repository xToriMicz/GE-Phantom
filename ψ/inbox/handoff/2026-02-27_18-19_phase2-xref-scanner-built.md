# Handoff: Phase 2 — IES Property Scanner Built & Pushed

**Date**: 2026-02-27 18:19 ICT
**Context**: ~40%

## What We Did
- Implemented full Phase 2 plan: xref scanner + property callers + command interface
- Updated `phantom_hook.h` — added command shmem layout (256 bytes), command codes (PING/SCAN/GET_PROP/SET_PROP/READ_ADDR), function typedefs for tolua++ GetPropertyNumber/SetPropertyNumber
- Updated `phantom_hook.c` (~450 lines added):
  - `scan_xrefs()` — brute-force .text scan for 4-byte LE patterns of target string addresses, logs instruction type + 16-byte context + adjacent PUSH/CALL analysis
  - `call_get_property()` / `call_set_property()` — SEH-wrapped function callers
  - Command handler with 50ms poll thread
  - DllMain runs xref scan on DLL_PROCESS_ATTACH
- Updated `dll_injector.py` — added `launch` command (CreateProcess SUSPENDED → inject → ResumeThread)
- Created `range_control.py` — interactive Python controller (ping/scan/get/set/read/probe)
- Built DLL successfully (107,520 bytes, only C4996 warnings)
- Committed and pushed: `6290fdf`

## Pending
- [ ] Actually run `launch` command against ge.exe and check phantom_hook.log for xref results
- [ ] Analyze xref output to identify real GetPropertyNumber/SetPropertyNumber function addresses
- [ ] Determine correct function signatures from disassembly context around xrefs
- [ ] Figure out idSpace and objName parameters (need to observe how game calls these functions)
- [ ] Test `range_control.py ping` to verify shared memory communication works
- [ ] Test property reading/writing once function addresses are resolved
- [ ] Untracked files in repo: data/*.json, src/bot/*.py, various tools — may want to .gitignore or commit

## Next Session
- [ ] Run `python tools/dll_injector.py launch --exe "C:\Granado Espada\ge.exe"` and collect log
- [ ] Parse xref scan results from phantom_hook.log
- [ ] Identify tolua++ registration pattern: `push string_addr → push func_ptr → call register`
- [ ] Set resolved addresses in range_control.py and test GetPropertyNumber
- [ ] If function signature is wrong (crash), adjust typedefs and rebuild
- [ ] If property read works, test SetPropertyNumber to modify range in-game

## Key Files
- `tools/phantom_hook/phantom_hook.c` — DLL with xref scanner + command handler
- `tools/phantom_hook/phantom_hook.h` — shared constants + shmem layout
- `tools/dll_injector.py` — inject/launch/eject commands
- `tools/range_control.py` — Python controller for Phase 2 commands
- `tools/phantom_hook/phantom_hook.log` — will contain xref scan results after launch

## Risks
- C2S encrypted (Phase 1 finding) — can't packet-sniff property changes
- Function signature guesses (cdecl, 3-4 params) may be wrong → crash
- Server may validate range server-side → client-only change has no effect
- tolua++ registration pattern may differ from expected PUSH/PUSH/CALL
