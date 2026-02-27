# Handoff: VTable Spy Built — Call Site Never Fires During Gameplay

**Date**: 2026-02-27 21:07 ICT
**Context**: ~70%

## What We Did

### 1. Built Phase 3: VTable Spy + GET Hook (phantom_hook_v5.dll)
- Added `CMD_VTABLE_SPY` (0x30) — one-shot naked asm code cave at KeepRange GET site (0x004FEA4B)
  - Replaces `push "KeepRange"` (5 bytes) with JMP to cave
  - Cave captures ESI (object ptr), reads vtable, extracts vtable[0x10] (getter) and vtable[0x28] (setter)
  - Uses pushad/pushfd for safe register preservation
  - Auto-removes after capture
- Added `CMD_HOOK_VTABLE_GET` (0x31) — persistent hook at 0x004FEA58 (mov ecx,esi; call [edi+0x10])
  - Intercepts vtable GET return value from FPU ST(0)
  - Optional value override via `CMD_SET_VTGET_OVERRIDE` (0x33)
  - Stats via `CMD_VTGET_STATUS` (0x34)
- Updated range_control.py with new interactive commands: spy, hookvt, unhookvt, override, nooverride, vtstatus
- Built and pushed: `10c4f50`

### 2. Live Testing — THE WALL
- Injected v5 into running ge.exe (PID 55072)
- Ping works, DLL responsive
- **VTable spy got 0 triggers in 3 attempts (30s each)** even while user was actively fighting monsters
- The KeepRange GET call site at 0x004FEA4B **NEVER fires during normal gameplay**
- Tried map warp — still 0 triggers

### 3. Discovery: Property Descriptors Are String Lists
- Read memory at SplRange registration ECX addresses (0x00D1EBF8 etc.)
- They contain **property NAME STRINGS** (e.g., "SplRange", "SkillResult", "arg1"), not objects
- The registration pattern stores property name pointers in class template tables

### 4. Lua API Probing — Returns Garbage
- GetPropertyNumber returns `2.225e-308` (DBL_MIN sentinel) for ALL property/idSpace combos
- The function doesn't work with arbitrary parameters — needs specific internal state

## Key Insight

**The game reads KeepRange from the property system ONCE at character load time, then caches the value in the C++ object's member variable.** During gameplay/combat, it reads from the cached member, never from the property system. All 3 KeepRange xrefs are initialization-only code paths.

## Pending
- [ ] VTable spy/hook code is ready but call site doesn't fire during gameplay
- [ ] Need a different approach to find the cached range value in the character object
- [ ] Untracked files in repo (data/*.json, tools/*.py, old DLLs)

## Next Session — 3 Options

### Option A: Hook String Resolver (0x005E79F2)
- Add `CMD_HOOK_RESOLVER` to DLL — hook the string resolver function
- Filter for "KeepRange"/"SplRange" strings to find ALL call sites that access range properties
- Discover which code paths fire during character initialization
- This reveals the vtable + object pointer at the moment the value is read

### Option B: Memory Scan for Cached Float
- Use Python memory scanner (src/bot/memory.py + range_modifier.py)
- Need to know approximate range value (depends on character weapon type)
- Scan for that float in process memory, narrow down with value changes
- Previous finding: attack_range is server-authoritative (client modification has no effect on hit validation)

### Option C: Force Character Reload
- Find a reliable way to trigger character re-initialization WITHOUT map change
- Maybe: re-equip weapon, use a skill that modifies range, change stance
- Then the spy at 0x004FEA4B would fire and capture the vtable

### Recommended: Option A first
- Hook the resolver at 0x005E79F2 (it's the chokepoint for ALL property accesses)
- Log all property name resolutions to understand what the game reads during combat
- Filter for range-related properties to find the actual code paths
- This gives us ground truth about the property system's runtime behavior

## Key Files
- `tools/phantom_hook/phantom_hook.c` — DLL with Phase 3 vtable spy + hook (~1500 lines)
- `tools/phantom_hook/phantom_hook.h` — shared constants + call site addresses
- `tools/phantom_hook/phantom_hook_v5.dll` — built DLL (115KB)
- `tools/phantom_hook/phantom_hook_v5.log` — runtime log showing 0 triggers
- `tools/range_control.py` — Python controller with spy/hookvt/override commands
- `tools/phantom_hook/build_v5.bat` — build script

## Risks
- Resolver hook (0x005E79F2) is called for EVERY property access — could be very noisy
- Need to understand resolver's calling convention (thiscall? variable params across call sites?)
- Server-side validation may make client range modification useless even if we find the cached value
- The property system architecture (read-once, cache forever) means the vtable hook approach may not be useful for live modification
