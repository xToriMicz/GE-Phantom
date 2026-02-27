/**
 * phantom_hook.h — Shared constants for GE_Phantom DLL hook
 *
 * Used by both the C DLL and referenced from Python packet logger.
 * Phase 1: IAT hooks for send/recv packet capture
 * Phase 2: IES property scanner + range modifier
 */

#ifndef PHANTOM_HOOK_H
#define PHANTOM_HOOK_H

/* Named pipe for packet streaming to Python reader */
#define GE_PIPE_NAME    "\\\\.\\pipe\\ge_phantom"

/* Shared memory name for control flags */
#define GE_SHMEM_NAME   "Local\\ge_phantom_ctl"

/* Shared memory name for Phase 2 command interface */
#define GE_SHMEM_CMD_NAME   "Local\\ge_phantom_cmd"

/* Packet direction markers */
#define DIR_C2S         0x01   /* Client → Server (send) */
#define DIR_S2C         0x02   /* Server → Client (recv) */

/* Control flags in shared memory byte[0] */
#define CTL_HOOK_ACTIVE     0x01   /* Master on/off */
#define CTL_LOG_SEND        0x02   /* Log send() packets */
#define CTL_LOG_RECV        0x04   /* Log recv() packets */
#define CTL_LOG_ALL         (CTL_LOG_SEND | CTL_LOG_RECV)
#define CTL_DEFAULT         (CTL_HOOK_ACTIVE | CTL_LOG_ALL)

/* Pipe message header (8 bytes) */
/* Layout: [direction:1][padding:1][length:2][timestamp:4] then [payload:length] */
#define PIPE_HEADER_SIZE    8

/* Max packet size we'll log (anything larger gets truncated) */
#define MAX_PACKET_LOG      65536

/* ─── GE Static Addresses (no ASLR, image base 0x00400000) ──── */

#define GE_IMAGE_BASE           0x00400000
#define GE_TEXT_START            0x00401000
#define GE_TEXT_END              0x00B6B000   /* approximate .text end */
#define GE_RDATA_BASE           0x00B6B000

/* Known string addresses in .rdata (verified via runtime memory scan) */
#define GE_STR_SET_PROP_NUM     0x00BAF04C   /* "SetPropertyNumber" */
#define GE_STR_GET_PROP_NUM     0x00BE30C8   /* "GetPropertyNumber" */
#define GE_STR_SPL_RANGE        0x00B9BD64   /* "SplRange" */
#define GE_STR_KEEP_RANGE       0x00B82770   /* "KeepRange" */

/* Resolved function addresses (underlying C++ functions, NOT tolua wrappers) */
/* tolua wrappers: Get=0x008ABD73, Set=0x006C6449 — these take lua_State*, don't call directly */
#define GE_FUNC_GET_PROP_NUM    0x0089D5FC   /* GetPropertyNumber: double __cdecl (objName, idSpace, propName) */
#define GE_FUNC_SET_PROP_NUM    0x005C62A2   /* SetPropertyNumber: void __cdecl (objName, idSpace, propName, value) */
#define GE_FUNC_CHAT_INTERNAL   0x004FAB43   /* void __cdecl (const char*) — Chat: sends to server + local */
#define GE_FUNC_SYSMSG_INTERNAL 0x0050C6FC   /* void __cdecl (const char*) — SysMsg: local system message */

/* ─── Phase 2: Command Interface ─────────────────────────────── */

/*
 * Shared memory layout for command interface (256 bytes):
 *
 * Offset  Size  Field
 * ------  ----  -----
 * 0x00    1     command    (Python writes, DLL reads & clears)
 * 0x01    1     status     (DLL writes: 0=idle, 1=busy, 2=done, 0xFF=error)
 * 0x02    2     reserved
 * 0x04    4     param1     (command-specific parameter)
 * 0x08    4     param2     (command-specific parameter)
 * 0x0C    4     result_i32 (integer result from DLL)
 * 0x10    4     result_f32 (float result from DLL)  — alias: same as double low bits
 * 0x14    8     result_f64 (double result from DLL)
 * 0x1C    4     reserved
 * 0x20    64    str_param  (null-terminated string parameter, e.g. property name)
 * 0x60    64    str_param2 (null-terminated string parameter, e.g. object name)
 * 0xA0    96    str_result (null-terminated result string from DLL)
 */

#define CMD_SHMEM_SIZE          256

/* Offsets into shared memory */
#define CMD_OFF_COMMAND         0x00
#define CMD_OFF_STATUS          0x01
#define CMD_OFF_PARAM1          0x04
#define CMD_OFF_PARAM2          0x08
#define CMD_OFF_RESULT_I32      0x0C
#define CMD_OFF_RESULT_F32      0x10
#define CMD_OFF_RESULT_F64      0x14
#define CMD_OFF_STR_PARAM       0x20
#define CMD_OFF_STR_PARAM2      0x60
#define CMD_OFF_STR_RESULT      0xA0

/* Command codes (written by Python to offset 0x00) */
#define CMD_NOP                 0x00   /* No command / idle */
#define CMD_SCAN                0x01   /* Trigger xref scan → results in log */
#define CMD_GET_PROP            0x02   /* GetPropertyNumber(param1=idSpace, str=propName) */
#define CMD_SET_PROP            0x03   /* SetPropertyNumber(param1=idSpace, str=propName, f64=value) */
#define CMD_READ_ADDR           0x10   /* Read 4 bytes from param1 address → result_i32 */
#define CMD_SET_FUNC_ADDR       0x11   /* Set function addr: param1=addr, param2=0=get/1=set/2=update */
#define CMD_FIND_STRING         0x12   /* Find string in .rdata: str_param=needle → result_i32=addr */
#define CMD_HOOK_GETPROP        0x20   /* Install logging hook on GetPropertyNumber */
#define CMD_UNHOOK_GETPROP      0x21   /* Remove logging hook */
#define CMD_HOOK_SETPROP        0x22   /* Install logging hook on SetPropertyNumber */
#define CMD_UNHOOK_SETPROP      0x23   /* Remove logging hook */
#define CMD_VTABLE_SPY          0x30   /* One-shot vtable spy → captures obj, vtable, fn addrs */
#define CMD_HOOK_VTABLE_GET     0x31   /* Persistent hook on vtable GET at KeepRange call site */
#define CMD_UNHOOK_VTABLE_GET   0x32   /* Remove vtable GET hook */
#define CMD_SET_VTGET_OVERRIDE  0x33   /* Set override value for vtable GET (f64), param1=0 off/1 on */
#define CMD_VTGET_STATUS        0x34   /* Read hook stats → result_i32=count, f64=last_value, str=info */
#define CMD_CHAT                0x40   /* Chat(str_param) → sends to server + local display */
                                       /* ⚠ UNSAFE: causes server disconnect! Requires param1=0xCAFE to confirm */
#define CMD_SYSMSG              0x41   /* SysMsg(str_param) → local system message display */
#define CMD_UPDATE_ITEM_TABLE   0x42   /* UpdateItemTable() → flush IES cache (main thread) */
#define CMD_SEND_KEY            0x43   /* SendKey: param1=VK code, param2=flags (0=tap,1=down,2=up) */
#define CMD_SEND_KEYS           0x44   /* SendKeys: str_param=key sequence, param1=delay_ms between keys */
#define CMD_DUMP_MEM            0x50   /* Dump N bytes: param1=addr, param2=count(max 96) → str_result as hex */
#define CMD_SCAN_XREF_STR      0x51   /* Find string in .rdata, then scan .text for xrefs → str_result */
#define CMD_PING                0xFE   /* Ping → status=done, result_i32=0xDEADBEEF */

/* Status codes (written by DLL to offset 0x01) */
#define CMD_STATUS_IDLE         0x00
#define CMD_STATUS_BUSY         0x01
#define CMD_STATUS_DONE         0x02
#define CMD_STATUS_ERROR        0xFF

/* ─── Xref Scan Targets ──────────────────────────────────────── */

/* Number of cross-reference targets to scan for */
#define XREF_TARGET_COUNT       4

/* x86 instruction patterns that reference an immediate address:
 * - 68 XX XX XX XX          PUSH imm32
 * - B8-BF XX XX XX XX       MOV reg, imm32
 * - 8D 05 XX XX XX XX       LEA EAX, [imm32]  (and other /r variants)
 * - C7 .. XX XX XX XX       MOV [mem], imm32
 *
 * For initial scan, we just look for the 4-byte LE address anywhere
 * in .text, then decode context around each hit.
 */

/* ─── Property Function Typedefs ─────────────────────────────── */

/*
 * Actual C++ function signatures (determined from disassembly of tolua++ wrappers):
 *
 * GetPropertyNumber at 0x0089D5FC:
 *   Called from tolua wrapper at 0x008ABD73 with: PUSH propName, PUSH idSpace, PUSH objName
 *   Returns double via FPU ST(0) register
 *
 * SetPropertyNumber at 0x005C62A2:
 *   Called from tolua wrapper at 0x006C6449
 *   Takes objName, idSpace, propName, double value
 *
 * The tolua wrappers themselves (0x006C6449, 0x008ABD73) take lua_State* —
 * we call the underlying C++ functions directly instead.
 */
typedef double (__cdecl *fn_GetPropertyNumber)(const char *objName, int idSpace, const char *propName);
typedef void   (__cdecl *fn_SetPropertyNumber)(const char *objName, int idSpace, const char *propName, double value);
typedef void   (__cdecl *fn_ChatInternal)(const char *text);
typedef void   (__cdecl *fn_SysMsgInternal)(const char *text);
typedef void   (__cdecl *fn_UpdateItemTable)(void);

/* ─── Phase 3: VTable Call Sites (from xref scan) ────────── */

/*
 * KeepRange GET call site at 0x004FEA4B (xref #1):
 *
 *   004FEA4A: 50              push eax              ; &[ebp-4]
 *   004FEA4B: 68 70 27 B8 00  push "KeepRange"      ← SPY HOOK (5 bytes)
 *   004FEA50: 8B 3E           mov edi, [esi]        ; vtable
 *   004FEA52: E8 xx xx xx xx  call resolve_string
 *   004FEA57: 50              push eax              ; prop_id
 *   004FEA58: 8B CE           mov ecx, esi          ← GET HOOK (5 bytes)
 *   004FEA5A: FF 57 10        call [edi+0x10]       ; vtable GET
 *   004FEA5D: 8B 45 FC        mov eax, [ebp-4]      ; continue
 *
 * ESI = character object, EDI = vtable ptr (after 004FEA50)
 */
#define GE_KEEPRANGE_SPY_SITE    0x004FEA4B   /* push "KeepRange" — 5 bytes, spy target (xref #1, getter) */
#define GE_KEEPRANGE_SPY_RESUME  0x004FEA50   /* instruction after push */
#define GE_KEEPRANGE_GET_SITE    0x004FEA58   /* mov ecx,esi; call [edi+0x10] — 5 bytes */
#define GE_KEEPRANGE_GET_RESUME  0x004FEA5D   /* instruction after vtable call */

/*
 * KeepRange SET call site at 0x0050A942 (xref #2):
 *
 *   0050A933: 0F E6 C0        cvtdq2pd xmm0, xmm0   ; int → double
 *   0050A936: 51              push ecx               ; \
 *   0050A937: 51              push ecx               ; / reserve 8 bytes for double
 *   0050A938: 8B 3E           mov edi, [esi]         ; vtable (loaded BEFORE push!)
 *   0050A93A: 8D 4D FC        lea ecx, [ebp-4]
 *   0050A93D: F2 0F 11 04 24  movsd [esp], xmm0      ; store double value on stack
 *   0050A942: 68 70 27 B8 00  push "KeepRange"       ← SPY HOOK (5 bytes)
 *   0050A947: E8 A6 D0 0D 00  call resolve_string
 *   0050A94C: 50              push eax               ; prop_id
 *   0050A94D: 8B CE           mov ecx, esi           ; this
 *   0050A94F: FF 57 28        call [edi+0x28]        ; vtable SET (offset 0x28, not 0x10!)
 *   0050A952: 5F 5E C9 C3    pop edi; pop esi; leave; ret
 *
 * Key differences from xref #1:
 *   - EDI = vtable is ALREADY loaded (before the push)
 *   - Double value lives on stack at [ESP] (the value being SET)
 *   - Uses vtable[0x28] (setter) not vtable[0x10] (getter)
 */
#define GE_KEEPRANGE_SET_SITE    0x0050A942   /* push "KeepRange" — 5 bytes, xref #2 (setter) */
#define GE_KEEPRANGE_SET_RESUME  0x0050A947   /* instruction after push */

/* Known property names to probe */
#define PROP_SPL_RANGE      "SplRange"
#define PROP_KEEP_RANGE     "KeepRange"
#define PROP_VIEW_RANGE     "ViewRange"
#define PROP_AI_RANGE       "AiRange"
#define PROP_MAX_LINK_RANGE "MaxLinkRange"

#endif /* PHANTOM_HOOK_H */
