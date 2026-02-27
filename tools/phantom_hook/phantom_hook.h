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

/* Known string addresses in .rdata */
#define GE_STR_SET_PROP_NUM     0x00BAD84C   /* "SetPropertyNumber" */
#define GE_STR_GET_PROP_NUM     0x00BE18C8   /* "GetPropertyNumber" */
#define GE_STR_SPL_RANGE        0x00B9A564   /* "SplRange" */
#define GE_STR_KEEP_RANGE       0x00B80F70   /* "KeepRange" */

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
 * tolua++ registered functions typically use lua_State* as first param.
 * But the actual C++ functions behind them may have signatures like:
 *
 *   double GetPropertyNumber(int idSpace, const char* objName, const char* propName);
 *   void   SetPropertyNumber(int idSpace, const char* objName, const char* propName, double value);
 *
 * We'll determine the exact signature from disassembly around xrefs.
 * These typedefs are initial guesses — may need adjustment after scan.
 */
typedef double (__cdecl *fn_GetPropertyNumber)(int idSpace, const char *objName, const char *propName);
typedef void   (__cdecl *fn_SetPropertyNumber)(int idSpace, const char *objName, const char *propName, double value);

/* Known property names to probe */
#define PROP_SPL_RANGE      "SplRange"
#define PROP_KEEP_RANGE     "KeepRange"
#define PROP_VIEW_RANGE     "ViewRange"
#define PROP_AI_RANGE       "AiRange"
#define PROP_MAX_LINK_RANGE "MaxLinkRange"

#endif /* PHANTOM_HOOK_H */
