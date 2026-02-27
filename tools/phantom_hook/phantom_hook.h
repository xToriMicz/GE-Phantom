/**
 * phantom_hook.h — Shared constants for GE_Phantom DLL hook
 *
 * Used by both the C DLL and referenced from Python packet logger.
 */

#ifndef PHANTOM_HOOK_H
#define PHANTOM_HOOK_H

/* Named pipe for packet streaming to Python reader */
#define GE_PIPE_NAME    "\\\\.\\pipe\\ge_phantom"

/* Shared memory name for control flags */
#define GE_SHMEM_NAME   "Local\\ge_phantom_ctl"

/* Packet direction markers */
#define DIR_C2S         0x01   /* Client → Server (send) */
#define DIR_S2C         0x02   /* Server → Client (recv) */

/* Control flags in shared memory */
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

/* GE Static addresses (no ASLR, image base 0x00400000) */
#define GE_IMAGE_BASE           0x00400000
#define GE_RDATA_BASE           0x00B6B000
#define GE_STR_SET_PROP_NUM     0x00BAD84C   /* "SetPropertyNumber" */
#define GE_STR_GET_PROP_NUM     0x00BE18C8   /* "GetPropertyNumber" */
#define GE_STR_SPL_RANGE        0x00B9A564   /* "SplRange" */
#define GE_STR_KEEP_RANGE       0x00B80F70   /* "KeepRange" */

#endif /* PHANTOM_HOOK_H */
