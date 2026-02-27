/**
 * phantom_hook.c — GE_Phantom Reconnaissance DLL (Phase 1)
 *
 * IAT-hooks send() and recv() in ge.exe to capture plaintext packets
 * before encryption (C2S) and after decryption (S2C).
 *
 * Communication: Named pipe \\.\pipe\ge_phantom streams packets to
 * an external Python reader (packet_logger.py).
 *
 * Build (32-bit, from VS x86 command prompt):
 *   cl /LD /O2 phantom_hook.c ws2_32.lib user32.lib
 *
 * Or use build.bat which sets up the environment automatically.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#include "phantom_hook.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")

/* ─── Globals ─────────────────────────────────────────────────── */

/* Original function pointers */
static int (WSAAPI *g_orig_send)(SOCKET, const char*, int, int) = NULL;
static int (WSAAPI *g_orig_recv)(SOCKET, char*, int, int) = NULL;

/* Named pipe handle for streaming to Python */
static HANDLE g_pipe = INVALID_HANDLE_VALUE;

/* Shared memory for control flags */
static HANDLE  g_shmem_handle = NULL;
static volatile BYTE *g_ctl = NULL;

/* Statistics */
static volatile LONG g_send_count = 0;
static volatile LONG g_recv_count = 0;

/* Critical section for pipe writes (send/recv may be on different threads) */
static CRITICAL_SECTION g_pipe_lock;

/* ─── Pipe Communication ──────────────────────────────────────── */

/**
 * Create named pipe server. The Python logger connects as a client.
 * If the pipe already exists (previous inject), we connect to the existing one.
 */
static void pipe_init(void)
{
    g_pipe = CreateNamedPipeA(
        GE_PIPE_NAME,
        PIPE_ACCESS_OUTBOUND,           /* DLL writes, Python reads */
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1,                              /* Single instance */
        MAX_PACKET_LOG + PIPE_HEADER_SIZE,  /* Out buffer */
        0,                              /* In buffer (not used) */
        0,                              /* Default timeout */
        NULL                            /* Default security */
    );

    if (g_pipe == INVALID_HANDLE_VALUE) {
        /* Pipe might already exist from a previous injection — try as client */
        g_pipe = CreateFileA(
            GE_PIPE_NAME,
            GENERIC_WRITE,
            0, NULL,
            OPEN_EXISTING,
            0, NULL
        );
    }
}

/**
 * Write a packet to the named pipe with header.
 * Format: [dir:1][pad:1][len:2][tick:4][payload:len]
 */
static void pipe_write_packet(BYTE direction, const char *buf, int len)
{
    DWORD written;
    BYTE header[PIPE_HEADER_SIZE];
    int log_len;

    if (g_pipe == INVALID_HANDLE_VALUE)
        return;

    /* Check if logging is enabled */
    if (g_ctl) {
        if (!(g_ctl[0] & CTL_HOOK_ACTIVE))
            return;
        if (direction == DIR_C2S && !(g_ctl[0] & CTL_LOG_SEND))
            return;
        if (direction == DIR_S2C && !(g_ctl[0] & CTL_LOG_RECV))
            return;
    }

    /* Clamp packet size */
    log_len = (len > MAX_PACKET_LOG) ? MAX_PACKET_LOG : len;
    if (log_len <= 0)
        return;

    /* Build header */
    header[0] = direction;
    header[1] = 0;  /* padding */
    header[2] = (BYTE)(log_len & 0xFF);
    header[3] = (BYTE)((log_len >> 8) & 0xFF);

    /* Timestamp: GetTickCount() gives ms since boot, good enough for ordering */
    {
        DWORD tick = GetTickCount();
        header[4] = (BYTE)(tick & 0xFF);
        header[5] = (BYTE)((tick >> 8) & 0xFF);
        header[6] = (BYTE)((tick >> 16) & 0xFF);
        header[7] = (BYTE)((tick >> 24) & 0xFF);
    }

    EnterCriticalSection(&g_pipe_lock);

    /* Write header + payload atomically */
    WriteFile(g_pipe, header, PIPE_HEADER_SIZE, &written, NULL);
    if (written == PIPE_HEADER_SIZE) {
        WriteFile(g_pipe, buf, log_len, &written, NULL);
    }

    LeaveCriticalSection(&g_pipe_lock);
}

/* ─── Shared Memory (Control Flags) ──────────────────────────── */

static void shmem_init(void)
{
    g_shmem_handle = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0, 64,
        GE_SHMEM_NAME
    );

    if (g_shmem_handle) {
        g_ctl = (volatile BYTE *)MapViewOfFile(
            g_shmem_handle,
            FILE_MAP_ALL_ACCESS,
            0, 0, 64
        );
        if (g_ctl) {
            /* Set default flags on first creation */
            if (g_ctl[0] == 0) {
                g_ctl[0] = CTL_DEFAULT;
            }
        }
    }
}

/* ─── Hook Functions ──────────────────────────────────────────── */

static int WSAAPI hooked_send(SOCKET s, const char *buf, int len, int flags)
{
    InterlockedIncrement(&g_send_count);

    /* Log the plaintext packet BEFORE it hits the real send */
    pipe_write_packet(DIR_C2S, buf, len);

    /* Call original */
    return g_orig_send(s, buf, len, flags);
}

static int WSAAPI hooked_recv(SOCKET s, char *buf, int len, int flags)
{
    int result;

    /* Call original first — we need the data */
    result = g_orig_recv(s, buf, len, flags);

    if (result > 0) {
        InterlockedIncrement(&g_recv_count);
        pipe_write_packet(DIR_S2C, buf, result);
    }

    return result;
}

/* ─── IAT Hook Engine ─────────────────────────────────────────── */

/**
 * Walk the PE Import Address Table to find and replace a function pointer.
 *
 * ge.exe has ASLR disabled so the PE is always at 0x00400000.
 * We walk the import descriptors, find WS2_32.dll, then scan its
 * thunk array for the target function address.
 */
static BOOL iat_hook(
    HMODULE hModule,
    const char *target_dll,
    void *original_func,
    void *hook_func,
    void **out_original
)
{
    BYTE *base = (BYTE *)hModule;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_IMPORT_DESCRIPTOR *imports;
    DWORD import_rva;

    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (import_rva == 0)
        return FALSE;

    imports = (IMAGE_IMPORT_DESCRIPTOR *)(base + import_rva);

    /* Walk import descriptors */
    for (; imports->Name != 0; imports++) {
        const char *dll_name = (const char *)(base + imports->Name);

        /* Case-insensitive compare for DLL name */
        if (_stricmp(dll_name, target_dll) != 0)
            continue;

        /* Found the target DLL — scan its IAT thunks */
        {
            IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA *)(base + imports->FirstThunk);

            for (; thunk->u1.Function != 0; thunk++) {
                void *func = (void *)thunk->u1.Function;

                if (func == original_func) {
                    /* Found it — replace with our hook */
                    DWORD old_protect;

                    if (VirtualProtect(
                        &thunk->u1.Function,
                        sizeof(thunk->u1.Function),
                        PAGE_READWRITE,
                        &old_protect))
                    {
                        if (out_original)
                            *out_original = func;

                        thunk->u1.Function = (ULONG_PTR)hook_func;

                        /* Restore original protection */
                        VirtualProtect(
                            &thunk->u1.Function,
                            sizeof(thunk->u1.Function),
                            old_protect,
                            &old_protect
                        );

                        return TRUE;
                    }
                }
            }
        }
    }

    return FALSE;
}

/* ─── Install / Remove Hooks ──────────────────────────────────── */

static BOOL install_hooks(void)
{
    HMODULE hWs2 = GetModuleHandleA("WS2_32.dll");
    HMODULE hExe = GetModuleHandleA(NULL);  /* ge.exe */
    void *real_send, *real_recv;
    BOOL ok_send, ok_recv;

    if (!hWs2 || !hExe)
        return FALSE;

    /* Get the real addresses of send/recv from WS2_32 */
    real_send = (void *)GetProcAddress(hWs2, "send");
    real_recv = (void *)GetProcAddress(hWs2, "recv");

    if (!real_send || !real_recv)
        return FALSE;

    /* Hook send() in ge.exe's IAT */
    ok_send = iat_hook(
        hExe, "WS2_32.dll",
        real_send, hooked_send,
        (void **)&g_orig_send
    );

    /* Hook recv() in ge.exe's IAT */
    ok_recv = iat_hook(
        hExe, "WS2_32.dll",
        real_recv, hooked_recv,
        (void **)&g_orig_recv
    );

    /* If IAT lookup by address failed, try by name thunk (ordinal import) */
    if (!ok_send) {
        /* Fallback: scan all thunks looking for WS2_32 ordinal #19 (send) */
        /* For now, store the real function as fallback */
        g_orig_send = (void *)real_send;
    }

    if (!ok_recv) {
        g_orig_recv = (void *)real_recv;
    }

    return (ok_send || ok_recv);
}

static void remove_hooks(void)
{
    HMODULE hExe = GetModuleHandleA(NULL);

    if (g_orig_send) {
        iat_hook(hExe, "WS2_32.dll",
                 hooked_send, g_orig_send, NULL);
        g_orig_send = NULL;
    }

    if (g_orig_recv) {
        iat_hook(hExe, "WS2_32.dll",
                 hooked_recv, g_orig_recv, NULL);
        g_orig_recv = NULL;
    }
}

/* ─── Fallback: Inline Hook via Detour ────────────────────────── */

/**
 * If IAT hook fails (ge.exe imports by ordinal, not by name thunk match),
 * we fall back to a simple 5-byte JMP detour on the real send/recv.
 *
 * This patches the first 5 bytes of the target function with:
 *   E9 <relative_offset>   ; JMP hook_func
 *
 * We save the original 5 bytes so we can call through by restoring,
 * calling, and re-patching. This is a trampoline-less approach —
 * simple but has a tiny race window on unhook/rehook.
 */

static BYTE g_send_orig_bytes[5];
static BYTE g_recv_orig_bytes[5];
static void *g_send_real_addr = NULL;
static void *g_recv_real_addr = NULL;

static BOOL inline_hook(void *target, void *hook, BYTE *saved_bytes)
{
    DWORD old_protect;
    BYTE jmp_patch[5];
    DWORD rel;

    /* Calculate relative jump */
    rel = (DWORD)((BYTE *)hook - (BYTE *)target - 5);

    jmp_patch[0] = 0xE9;  /* JMP rel32 */
    memcpy(&jmp_patch[1], &rel, 4);

    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old_protect))
        return FALSE;

    /* Save original bytes */
    memcpy(saved_bytes, target, 5);

    /* Write JMP */
    memcpy(target, jmp_patch, 5);

    VirtualProtect(target, 5, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), target, 5);

    return TRUE;
}

static void inline_unhook(void *target, BYTE *saved_bytes)
{
    DWORD old_protect;
    if (VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old_protect)) {
        memcpy(target, saved_bytes, 5);
        VirtualProtect(target, 5, old_protect, &old_protect);
        FlushInstructionCache(GetCurrentProcess(), target, 5);
    }
}

/**
 * Trampoline-less call-through: unhook → call original → rehook.
 * Protected by critical section to avoid race conditions.
 */
static CRITICAL_SECTION g_detour_lock;

static int WSAAPI detour_send(SOCKET s, const char *buf, int len, int flags)
{
    int result;

    InterlockedIncrement(&g_send_count);
    pipe_write_packet(DIR_C2S, buf, len);

    EnterCriticalSection(&g_detour_lock);
    inline_unhook(g_send_real_addr, g_send_orig_bytes);
    result = ((int (WSAAPI *)(SOCKET, const char*, int, int))g_send_real_addr)(s, buf, len, flags);
    inline_hook(g_send_real_addr, detour_send, g_send_orig_bytes);
    LeaveCriticalSection(&g_detour_lock);

    return result;
}

static int WSAAPI detour_recv(SOCKET s, char *buf, int len, int flags)
{
    int result;

    EnterCriticalSection(&g_detour_lock);
    inline_unhook(g_recv_real_addr, g_recv_orig_bytes);
    result = ((int (WSAAPI *)(SOCKET, char*, int, int))g_recv_real_addr)(s, buf, len, flags);
    inline_hook(g_recv_real_addr, detour_recv, g_recv_orig_bytes);
    LeaveCriticalSection(&g_detour_lock);

    if (result > 0) {
        InterlockedIncrement(&g_recv_count);
        pipe_write_packet(DIR_S2C, buf, result);
    }

    return result;
}

static BOOL install_detour_hooks(void)
{
    HMODULE hWs2 = GetModuleHandleA("WS2_32.dll");
    BOOL ok;

    if (!hWs2)
        return FALSE;

    g_send_real_addr = (void *)GetProcAddress(hWs2, "send");
    g_recv_real_addr = (void *)GetProcAddress(hWs2, "recv");

    if (!g_send_real_addr || !g_recv_real_addr)
        return FALSE;

    InitializeCriticalSection(&g_detour_lock);

    ok  = inline_hook(g_send_real_addr, detour_send, g_send_orig_bytes);
    ok &= inline_hook(g_recv_real_addr, detour_recv, g_recv_orig_bytes);

    return ok;
}

static void remove_detour_hooks(void)
{
    if (g_send_real_addr)
        inline_unhook(g_send_real_addr, g_send_orig_bytes);
    if (g_recv_real_addr)
        inline_unhook(g_recv_real_addr, g_recv_orig_bytes);

    DeleteCriticalSection(&g_detour_lock);
}

/* ─── DLL Entry Point ─────────────────────────────────────────── */

static BOOL g_using_detour = FALSE;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_pipe_lock);

        /* Initialize shared memory for control flags */
        shmem_init();

        /* Initialize named pipe */
        pipe_init();

        /* Try IAT hook first (cleanest approach) */
        if (!install_hooks()) {
            /* IAT hook failed — fall back to inline detour */
            if (install_detour_hooks()) {
                g_using_detour = TRUE;
            } else {
                /* Both methods failed */
                OutputDebugStringA("[phantom_hook] FATAL: All hook methods failed\n");
                return FALSE;  /* Refuse to load */
            }
        }

        OutputDebugStringA("[phantom_hook] Hooks installed successfully\n");
        break;

    case DLL_PROCESS_DETACH:
        /* Clean up hooks */
        if (g_using_detour) {
            remove_detour_hooks();
        } else {
            remove_hooks();
        }

        /* Clean up pipe */
        if (g_pipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_pipe);
            g_pipe = INVALID_HANDLE_VALUE;
        }

        /* Clean up shared memory */
        if (g_ctl) {
            UnmapViewOfFile((void *)g_ctl);
            g_ctl = NULL;
        }
        if (g_shmem_handle) {
            CloseHandle(g_shmem_handle);
            g_shmem_handle = NULL;
        }

        DeleteCriticalSection(&g_pipe_lock);

        OutputDebugStringA("[phantom_hook] Hooks removed, DLL detaching\n");
        break;
    }

    return TRUE;
}

/* ─── Exported Status Function (callable from Python via ctypes) ── */

__declspec(dllexport) void phantom_status(DWORD *out_send, DWORD *out_recv)
{
    if (out_send) *out_send = (DWORD)g_send_count;
    if (out_recv) *out_recv = (DWORD)g_recv_count;
}
