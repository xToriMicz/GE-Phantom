/**
 * phantom_hook.c — GE_Phantom Reconnaissance DLL (Phase 1 + Phase 2)
 *
 * Phase 1: IAT-hooks send() and recv() in ge.exe to capture packets.
 * Phase 2: IES property scanner — scans .text for xrefs to known strings,
 *          provides GetPropertyNumber/SetPropertyNumber callers via
 *          shared memory command interface.
 *
 * Communication:
 *   - Named pipe \\.\pipe\ge_phantom streams packets to Python reader
 *   - Shared memory "Local\\ge_phantom_cmd" for Phase 2 command interface
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

#include <objbase.h>    /* CoInitializeEx / CoUninitialize */

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

/* ─── Debug Log ───────────────────────────────────────────────── */

static HANDLE g_logfile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_log_lock;

static void log_init(HMODULE hModule)
{
    char path[MAX_PATH];
    DWORD len;

    InitializeCriticalSection(&g_log_lock);

    /* Write log next to the DLL */
    len = GetModuleFileNameA(hModule, path, MAX_PATH);
    if (len > 4) {
        /* Replace .dll with .log */
        strcpy(path + len - 4, ".log");
    } else {
        strcpy(path, "C:\\phantom_hook.log");
    }

    g_logfile = CreateFileA(
        path, GENERIC_WRITE, FILE_SHARE_READ,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
}

static void log_write(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    DWORD written;
    int n;
    DWORD tick;

    if (g_logfile == INVALID_HANDLE_VALUE)
        return;

    tick = GetTickCount();

    EnterCriticalSection(&g_log_lock);

    n = sprintf(buf, "[%08u] ", tick);
    va_start(ap, fmt);
    n += vsprintf(buf + n, fmt, ap);
    va_end(ap);
    buf[n++] = '\r';
    buf[n++] = '\n';

    WriteFile(g_logfile, buf, n, &written, NULL);
    FlushFileBuffers(g_logfile);

    LeaveCriticalSection(&g_log_lock);
}

static void log_close(void)
{
    if (g_logfile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_logfile);
        g_logfile = INVALID_HANDLE_VALUE;
    }
    DeleteCriticalSection(&g_log_lock);
}

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

/* ─── Phase 2: Command Interface Globals ─────────────────────── */

static HANDLE  g_cmd_shmem_handle = NULL;
static volatile BYTE *g_cmd = NULL;

/* Resolved function addresses (filled by xref scan + manual analysis) */
static fn_GetPropertyNumber g_fn_get_prop = NULL;
static fn_SetPropertyNumber g_fn_set_prop = NULL;

/* Chat/SysMsg internal function pointers (hardcoded addresses from disassembly) */
static fn_ChatInternal  g_fn_chat   = (fn_ChatInternal)GE_FUNC_CHAT_INTERNAL;
static fn_SysMsgInternal g_fn_sysmsg = (fn_SysMsgInternal)GE_FUNC_SYSMSG_INTERNAL;

/* UpdateItemTable — address resolved dynamically via CMD_SET_FUNC_ADDR (which=2) */
static fn_UpdateItemTable g_fn_update_item_table = NULL;

/* Game window handle — found once, cached for SendKey */
static HWND g_game_hwnd = NULL;

/* Find main window of current process */
static BOOL CALLBACK enum_wnd_proc(HWND hwnd, LPARAM lParam)
{
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == GetCurrentProcessId() && IsWindowVisible(hwnd)) {
        char cls[64];
        GetClassNameA(hwnd, cls, sizeof(cls));
        /* Skip console windows */
        if (strcmp(cls, "ConsoleWindowClass") != 0) {
            *(HWND *)lParam = hwnd;
            return FALSE;  /* stop enumeration */
        }
    }
    return TRUE;
}

static HWND find_game_window(void)
{
    if (g_game_hwnd && IsWindow(g_game_hwnd))
        return g_game_hwnd;
    g_game_hwnd = NULL;
    EnumWindows(enum_wnd_proc, (LPARAM)&g_game_hwnd);
    if (g_game_hwnd) {
        char title[128];
        GetWindowTextA(g_game_hwnd, title, sizeof(title));
        log_write("find_game_window: hwnd=%p title=\"%s\"", g_game_hwnd, title);
    }
    return g_game_hwnd;
}

/* ── Keyboard Input ──────────────────────────────────────────── */
static DWORD g_key_hold_ms = 60;  /* keybd_event hold duration in ms */

/* Forward declarations (defined later in hook infrastructure section) */
static BOOL iat_hook(HMODULE hModule, const char *target_dll,
                     void *original_func, void *hook_func, void **out_original);
static BOOL inline_hook(void *target, void *hook, BYTE *saved_bytes);
static void inline_unhook(void *target, BYTE *saved_bytes);

/* Forward declaration for bot hotkey handler (defined in bot control section) */
static BOOL handle_bot_hotkey(BYTE vk, BOOL ctrl, BOOL shift, BOOL alt);

/* ── Phase 6b: Keyboard State API Hooks ──────────────────────── */

/*
 * Hook GetKeyState AND GetAsyncKeyState to:
 * 1. Return "pressed" (0x8000) for the VK we're faking via PostMessage
 * 2. Count calls to discover which API the game actually uses for input
 */
typedef SHORT (WINAPI *fn_GetKeyState)(int nVirtKey);
typedef SHORT (WINAPI *fn_GetAsyncKeyState)(int vKey);

static fn_GetKeyState      g_orig_GetKeyState      = NULL;
static fn_GetAsyncKeyState g_orig_GetAsyncKeyState  = NULL;

static volatile BOOL  g_keystate_hooked      = FALSE;
static volatile BOOL  g_asynckeystate_hooked = FALSE;

static volatile DWORD g_fake_vk = 0;          /* VK to fake as "pressed", 0 = none */
static volatile LONG  g_keystate_hook_count      = 0;
static volatile LONG  g_asynckeystate_hook_count = 0;
static volatile LONG  g_keystate_total_calls     = 0;  /* ALL calls, not just faked */
static volatile LONG  g_asynckeystate_total_calls = 0;

static SHORT WINAPI hooked_GetKeyState(int nVirtKey)
{
    InterlockedIncrement(&g_keystate_total_calls);
    if (g_fake_vk != 0 && (DWORD)nVirtKey == g_fake_vk) {
        InterlockedIncrement(&g_keystate_hook_count);
        return (SHORT)0x8000;
    }
    return g_orig_GetKeyState(nVirtKey);
}

static SHORT WINAPI hooked_GetAsyncKeyState(int vKey)
{
    InterlockedIncrement(&g_asynckeystate_total_calls);
    if (g_fake_vk != 0 && (DWORD)vKey == g_fake_vk) {
        InterlockedIncrement(&g_asynckeystate_hook_count);
        return (SHORT)0x8001;  /* pressed + toggled */
    }
    return g_orig_GetAsyncKeyState(vKey);
}

static BOOL install_keystate_hook(void)
{
    HMODULE hExe = GetModuleHandleA(NULL);
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    void *real_gks, *real_gaks;

    if (g_keystate_hooked && g_asynckeystate_hooked) return TRUE;
    if (!hUser32) return FALSE;

    /* Hook GetKeyState */
    if (!g_keystate_hooked) {
        real_gks = (void *)GetProcAddress(hUser32, "GetKeyState");
        if (real_gks && iat_hook(hExe, "user32.dll", real_gks, hooked_GetKeyState, (void **)&g_orig_GetKeyState)) {
            g_keystate_hooked = TRUE;
            log_write("install_keystate_hook: GetKeyState OK orig=%p", g_orig_GetKeyState);
        } else {
            log_write("install_keystate_hook: GetKeyState IAT hook FAILED");
        }
    }

    /* Hook GetAsyncKeyState */
    if (!g_asynckeystate_hooked) {
        real_gaks = (void *)GetProcAddress(hUser32, "GetAsyncKeyState");
        if (real_gaks && iat_hook(hExe, "user32.dll", real_gaks, hooked_GetAsyncKeyState, (void **)&g_orig_GetAsyncKeyState)) {
            g_asynckeystate_hooked = TRUE;
            log_write("install_keystate_hook: GetAsyncKeyState OK orig=%p", g_orig_GetAsyncKeyState);
        } else {
            log_write("install_keystate_hook: GetAsyncKeyState IAT hook FAILED");
        }
    }

    return g_keystate_hooked || g_asynckeystate_hooked;
}

static void remove_keystate_hook(void)
{
    HMODULE hExe;

    hExe = GetModuleHandleA(NULL);

    if (g_keystate_hooked && g_orig_GetKeyState) {
        iat_hook(hExe, "user32.dll", hooked_GetKeyState, g_orig_GetKeyState, NULL);
        g_keystate_hooked = FALSE;
    }
    if (g_asynckeystate_hooked && g_orig_GetAsyncKeyState) {
        iat_hook(hExe, "user32.dll", hooked_GetAsyncKeyState, g_orig_GetAsyncKeyState, NULL);
        g_asynckeystate_hooked = FALSE;
    }

    g_fake_vk = 0;
    log_write("remove_keystate_hook: restored (triggered %d times)", (int)g_keystate_hook_count);
}

/* ── Phase 6c: DirectInput Keyboard Hook ─────────────────────── */

/*
 * The game uses DirectInput8 for keyboard input (dinput8.dll is loaded).
 * We hook IDirectInputDevice8::GetDeviceState to inject fake key presses
 * into the 256-byte keyboard state buffer. This works WITHOUT focus
 * because we modify the output AFTER the real call returns.
 *
 * GetDeviceState returns a 256-byte buffer where each byte is a key state.
 * Index = DIK code (== hardware scan code). Bit 0x80 = key pressed.
 * DIK codes: DIK_Q=0x10, DIK_W=0x11, DIK_SPACE=0x39, DIK_F1=0x3B, etc.
 * Same as scan codes from MapVirtualKey(vk, MAPVK_VK_TO_VSC).
 */

/* GUIDs we need — defined manually to avoid dinput.h dependency */
static const GUID GUID_SysKeyboard_  = {0x6F1D2B61, 0xD5A0, 0x11CF, {0xBF, 0xD4, 0x00, 0xAA, 0x00, 0x5F, 0x58, 0x42}};
static const GUID IID_IDirectInput8A_ = {0xBF798030, 0x483A, 0x4DA2, {0xAA, 0x99, 0x5D, 0x64, 0xED, 0x36, 0x97, 0x00}};

/* c_dfDIKeyboard — standard 256-byte keyboard data format */
/* We only need the format GUID for SetDataFormat, but we can use the address
 * from dinput8.dll. For simplicity, we'll just call SetCooperativeLevel +
 * SetDataFormat using the known structure. */

typedef HRESULT (WINAPI *fn_DirectInput8Create)(HINSTANCE, DWORD, const GUID *, void **, void *);

/* IDirectInputDevice8::GetDeviceState signature (COM __stdcall) */
typedef HRESULT (__stdcall *fn_DIGetDeviceState)(void *pThis, DWORD cbData, void *lpvData);

static fn_DIGetDeviceState g_orig_DIGetDeviceState = NULL;
static volatile BOOL  g_di_hooked = FALSE;
static volatile DWORD g_fake_dik  = 0;     /* DIK scan code to fake, 0 = none */
static volatile LONG  g_di_hook_inject_count = 0;  /* times we injected a fake key */
static volatile LONG  g_di_hook_call_count = 0;     /* total GetDeviceState calls */
static BYTE g_di_orig_bytes[5];  /* saved bytes for inline hook */
static CRITICAL_SECTION g_di_lock;
static BOOL g_di_lock_inited = FALSE;

static HRESULT __stdcall hooked_DIGetDeviceState(void *pThis, DWORD cbData, void *lpvData)
{
    HRESULT hr;
    DWORD fake;

    InterlockedIncrement(&g_di_hook_call_count);

    /* Call original: unhook → call → rehook (trampoline-less) */
    EnterCriticalSection(&g_di_lock);
    inline_unhook((void *)g_orig_DIGetDeviceState, g_di_orig_bytes);
    hr = g_orig_DIGetDeviceState(pThis, cbData, lpvData);
    inline_hook((void *)g_orig_DIGetDeviceState, hooked_DIGetDeviceState, g_di_orig_bytes);
    LeaveCriticalSection(&g_di_lock);

    /* Inject fake key into the returned buffer */
    fake = g_fake_dik;
    if (fake != 0 && fake < cbData && SUCCEEDED(hr) && lpvData) {
        ((BYTE *)lpvData)[fake] |= 0x80;
        InterlockedIncrement(&g_di_hook_inject_count);
    }

    return hr;
}

static BOOL install_di_keyboard_hook(void)
{
    HMODULE hDI8;
    fn_DirectInput8Create pfnCreate;
    void *pDI = NULL;       /* IDirectInput8A* */
    void *pDevice = NULL;   /* IDirectInputDevice8A* */
    void **vtable;
    fn_DIGetDeviceState realGetDeviceState;
    HRESULT hr;

    if (g_di_hooked) return TRUE;

    /* COM must be initialized on this thread for CreateDevice to work */
    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    hDI8 = GetModuleHandleA("dinput8.dll");
    if (!hDI8) {
        log_write("install_di_keyboard_hook: dinput8.dll not loaded");
        CoUninitialize();
        return FALSE;
    }

    {
        char di8path[MAX_PATH] = {0};
        GetModuleFileNameA(hDI8, di8path, MAX_PATH);
        log_write("install_di_keyboard_hook: dinput8.dll path=%s", di8path);
    }

    pfnCreate = (fn_DirectInput8Create)GetProcAddress(hDI8, "DirectInput8Create");
    if (!pfnCreate) {
        log_write("install_di_keyboard_hook: DirectInput8Create not found");
        CoUninitialize();
        return FALSE;
    }

    /* Create temporary DI8 interface to discover vtable */
    log_write("install_di_keyboard_hook: dinput8.dll=%p pfnCreate=%p", hDI8, pfnCreate);
    hr = pfnCreate(GetModuleHandleA(NULL), 0x0800 /* DIRECTINPUT_VERSION 8.0 */,
                   &IID_IDirectInput8A_, &pDI, NULL);
    log_write("install_di_keyboard_hook: DirectInput8Create hr=0x%08X pDI=%p", hr, pDI);
    if (FAILED(hr) || !pDI) {
        log_write("install_di_keyboard_hook: DirectInput8Create FAILED");
        CoUninitialize();
        return FALSE;
    }

    /* CreateDevice(GUID_SysKeyboard) — vtable[3] */
    {
        void **di_vtable = *(void ***)pDI;
        typedef HRESULT (__stdcall *fn_CreateDevice)(void *, const GUID *, void **, void *);
        fn_CreateDevice pCreateDevice;

        log_write("install_di_keyboard_hook: pDI vtable=%p [0]=%p [1]=%p [2]=%p [3]=%p",
                  di_vtable, di_vtable[0], di_vtable[1], di_vtable[2], di_vtable[3]);

        pCreateDevice = (fn_CreateDevice)di_vtable[3];
        log_write("install_di_keyboard_hook: calling CreateDevice(%p, GUID_SysKeyboard, ...)", pDI);

        hr = pCreateDevice(pDI, &GUID_SysKeyboard_, &pDevice, NULL);
        if (FAILED(hr) || !pDevice) {
            log_write("install_di_keyboard_hook: CreateDevice failed hr=0x%08X — trying fallback", hr);

            /* Fallback: scan dinput8.dll .rdata for IDirectInputDevice8 vtable.
               We look for an array of 32+ function pointers that all point into
               dinput8.dll's code range. The device vtable has ~32 entries. */
            {
                IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hDI8;
                IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)hDI8 + dos->e_lfanew);
                IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
                DWORD s;
                BYTE *codeStart = NULL, *codeEnd = NULL;
                void **found_vtable = NULL;

                /* Find code section */
                for (s = 0; s < nt->FileHeader.NumberOfSections; s++) {
                    BYTE *sbase = (BYTE *)hDI8 + sec[s].VirtualAddress;
                    DWORD ssize = sec[s].Misc.VirtualSize;
                    if (sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                        codeStart = sbase;
                        codeEnd = sbase + ssize;
                    }
                }

                log_write("install_di_keyboard_hook: code=%p-%p imageSize=0x%X",
                          codeStart, codeEnd, nt->OptionalHeader.SizeOfImage);

                if (codeStart) {
                    /* Scan ALL non-code sections for vtable candidates */
                    for (s = 0; s < nt->FileHeader.NumberOfSections; s++) {
                        BYTE *sbase = (BYTE *)hDI8 + sec[s].VirtualAddress;
                        DWORD ssize = sec[s].Misc.VirtualSize;
                        DWORD i;

                        if (sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
                        if (!(sec[s].Characteristics & IMAGE_SCN_MEM_READ)) continue;

                        log_write("install_di_keyboard_hook: scanning section %.8s %p-%p (0x%X chars)",
                                  sec[s].Name, sbase, sbase + ssize, sec[s].Characteristics);

                        for (i = 0; i + 20 * sizeof(void *) <= ssize; i += sizeof(void *)) {
                            void **candidate = (void **)(sbase + i);
                            int good = 0, j;
                            for (j = 0; j < 20; j++) {
                                BYTE *p = (BYTE *)candidate[j];
                                if (p >= codeStart && p < codeEnd)
                                    good++;
                                else
                                    break;
                            }
                            if (good >= 20) {
                                int total = 0;
                                if (candidate == di_vtable) continue;
                                for (j = 0; j < 40; j++) {
                                    BYTE *p = (BYTE *)candidate[j];
                                    if (p >= codeStart && p < codeEnd)
                                        total++;
                                    else
                                        break;
                                }
                                log_write("install_di_keyboard_hook: vtable candidate at %p (%d entries) [9]=%p",
                                          candidate, total, candidate[9]);
                                if (total >= 25 && !found_vtable) {
                                    found_vtable = candidate;
                                }
                            }
                        }
                    }
                }

                /* Release DI8 */
                ((HRESULT (__stdcall *)(void *))di_vtable[2])(pDI);
                CoUninitialize();

                if (found_vtable) {
                    realGetDeviceState = (fn_DIGetDeviceState)found_vtable[9];
                    log_write("install_di_keyboard_hook: fallback found vtable=%p GetDeviceState=%p", found_vtable, realGetDeviceState);
                    goto do_hook;
                }
                log_write("install_di_keyboard_hook: fallback scan found no device vtable");
                return FALSE;
            }
        }
    }

    /* Read GetDeviceState address from device vtable[9] */
    vtable = *(void ***)pDevice;
    realGetDeviceState = (fn_DIGetDeviceState)vtable[9];
    log_write("install_di_keyboard_hook: GetDeviceState = %p", realGetDeviceState);

    /* Release temp objects — vtable[2] = Release */
    ((HRESULT (__stdcall *)(void *))(*(void ***)pDevice)[2])(pDevice);
    ((HRESULT (__stdcall *)(void *))(*(void ***)pDI)[2])(pDI);

    CoUninitialize();

do_hook:

    /* Init critical section for unhook/rehook */
    if (!g_di_lock_inited) {
        InitializeCriticalSection(&g_di_lock);
        g_di_lock_inited = TRUE;
    }

    /* Inline-hook GetDeviceState */
    g_orig_DIGetDeviceState = realGetDeviceState;
    if (!inline_hook((void *)realGetDeviceState, hooked_DIGetDeviceState, g_di_orig_bytes)) {
        log_write("install_di_keyboard_hook: inline_hook FAILED");
        return FALSE;
    }

    g_di_hooked = TRUE;
    g_di_hook_call_count = 0;
    g_di_hook_inject_count = 0;
    log_write("install_di_keyboard_hook: OK — hooked GetDeviceState at %p", realGetDeviceState);
    return TRUE;
}

static void remove_di_keyboard_hook(void)
{
    if (!g_di_hooked || !g_orig_DIGetDeviceState) return;

    inline_unhook((void *)g_orig_DIGetDeviceState, g_di_orig_bytes);
    g_di_hooked = FALSE;
    g_fake_dik = 0;
    log_write("remove_di_keyboard_hook: restored (injected %d, total %d calls)",
              (int)g_di_hook_inject_count, (int)g_di_hook_call_count);
}

/* ── Phase 6: WndProc Message Spy ────────────────────────────── */

static WNDPROC g_orig_wndproc = NULL;
static volatile BOOL g_wndproc_hooked = FALSE;

/* Per-type message counters (atomically incremented from WndProc) */
static volatile LONG g_wnd_keydown    = 0;   /* WM_KEYDOWN    0x0100 */
static volatile LONG g_wnd_keyup      = 0;   /* WM_KEYUP      0x0101 */
static volatile LONG g_wnd_char       = 0;   /* WM_CHAR        0x0102 */
static volatile LONG g_wnd_syskeydown = 0;   /* WM_SYSKEYDOWN 0x0104 */
static volatile LONG g_wnd_syskeyup   = 0;   /* WM_SYSKEYUP   0x0105 */
static volatile LONG g_wnd_input      = 0;   /* WM_INPUT      0x00FF */
static volatile LONG g_wnd_hotkey     = 0;   /* WM_HOTKEY     0x0312 */
static volatile LONG g_wnd_other_kb   = 0;   /* other keyboard msgs   */

/* Ring buffer for recent keyboard messages */
#define WNDPROC_LOG_SIZE 32

typedef struct {
    DWORD tick;
    UINT  msg;
    DWORD wParam;
    DWORD lParam;
} WndProcLogEntry;

static WndProcLogEntry g_wndproc_log[WNDPROC_LOG_SIZE];
static volatile LONG g_wndproc_log_idx = 0;

static BOOL is_keyboard_msg(UINT msg)
{
    return (msg >= 0x0100 && msg <= 0x0109)   /* WM_KEYFIRST..WM_KEYLAST */
        || msg == 0x00FF                       /* WM_INPUT */
        || msg == 0x0312                       /* WM_HOTKEY */
        || msg == 0x0290                       /* WM_IME_KEYDOWN */
        || msg == 0x0291;                      /* WM_IME_KEYUP */
}

static const char *kb_msg_name(UINT msg)
{
    switch (msg) {
    case 0x0100: return "KEYDOWN";
    case 0x0101: return "KEYUP";
    case 0x0102: return "CHAR";
    case 0x0103: return "DEADCHAR";
    case 0x0104: return "SYSKEYDOWN";
    case 0x0105: return "SYSKEYUP";
    case 0x0106: return "SYSCHAR";
    case 0x0107: return "SYSDEADCHAR";
    case 0x0108: return "UNICHAR";
    case 0x0109: return "KEYLAST";
    case 0x00FF: return "INPUT";
    case 0x0312: return "HOTKEY";
    case 0x0290: return "IME_KEYDN";
    case 0x0291: return "IME_KEYUP";
    default:     return "?KB";
    }
}

/**
 * Subclassed WndProc — intercepts all keyboard messages.
 * This runs on the game's main thread (called by DispatchMessage).
 *
 * SAFETY: We cache g_orig_wndproc in a local to avoid a race with
 * remove_wndproc_hook() setting it to NULL from the detach thread.
 */
static LRESULT CALLBACK hooked_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    WNDPROC orig = g_orig_wndproc;  /* cache — protect against concurrent unhook */
    if (!orig) return DefWindowProcA(hwnd, msg, wParam, lParam);

    /* Bot hotkey detection — check on key down before logging */
    if (msg == 0x0100 /* WM_KEYDOWN */ || msg == 0x0104 /* WM_SYSKEYDOWN */) {
        BOOL ctrl  = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
        BOOL shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
        BOOL alt   = (GetKeyState(VK_MENU) & 0x8000) != 0;
        if (handle_bot_hotkey((BYTE)wParam, ctrl, shift, alt))
            return 0;  /* consumed — don't pass to game */
    }

    if (is_keyboard_msg(msg)) {
        /* Log to ring buffer */
        LONG idx = InterlockedIncrement(&g_wndproc_log_idx) - 1;
        WndProcLogEntry *e = &g_wndproc_log[idx % WNDPROC_LOG_SIZE];
        e->tick = GetTickCount();
        e->msg = msg;
        e->wParam = (DWORD)wParam;
        e->lParam = (DWORD)lParam;

        /* Increment per-type counter */
        switch (msg) {
        case 0x0100: InterlockedIncrement(&g_wnd_keydown); break;
        case 0x0101: InterlockedIncrement(&g_wnd_keyup); break;
        case 0x0102: InterlockedIncrement(&g_wnd_char); break;
        case 0x0104: InterlockedIncrement(&g_wnd_syskeydown); break;
        case 0x0105: InterlockedIncrement(&g_wnd_syskeyup); break;
        case 0x00FF: InterlockedIncrement(&g_wnd_input); break;
        case 0x0312: InterlockedIncrement(&g_wnd_hotkey); break;
        default:     InterlockedIncrement(&g_wnd_other_kb); break;
        }

        /* Log details — rate-limit WM_INPUT (could be mouse spam) */
        if (msg == 0x00FF) {
            /* WM_INPUT: only log first 20 to avoid mouse-move flood */
            if (g_wnd_input <= 20) {
                log_write("WndProc: INPUT(0x00FF) wP=0x%04X lP=0x%08X (#%d)",
                          (DWORD)wParam, (DWORD)lParam, (int)g_wnd_input);
            } else if (g_wnd_input == 21) {
                log_write("WndProc: INPUT — suppressing further logs (count > 20)");
            }
        } else {
            log_write("WndProc: %s(0x%04X) wP=0x%04X lP=0x%08X",
                      kb_msg_name(msg), msg, (DWORD)wParam, (DWORD)lParam);
        }
    }

    return CallWindowProcA(orig, hwnd, msg, wParam, lParam);
}

/**
 * Install WndProc subclass on the game window.
 * MUST be called from the game's main thread (deferred via g_mainthread_cmd).
 */
static BOOL install_wndproc_hook(void)
{
    HWND hwnd = find_game_window();
    if (!hwnd) {
        log_write("install_wndproc_hook: no game window found");
        return FALSE;
    }
    if (g_wndproc_hooked) {
        log_write("install_wndproc_hook: already hooked");
        return TRUE;
    }

    g_orig_wndproc = (WNDPROC)(LONG_PTR)SetWindowLongA(hwnd, GWL_WNDPROC, (LONG)(LONG_PTR)hooked_wndproc);
    if (!g_orig_wndproc) {
        log_write("install_wndproc_hook: SetWindowLongA failed err=%u", GetLastError());
        return FALSE;
    }

    g_wndproc_hooked = TRUE;

    /* Reset counters */
    g_wnd_keydown = 0;
    g_wnd_keyup = 0;
    g_wnd_char = 0;
    g_wnd_syskeydown = 0;
    g_wnd_syskeyup = 0;
    g_wnd_input = 0;
    g_wnd_hotkey = 0;
    g_wnd_other_kb = 0;
    g_wndproc_log_idx = 0;

    log_write("install_wndproc_hook: OK orig=%p new=%p hwnd=%p",
              g_orig_wndproc, hooked_wndproc, hwnd);
    return TRUE;
}

/**
 * Remove WndProc subclass — restore original WndProc.
 * Safe to call from any thread (DllMain detach or main thread command).
 *
 * Safety: verify current WndProc is still ours before restoring.
 * If another hook chained after us, blindly restoring would break the chain.
 */
static void remove_wndproc_hook(void)
{
    HWND hwnd;
    WNDPROC current;
    if (!g_wndproc_hooked || !g_orig_wndproc) return;

    hwnd = find_game_window();
    if (hwnd) {
        current = (WNDPROC)(LONG_PTR)GetWindowLongA(hwnd, GWL_WNDPROC);
        if (current == hooked_wndproc) {
            SetWindowLongA(hwnd, GWL_WNDPROC, (LONG)(LONG_PTR)g_orig_wndproc);
            log_write("remove_wndproc_hook: restored orig=%p", g_orig_wndproc);
        } else {
            log_write("remove_wndproc_hook: WndProc changed by someone else! current=%p ours=%p — NOT restoring",
                      current, hooked_wndproc);
        }
    }

    /* Mark unhooked — set flag before clearing pointer for hooked_wndproc safety */
    g_wndproc_hooked = FALSE;
    g_orig_wndproc = NULL;
}

/**
 * Check if ge.exe imports Raw Input API functions from user32.dll.
 * Scans the Import Address Table by name. Returns count of RI imports found.
 */
static int check_raw_input_imports(void)
{
    HMODULE hExe = GetModuleHandleA(NULL);
    BYTE *base = (BYTE *)hExe;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_IMPORT_DESCRIPTOR *imports;
    DWORD import_rva;
    int found = 0;

    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!import_rva) return 0;

    imports = (IMAGE_IMPORT_DESCRIPTOR *)(base + import_rva);

    for (; imports->Name != 0; imports++) {
        const char *dll_name = (const char *)(base + imports->Name);

        if (_stricmp(dll_name, "user32.dll") != 0)
            continue;

        log_write("  Scanning user32.dll IAT (OriginalFirstThunk)...");

        /* Walk Original First Thunk (Import Name Table) for named imports */
        if (imports->OriginalFirstThunk) {
            IMAGE_THUNK_DATA *oft = (IMAGE_THUNK_DATA *)(base + imports->OriginalFirstThunk);
            IMAGE_THUNK_DATA *ft  = (IMAGE_THUNK_DATA *)(base + imports->FirstThunk);
            int idx = 0;

            for (; oft->u1.AddressOfData != 0; oft++, ft++, idx++) {
                if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                    continue;  /* ordinal import, skip */

                {
                    IMAGE_IMPORT_BY_NAME *hint =
                        (IMAGE_IMPORT_BY_NAME *)(base + (DWORD)oft->u1.AddressOfData);
                    const char *name = (const char *)hint->Name;

                    /* Flag Raw Input functions */
                    if (strstr(name, "RawInput") || strstr(name, "RAWINPUT")) {
                        log_write("  ** RAW INPUT: %s @ IAT[%d] = %p", name, idx, (void *)ft->u1.Function);
                        found++;
                    }

                    /* Also log all keyboard-related imports for reference */
                    if (strstr(name, "Key") || strstr(name, "key") ||
                        strstr(name, "Input") || strstr(name, "Message") ||
                        strstr(name, "Dispatch") || strstr(name, "Translate") ||
                        strstr(name, "Wnd") || strstr(name, "Window")) {
                        log_write("  user32: %s @ IAT[%d] = %p", name, idx, (void *)ft->u1.Function);
                    }
                }
            }
        }
        break;  /* found user32.dll, done */
    }

    /* Also check dynamic resolution */
    {
        HMODULE hUser32 = GetModuleHandleA("user32.dll");
        if (hUser32) {
            void *pRegRID = (void *)GetProcAddress(hUser32, "RegisterRawInputDevices");
            void *pGetRID = (void *)GetProcAddress(hUser32, "GetRawInputData");
            log_write("  GetProcAddress: RegisterRawInputDevices=%p GetRawInputData=%p",
                      pRegRID, pGetRID);
        }
    }

    return found;
}

/* ─── Bot Control System ─────────────────────────────────────── */

typedef struct {
    DWORD interval_ms;   /* 0 = disabled */
    DWORD last_tick;
} BotTimer;

typedef struct {
    BOOL  enabled;              /* master bot toggle */
    BOOL  auto_pick;            /* Ctrl+Space picking */
    DWORD pick_interval_ms;     /* default 500ms */
    DWORD pick_last_tick;
    BOOL  auto_attack;          /* Space attack */
    DWORD attack_interval_ms;   /* default 2000ms */
    DWORD attack_last_tick;
    BotTimer skill[3][6];       /* 3 chars × 6 skills: PC1=QWE RTY, PC2=ASD FGH, PC3=ZXC VBN */
    BotTimer item[12];          /* 12 item slots: F1-F12 */
} BotState;

static BotState g_bot = {0};

/* Skill key mappings: PC1=QWERTY, PC2=ASDFGH, PC3=ZXCVBN */
static const BYTE g_skill_keys[3][6] = {
    { 'Q', 'W', 'E', 'R', 'T', 'Y' },
    { 'A', 'S', 'D', 'F', 'G', 'H' },
    { 'Z', 'X', 'C', 'V', 'B', 'N' },
};

/* Item keys: F1-F12 */
static const BYTE g_item_keys[12] = {
    VK_F1, VK_F2, VK_F3, VK_F4, VK_F5, VK_F6,
    VK_F7, VK_F8, VK_F9, VK_F10, VK_F11, VK_F12,
};

/* Timer cycle presets (ms): OFF, 10s, 20s, 30s, 60s, 120s, 300s, 600s */
static const DWORD g_timer_presets[] = { 0, 10000, 20000, 30000, 60000, 120000, 300000, 600000 };
#define NUM_TIMER_PRESETS (sizeof(g_timer_presets) / sizeof(g_timer_presets[0]))

/**
 * Send a key combo via keybd_event: focus → modifiers down → key tap → modifiers up → restore.
 * modifiers: bit0=Ctrl, bit1=Shift, bit2=Alt
 */
static void send_key_combo(BYTE vk, BYTE modifiers)
{
    HWND hwnd = find_game_window();
    HWND prev_fg = GetForegroundWindow();
    BOOL need_focus = hwnd && (prev_fg != hwnd);
    BYTE scan = (BYTE)MapVirtualKey(vk, 0);

    if (need_focus) {
        SetForegroundWindow(hwnd);
        Sleep(15);
    }

    /* Modifiers down */
    if (modifiers & 0x01) keybd_event(VK_CONTROL, 0, 0, 0);
    if (modifiers & 0x02) keybd_event(VK_SHIFT, 0, 0, 0);
    if (modifiers & 0x04) keybd_event(VK_MENU, 0, 0, 0);

    /* Key tap */
    keybd_event(vk, scan, 0, 0);
    Sleep(g_key_hold_ms);
    keybd_event(vk, scan, KEYEVENTF_KEYUP, 0);

    /* Modifiers up (reverse order) */
    if (modifiers & 0x04) keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0);
    if (modifiers & 0x02) keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);
    if (modifiers & 0x01) keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, 0);

    /* Restore focus */
    if (need_focus && prev_fg) {
        Sleep(10);
        SetForegroundWindow(prev_fg);
    }
}

/**
 * Bot timer tick — called every 50ms from poll thread.
 * Fires scheduled key combos when intervals elapse.
 */
static void bot_tick(void)
{
    DWORD now;
    int c, s;

    if (!g_bot.enabled) return;

    now = GetTickCount();

    /* Auto pick: Ctrl+Space */
    if (g_bot.auto_pick && g_bot.pick_interval_ms > 0) {
        if (now - g_bot.pick_last_tick >= g_bot.pick_interval_ms) {
            g_bot.pick_last_tick = now;
            send_key_combo(VK_SPACE, 0x01);  /* Ctrl+Space */
        }
    }

    /* Auto attack: Space */
    if (g_bot.auto_attack && g_bot.attack_interval_ms > 0) {
        if (now - g_bot.attack_last_tick >= g_bot.attack_interval_ms) {
            g_bot.attack_last_tick = now;
            send_key_combo(VK_SPACE, 0);
        }
    }

    /* Skills: 3 chars × 6 skills */
    for (c = 0; c < 3; c++) {
        for (s = 0; s < 6; s++) {
            if (g_bot.skill[c][s].interval_ms > 0 &&
                now - g_bot.skill[c][s].last_tick >= g_bot.skill[c][s].interval_ms) {
                g_bot.skill[c][s].last_tick = now;
                send_key_combo(g_skill_keys[c][s], 0);
            }
        }
    }

    /* Items: F1-F12 */
    for (s = 0; s < 12; s++) {
        if (g_bot.item[s].interval_ms > 0 &&
            now - g_bot.item[s].last_tick >= g_bot.item[s].interval_ms) {
            g_bot.item[s].last_tick = now;
            send_key_combo(g_item_keys[s], 0);
        }
    }
}

/**
 * Cycle a timer to the next preset value.
 * Returns the new interval in ms.
 */
static DWORD cycle_timer(DWORD current_ms)
{
    DWORD i;
    for (i = 0; i < NUM_TIMER_PRESETS; i++) {
        if (g_timer_presets[i] == current_ms) {
            return g_timer_presets[(i + 1) % NUM_TIMER_PRESETS];
        }
    }
    /* Not a preset value — reset to OFF */
    return 0;
}

/**
 * Format milliseconds as human-readable string (e.g. "30s", "5m", "OFF").
 */
static const char *format_timer(DWORD ms, char *buf, int buf_size)
{
    if (ms == 0) return "OFF";
    if (ms < 60000)
        sprintf(buf, "%us", ms / 1000);
    else
        sprintf(buf, "%um", ms / 60000);
    return buf;
}

/**
 * Safe sysmsg wrapper — catches crashes when game UI isn't ready.
 * Disables g_fn_sysmsg on first crash so subsequent calls are no-ops.
 */
static void safe_sysmsg(const char *text)
{
    if (!g_fn_sysmsg) return;
    __try {
        g_fn_sysmsg(text);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        log_write("safe_sysmsg: crashed (game not ready?) — disabling sysmsg");
        g_fn_sysmsg = NULL;
    }
}

/**
 * Handle bot hotkeys detected in WndProc.
 * Returns TRUE if the key was consumed (don't pass to game).
 *
 * Hotkeys:
 *   Alt+Shift+0: Master toggle
 *   Alt+Shift+1: Auto Pick toggle
 *   Alt+Shift+2: Auto Attack toggle
 *   Ctrl+Shift+Q/W/E/R/T/Y: Cycle PC1 skill timers
 *   Ctrl+Shift+A/S/D/F/G/H: Cycle PC2 skill timers
 *   Ctrl+Shift+Z/X/C/V/B/N: Cycle PC3 skill timers
 */
static BOOL handle_bot_hotkey(BYTE vk, BOOL ctrl, BOOL shift, BOOL alt)
{
    char msg[64], tbuf[16];

    /* Alt+Shift+number: bot toggles */
    if (alt && shift && !ctrl) {
        switch (vk) {
        case '0':
            g_bot.enabled = !g_bot.enabled;
            sprintf(msg, "[Bot] Master: %s", g_bot.enabled ? "ON" : "OFF");
            log_write("HOTKEY: %s", msg);
            safe_sysmsg(msg);
            return TRUE;
        case '1':
            g_bot.auto_pick = !g_bot.auto_pick;
            if (g_bot.auto_pick && g_bot.pick_interval_ms == 0)
                g_bot.pick_interval_ms = 500;
            g_bot.pick_last_tick = GetTickCount();
            sprintf(msg, "[Bot] Auto Pick: %s (%ums)", g_bot.auto_pick ? "ON" : "OFF", g_bot.pick_interval_ms);
            log_write("HOTKEY: %s", msg);
            safe_sysmsg(msg);
            return TRUE;
        case '2':
            g_bot.auto_attack = !g_bot.auto_attack;
            if (g_bot.auto_attack && g_bot.attack_interval_ms == 0)
                g_bot.attack_interval_ms = 2000;
            g_bot.attack_last_tick = GetTickCount();
            sprintf(msg, "[Bot] Auto Attack: %s (%ums)", g_bot.auto_attack ? "ON" : "OFF", g_bot.attack_interval_ms);
            log_write("HOTKEY: %s", msg);
            safe_sysmsg(msg);
            return TRUE;
        }
    }

    /* Ctrl+Shift+key: cycle skill timers */
    if (ctrl && shift && !alt) {
        int c, s;
        for (c = 0; c < 3; c++) {
            for (s = 0; s < 6; s++) {
                if (vk == g_skill_keys[c][s]) {
                    DWORD new_ms = cycle_timer(g_bot.skill[c][s].interval_ms);
                    g_bot.skill[c][s].interval_ms = new_ms;
                    g_bot.skill[c][s].last_tick = GetTickCount();
                    sprintf(msg, "[Bot] PC%d Skill%d(%c): %s",
                            c + 1, s + 1, g_skill_keys[c][s],
                            format_timer(new_ms, tbuf, sizeof(tbuf)));
                    log_write("HOTKEY: %s", msg);
                    safe_sysmsg(msg);
                    return TRUE;
                }
            }
        }
    }

    return FALSE;  /* not consumed */
}

/* Flag: auto-install WndProc hook on first poll tick */
static volatile BOOL g_auto_wndproc_pending = TRUE;

/* Flag: pending game-thread command (GET_PROP/SET_PROP must run on main thread) */
static volatile BYTE g_mainthread_cmd = CMD_NOP;

/* Forward declarations for game-thread property calls */
static double call_get_property(int idSpace, const char *objName, const char *propName);
static BOOL call_set_property(int idSpace, const char *objName, const char *propName, double value);

/* ─── Pipe Communication ──────────────────────────────────────── */

/**
 * Create named pipe server. The Python logger connects as a client.
 * If the pipe already exists (previous inject), we connect to the existing one.
 */
static volatile BOOL g_pipe_connected = FALSE;

/**
 * Background thread: waits for Python logger to connect to the pipe.
 * ConnectNamedPipe is blocking, so we can't do it in DllMain.
 * Once connected, pipe_write_packet will start delivering data.
 */
static DWORD WINAPI pipe_wait_thread(LPVOID param)
{
    (void)param;
    log_write("pipe_wait_thread: waiting for client...");

    if (ConnectNamedPipe(g_pipe, NULL)) {
        g_pipe_connected = TRUE;
        log_write("pipe_wait_thread: client connected!");
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_PIPE_CONNECTED) {
            /* Client already connected before we called ConnectNamedPipe */
            g_pipe_connected = TRUE;
            log_write("pipe_wait_thread: client was already connected");
        } else {
            log_write("pipe_wait_thread: ConnectNamedPipe failed (err=%u)", err);
        }
    }
    return 0;
}

static void pipe_init(void)
{
    HANDLE hThread;

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

    if (g_pipe != INVALID_HANDLE_VALUE) {
        log_write("pipe: created server pipe OK (handle=%p)", g_pipe);
        /* Start background thread to wait for client connection */
        hThread = CreateThread(NULL, 0, pipe_wait_thread, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    } else {
        DWORD err = GetLastError();
        log_write("pipe: CreateNamedPipe failed (err=%u), trying as client...", err);
        g_pipe = CreateFileA(
            GE_PIPE_NAME,
            GENERIC_WRITE,
            0, NULL,
            OPEN_EXISTING,
            0, NULL
        );
        if (g_pipe != INVALID_HANDLE_VALUE) {
            g_pipe_connected = TRUE;
            log_write("pipe: connected as client OK");
        } else {
            log_write("pipe: FAILED to connect as client (err=%u)", GetLastError());
        }
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

    if (g_pipe == INVALID_HANDLE_VALUE || !g_pipe_connected)
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
    {
        static volatile LONG pipe_write_count = 0;
        BOOL ok1, ok2 = FALSE;
        DWORD written2 = 0;
        LONG pwc;

        ok1 = WriteFile(g_pipe, header, PIPE_HEADER_SIZE, &written, NULL);
        if (ok1 && written == PIPE_HEADER_SIZE) {
            ok2 = WriteFile(g_pipe, buf, log_len, &written2, NULL);
        }

        pwc = InterlockedIncrement(&pipe_write_count);
        if (pwc <= 10 || (pwc % 1000 == 0)) {
            log_write("pipe_write #%d: dir=%d len=%d ok1=%d ok2=%d w1=%u w2=%u err=%u",
                pwc, direction, log_len, ok1, ok2, written, written2,
                (!ok1 || !ok2) ? GetLastError() : 0);
        }
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

/* ─── Main-Thread Command Execution ──────────────────────────── */

/**
 * Execute property get/set commands on the main game thread.
 * Called from hooked_send/hooked_recv which run on the game's main thread.
 * The cmd_poll_thread sets g_mainthread_cmd; this function executes it.
 */
static volatile LONG g_mainthread_busy = 0;  /* reentrancy guard */

static void try_execute_mainthread_cmd(void)
{
    BYTE cmd;
    volatile BYTE *mem = g_cmd;

    if (!mem) return;

    cmd = g_mainthread_cmd;
    if (cmd == CMD_NOP) return;

    /* Reentrancy guard — if Chat/SysMsg calls send() internally,
     * hooked_send would re-enter here. Prevent infinite recursion. */
    if (InterlockedCompareExchange(&g_mainthread_busy, 1, 0) != 0)
        return;

    /* Claim command immediately — prevent poll thread from re-deferring */
    g_mainthread_cmd = CMD_NOP;

    switch (cmd) {
    case CMD_GET_PROP:
    {
        int idSpace = *(volatile int *)(mem + CMD_OFF_PARAM1);
        char propName[64];
        char objName[64];
        double val;

        memcpy(propName, (const void *)(mem + CMD_OFF_STR_PARAM), 64);
        propName[63] = '\0';
        memcpy(objName, (const void *)(mem + CMD_OFF_STR_PARAM2), 64);
        objName[63] = '\0';

        log_write("MAIN_THREAD CMD: GET_PROP idSpace=%d obj=\"%s\" prop=\"%s\"",
            idSpace, objName, propName);

        val = call_get_property(idSpace, objName[0] ? objName : NULL, propName);
        *(volatile double *)(mem + CMD_OFF_RESULT_F64) = val;
        *(volatile float *)(mem + CMD_OFF_RESULT_F32) = (float)val;
        mem[CMD_OFF_STATUS] = (val == -9999.0) ? CMD_STATUS_ERROR : CMD_STATUS_DONE;
        break;
    }

    case CMD_SET_PROP:
    {
        int idSpace = *(volatile int *)(mem + CMD_OFF_PARAM1);
        char propName[64];
        char objName[64];
        double value;
        BOOL ok;

        memcpy(propName, (const void *)(mem + CMD_OFF_STR_PARAM), 64);
        propName[63] = '\0';
        memcpy(objName, (const void *)(mem + CMD_OFF_STR_PARAM2), 64);
        objName[63] = '\0';
        value = *(volatile double *)(mem + CMD_OFF_RESULT_F64);

        log_write("MAIN_THREAD CMD: SET_PROP idSpace=%d obj=\"%s\" prop=\"%s\" val=%f",
            idSpace, objName, propName, value);

        ok = call_set_property(idSpace, objName[0] ? objName : NULL, propName, value);
        mem[CMD_OFF_STATUS] = ok ? CMD_STATUS_DONE : CMD_STATUS_ERROR;
        break;
    }

    case CMD_CHAT:
    {
        DWORD confirm = *(volatile DWORD *)(mem + CMD_OFF_PARAM1);
        char text[64];
        BYTE first_bytes[8];

        /* Safety guard: Chat causes server disconnect! Require confirmation code. */
        if (confirm != 0xCAFE) {
            log_write("MAIN_THREAD CMD: CHAT BLOCKED — requires param1=0xCAFE (got 0x%08X)", confirm);
            log_write("  Chat at 0x%08X is UNSAFE (causes disconnect). Use confirm code to override.",
                (DWORD)(DWORD_PTR)g_fn_chat);
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
            break;
        }

        memcpy(text, (const void *)(mem + CMD_OFF_STR_PARAM), 64);
        text[63] = '\0';

        /* Read first bytes at function address for diagnostics */
        memcpy(first_bytes, (void *)g_fn_chat, 8);
        log_write("MAIN_THREAD CMD: CHAT text=\"%s\" fn=0x%08X bytes=[%02X %02X %02X %02X %02X %02X %02X %02X]",
            text, (DWORD)(DWORD_PTR)g_fn_chat,
            first_bytes[0], first_bytes[1], first_bytes[2], first_bytes[3],
            first_bytes[4], first_bytes[5], first_bytes[6], first_bytes[7]);

        __try {
            log_write("  calling g_fn_chat (CONFIRMED)...");
            g_fn_chat(text);
            log_write("  -> CHAT OK (returned)");
            mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            log_write("  -> CHAT EXCEPTION 0x%08X!", GetExceptionCode());
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
        }
        break;
    }

    case CMD_SYSMSG:
    {
        char text[64];
        BYTE first_bytes[8];
        memcpy(text, (const void *)(mem + CMD_OFF_STR_PARAM), 64);
        text[63] = '\0';

        /* Read first bytes at function address for diagnostics */
        memcpy(first_bytes, (void *)g_fn_sysmsg, 8);
        log_write("MAIN_THREAD CMD: SYSMSG text=\"%s\" fn=0x%08X bytes=[%02X %02X %02X %02X %02X %02X %02X %02X]",
            text, (DWORD)(DWORD_PTR)g_fn_sysmsg,
            first_bytes[0], first_bytes[1], first_bytes[2], first_bytes[3],
            first_bytes[4], first_bytes[5], first_bytes[6], first_bytes[7]);

        __try {
            log_write("  calling g_fn_sysmsg...");
            g_fn_sysmsg(text);
            log_write("  -> SYSMSG OK (returned)");
            mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            log_write("  -> SYSMSG EXCEPTION 0x%08X!", GetExceptionCode());
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
        }
        break;
    }

    case CMD_UPDATE_ITEM_TABLE:
    {
        if (!g_fn_update_item_table) {
            log_write("MAIN_THREAD CMD: UPDATE_ITEM_TABLE — function not resolved! Use setaddr update <addr>");
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
            break;
        }

        log_write("MAIN_THREAD CMD: UPDATE_ITEM_TABLE fn=0x%08X",
            (DWORD)(DWORD_PTR)g_fn_update_item_table);

        __try {
            DWORD tick_before = GetTickCount();
            DWORD tick_after;

            g_fn_update_item_table();

            tick_after = GetTickCount();
            log_write("  -> UPDATE_ITEM_TABLE OK (took %u ms)", tick_after - tick_before);

            *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = tick_after - tick_before;
            mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            log_write("  -> UPDATE_ITEM_TABLE EXCEPTION 0x%08X!", GetExceptionCode());
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
        }
        break;
    }

    case CMD_HOOK_WNDPROC:
    {
        log_write("MAIN_THREAD CMD: HOOK_WNDPROC");
        if (install_wndproc_hook()) {
            mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        } else {
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
        }
        break;
    }

    case CMD_UNHOOK_WNDPROC:
    {
        log_write("MAIN_THREAD CMD: UNHOOK_WNDPROC");
        remove_wndproc_hook();
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;
    }

    default:
        break;
    }

    /* Clear command in shmem — ready for next */
    mem[CMD_OFF_COMMAND] = CMD_NOP;

    /* Release reentrancy guard */
    InterlockedExchange(&g_mainthread_busy, 0);
}

/* ─── Hook Functions ──────────────────────────────────────────── */

static int WSAAPI hooked_send(SOCKET s, const char *buf, int len, int flags)
{
    LONG n = InterlockedIncrement(&g_send_count);

    /* Execute pending game-thread commands (GET_PROP/SET_PROP) */
    try_execute_mainthread_cmd();

    /* Log first few sends to debug file */
    if (n <= 5) {
        log_write("hooked_send #%d: len=%d first4=[%02X %02X %02X %02X]",
            n, len,
            len > 0 ? (BYTE)buf[0] : 0, len > 1 ? (BYTE)buf[1] : 0,
            len > 2 ? (BYTE)buf[2] : 0, len > 3 ? (BYTE)buf[3] : 0);
    }

    /* Log the plaintext packet BEFORE it hits the real send */
    pipe_write_packet(DIR_C2S, buf, len);

    /* Call original */
    return g_orig_send(s, buf, len, flags);
}

static int WSAAPI hooked_recv(SOCKET s, char *buf, int len, int flags)
{
    int result;

    /* Execute pending game-thread commands (GET_PROP/SET_PROP) */
    try_execute_mainthread_cmd();

    /* Call original first — we need the data */
    result = g_orig_recv(s, buf, len, flags);

    if (result > 0) {
        LONG n = InterlockedIncrement(&g_recv_count);
        if (n <= 5) {
            log_write("hooked_recv #%d: len=%d first4=[%02X %02X %02X %02X]",
                n, result,
                result > 0 ? (BYTE)buf[0] : 0, result > 1 ? (BYTE)buf[1] : 0,
                result > 2 ? (BYTE)buf[2] : 0, result > 3 ? (BYTE)buf[3] : 0);
        }
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

    log_write("install_hooks: WS2_32=%p ge.exe=%p", hWs2, hExe);

    if (!hWs2 || !hExe) {
        log_write("install_hooks: FAILED — module handle NULL");
        return FALSE;
    }

    /* Get the real addresses of send/recv from WS2_32 */
    real_send = (void *)GetProcAddress(hWs2, "send");
    real_recv = (void *)GetProcAddress(hWs2, "recv");

    log_write("install_hooks: real_send=%p real_recv=%p", real_send, real_recv);

    if (!real_send || !real_recv) {
        log_write("install_hooks: FAILED — GetProcAddress returned NULL");
        return FALSE;
    }

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

    log_write("install_hooks: IAT send=%s recv=%s",
        ok_send ? "OK" : "FAIL", ok_recv ? "OK" : "FAIL");

    /* If IAT lookup by address failed, store real function for detour fallback */
    if (!ok_send) {
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

    /* Execute pending game-thread commands (same as hooked_send) */
    try_execute_mainthread_cmd();

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

    /* Execute pending game-thread commands (same as hooked_recv) */
    try_execute_mainthread_cmd();

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
    BOOL ok_send, ok_recv;

    if (!hWs2) {
        log_write("detour: WS2_32 not found");
        return FALSE;
    }

    g_send_real_addr = (void *)GetProcAddress(hWs2, "send");
    g_recv_real_addr = (void *)GetProcAddress(hWs2, "recv");

    log_write("detour: send=%p recv=%p", g_send_real_addr, g_recv_real_addr);

    if (!g_send_real_addr || !g_recv_real_addr)
        return FALSE;

    InitializeCriticalSection(&g_detour_lock);

    ok_send = inline_hook(g_send_real_addr, detour_send, g_send_orig_bytes);
    ok_recv = inline_hook(g_recv_real_addr, detour_recv, g_recv_orig_bytes);

    log_write("detour: send=%s recv=%s",
        ok_send ? "OK" : "FAIL", ok_recv ? "OK" : "FAIL");
    log_write("detour: send orig bytes=[%02X %02X %02X %02X %02X]",
        g_send_orig_bytes[0], g_send_orig_bytes[1], g_send_orig_bytes[2],
        g_send_orig_bytes[3], g_send_orig_bytes[4]);

    return (ok_send && ok_recv);
}

static void remove_detour_hooks(void)
{
    if (g_send_real_addr)
        inline_unhook(g_send_real_addr, g_send_orig_bytes);
    if (g_recv_real_addr)
        inline_unhook(g_recv_real_addr, g_recv_orig_bytes);

    DeleteCriticalSection(&g_detour_lock);
}

/* ─── Phase 2: Cross-Reference Scanner ────────────────────────── */

/**
 * Xref target: a string address we want to find references to in .text
 */
typedef struct {
    DWORD   addr;       /* Address of the string in .rdata */
    const char *label;  /* Human-readable label for logging */
} xref_target_t;

static const xref_target_t g_xref_targets[] = {
    { GE_STR_SET_PROP_NUM, "SetPropertyNumber" },
    { GE_STR_GET_PROP_NUM, "GetPropertyNumber" },
    { GE_STR_SPL_RANGE,    "SplRange"          },
    { GE_STR_KEEP_RANGE,   "KeepRange"         },
};

/**
 * Decode what kind of x86 instruction references our target address.
 * Looks backwards from the match position to identify the instruction.
 *
 * Returns a string describing the instruction type.
 */
static const char *decode_instruction_type(const BYTE *text_base, DWORD match_offset)
{
    const BYTE *p;

    /* Check 1 byte before: PUSH imm32 (68 XX XX XX XX) */
    if (match_offset >= 1) {
        p = text_base + match_offset - 1;
        if (*p == 0x68)
            return "PUSH imm32";
    }

    /* Check 1 byte before: MOV reg, imm32 (B8-BF XX XX XX XX) */
    if (match_offset >= 1) {
        p = text_base + match_offset - 1;
        if (*p >= 0xB8 && *p <= 0xBF) {
            static char mov_buf[32];
            sprintf(mov_buf, "MOV %s, imm32",
                (*p == 0xB8) ? "EAX" : (*p == 0xB9) ? "ECX" :
                (*p == 0xBA) ? "EDX" : (*p == 0xBB) ? "EBX" :
                (*p == 0xBC) ? "ESP" : (*p == 0xBD) ? "EBP" :
                (*p == 0xBE) ? "ESI" : "EDI");
            return mov_buf;
        }
    }

    /* Check 2 bytes before: LEA reg, [imm32] (8D /r XX XX XX XX) */
    if (match_offset >= 2) {
        p = text_base + match_offset - 2;
        if (p[0] == 0x8D && (p[1] & 0xC7) == 0x05)
            return "LEA reg, [imm32]";
    }

    /* Check 2 bytes before: MOV [mem], imm32 (C7 05 XX XX XX XX XX XX XX XX) */
    if (match_offset >= 2) {
        p = text_base + match_offset - 2;
        if (p[0] == 0xC7)
            return "MOV [mem], imm32";
    }

    return "unknown";
}

/**
 * Scan the .text section of ge.exe for all references to target string addresses.
 * For each match, log the instruction type and surrounding bytes.
 *
 * This is a brute-force scan — we look for the 4-byte LE address pattern
 * anywhere in .text, which is valid because ge.exe has no ASLR.
 */
static void scan_xrefs(void)
{
    BYTE *text_start = (BYTE *)GE_TEXT_START;
    DWORD text_size  = GE_TEXT_END - GE_TEXT_START;
    int t, total_found = 0;

    log_write("=== XREF SCAN START ===");
    log_write("Scanning .text: 0x%08X - 0x%08X (%u bytes)",
        GE_TEXT_START, GE_TEXT_END, text_size);

    /* Verify memory is readable */
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(text_start, &mbi, sizeof(mbi)) == 0) {
            log_write("XREF SCAN: VirtualQuery failed — cannot read .text");
            return;
        }
        log_write("  .text region: base=%p size=0x%X state=0x%X protect=0x%X",
            mbi.BaseAddress, (DWORD)mbi.RegionSize, mbi.State, mbi.Protect);
    }

    for (t = 0; t < XREF_TARGET_COUNT; t++) {
        DWORD target_addr = g_xref_targets[t].addr;
        const char *label = g_xref_targets[t].label;
        BYTE needle[4];
        DWORD i;
        int found = 0;

        /* Build little-endian needle */
        needle[0] = (BYTE)(target_addr & 0xFF);
        needle[1] = (BYTE)((target_addr >> 8) & 0xFF);
        needle[2] = (BYTE)((target_addr >> 16) & 0xFF);
        needle[3] = (BYTE)((target_addr >> 24) & 0xFF);

        log_write("--- Scanning for \"%s\" (0x%08X) needle=[%02X %02X %02X %02X] ---",
            label, target_addr, needle[0], needle[1], needle[2], needle[3]);

        /* Linear scan through .text */
        for (i = 0; i < text_size - 4; i++) {
            if (text_start[i]   == needle[0] &&
                text_start[i+1] == needle[1] &&
                text_start[i+2] == needle[2] &&
                text_start[i+3] == needle[3])
            {
                DWORD abs_addr = GE_TEXT_START + i;
                const char *insn_type = decode_instruction_type(text_start, i);
                int ctx_before = (i >= 16) ? 16 : (int)i;
                int ctx_after  = (i + 4 + 16 <= text_size) ? 16 : (int)(text_size - i - 4);
                char hex_buf[256];
                int h, hpos = 0;
                BYTE *ctx_start = text_start + i - ctx_before;
                int ctx_total = ctx_before + 4 + ctx_after;

                found++;
                total_found++;

                /* Format context bytes as hex */
                for (h = 0; h < ctx_total && hpos < 240; h++) {
                    if (h == ctx_before)
                        hpos += sprintf(hex_buf + hpos, "[");
                    hpos += sprintf(hex_buf + hpos, "%02X", ctx_start[h]);
                    if (h == ctx_before + 3)
                        hpos += sprintf(hex_buf + hpos, "]");
                    else if (h < ctx_total - 1)
                        hpos += sprintf(hex_buf + hpos, " ");
                }

                log_write("  XREF #%d: \"%s\" at 0x%08X — %s",
                    found, label, abs_addr, insn_type);
                log_write("    context: %s", hex_buf);

                /* For PUSH instructions, check what's pushed before/after (tolua++ pattern) */
                if (i >= 5 && text_start[i-5] == 0x68) {
                    DWORD prev_push = *(DWORD *)(text_start + i - 4);
                    log_write("    prev PUSH: 0x%08X (possible function ptr)", prev_push);
                }
                if (i >= 1 && text_start[i-1] == 0x68) {
                    /* This IS a PUSH of our string. Check next instruction for function ptr push */
                    if (i + 4 < text_size - 5 && text_start[i+4] == 0x68) {
                        DWORD next_push = *(DWORD *)(text_start + i + 5);
                        log_write("    next PUSH: 0x%08X (possible function ptr)", next_push);
                    }
                    if (i + 4 < text_size - 5 && text_start[i+4] == 0xE8) {
                        DWORD rel = *(DWORD *)(text_start + i + 5);
                        DWORD call_target = (GE_TEXT_START + i + 4) + 5 + rel;
                        log_write("    next CALL: 0x%08X (relative)", call_target);
                    }
                }
            }
        }

        log_write("  Found %d xrefs for \"%s\"", found, label);
    }

    log_write("=== XREF SCAN DONE — %d total xrefs found ===", total_found);
}

/* ─── Phase 2: Property Function Callers ─────────────────────── */

/**
 * Call GetPropertyNumber with the resolved function pointer.
 * Returns the property value as a double, or -9999.0 on error.
 */
static double call_get_property(int idSpace, const char *objName, const char *propName)
{
    double result;

    if (!g_fn_get_prop) {
        log_write("call_get_property: function not resolved!");
        return -9999.0;
    }

    log_write("call_get_property(obj=\"%s\", id=%d, prop=\"%s\") @ 0x%08X",
        objName ? objName : "(null)", idSpace, propName,
        (DWORD)(DWORD_PTR)g_fn_get_prop);

    __try {
        /* New signature: double GetPropertyNumber(objName, idSpace, propName) */
        result = g_fn_get_prop(objName, idSpace, propName);
        log_write("  -> result = %f", result);
        return result;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log_write("  -> EXCEPTION 0x%08X!", GetExceptionCode());
        return -9999.0;
    }
}

/**
 * Call SetPropertyNumber with the resolved function pointer.
 * Returns TRUE on success, FALSE on exception.
 */
static BOOL call_set_property(int idSpace, const char *objName, const char *propName, double value)
{
    if (!g_fn_set_prop) {
        log_write("call_set_property: function not resolved!");
        return FALSE;
    }

    log_write("call_set_property(obj=\"%s\", id=%d, prop=\"%s\", val=%f) @ 0x%08X",
        objName ? objName : "(null)", idSpace, propName, value,
        (DWORD)(DWORD_PTR)g_fn_set_prop);

    __try {
        /* New signature: void SetPropertyNumber(objName, idSpace, propName, value) */
        g_fn_set_prop(objName, idSpace, propName, value);
        log_write("  -> OK");
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log_write("  -> EXCEPTION 0x%08X!", GetExceptionCode());
        return FALSE;
    }
}

/* ─── Phase 2: GetPropertyNumber Logging Hook ────────────────── */

/**
 * Inline hook on GetPropertyNumber (0x0089D5FC) to log ALL calls
 * the game makes, capturing (objName, idSpace, propName) and the result.
 *
 * Uses the same 5-byte JMP detour + critical section approach as
 * the send/recv detour hooks.
 */

static BYTE g_getprop_hook_bytes[5];
static CRITICAL_SECTION g_getprop_lock;
static volatile BOOL g_getprop_hooked = FALSE;
static volatile LONG g_getprop_log_count = 0;

static double __cdecl hooked_get_property_number(const char *objName, int idSpace, const char *propName)
{
    double result;
    LONG n = InterlockedIncrement(&g_getprop_log_count);

    /* Log the call */
    log_write("HOOK_GET #%d: obj=\"%s\" idSpace=%d prop=\"%s\"",
        n,
        objName ? objName : "(null)",
        idSpace,
        propName ? propName : "(null)");

    /* Call original: unhook -> call -> rehook (under lock) */
    EnterCriticalSection(&g_getprop_lock);
    inline_unhook((void *)GE_FUNC_GET_PROP_NUM, g_getprop_hook_bytes);
    result = ((fn_GetPropertyNumber)GE_FUNC_GET_PROP_NUM)(objName, idSpace, propName);
    inline_hook((void *)GE_FUNC_GET_PROP_NUM, hooked_get_property_number, g_getprop_hook_bytes);
    LeaveCriticalSection(&g_getprop_lock);

    /* Log result (only if non-zero or interesting) */
    if (result != 0.0) {
        log_write("HOOK_GET #%d: -> %f (obj=\"%s\" prop=\"%s\")", n, result, objName ? objName : "", propName ? propName : "");
    }

    return result;
}

static BOOL install_getprop_hook(void)
{
    if (g_getprop_hooked) {
        log_write("getprop_hook: already installed");
        return TRUE;
    }

    InitializeCriticalSection(&g_getprop_lock);

    if (inline_hook((void *)GE_FUNC_GET_PROP_NUM, hooked_get_property_number, g_getprop_hook_bytes)) {
        g_getprop_hooked = TRUE;
        g_getprop_log_count = 0;
        log_write("getprop_hook: INSTALLED at 0x%08X (orig bytes: %02X %02X %02X %02X %02X)",
            GE_FUNC_GET_PROP_NUM,
            g_getprop_hook_bytes[0], g_getprop_hook_bytes[1],
            g_getprop_hook_bytes[2], g_getprop_hook_bytes[3],
            g_getprop_hook_bytes[4]);
        return TRUE;
    }

    log_write("getprop_hook: FAILED to install");
    DeleteCriticalSection(&g_getprop_lock);
    return FALSE;
}

static void remove_getprop_hook(void)
{
    if (!g_getprop_hooked)
        return;

    inline_unhook((void *)GE_FUNC_GET_PROP_NUM, g_getprop_hook_bytes);
    g_getprop_hooked = FALSE;
    DeleteCriticalSection(&g_getprop_lock);
    log_write("getprop_hook: REMOVED (logged %d calls)", g_getprop_log_count);
}

/* ─── Phase 2: SetPropertyNumber Logging Hook ────────────────── */

static BYTE g_setprop_hook_bytes[5];
static CRITICAL_SECTION g_setprop_lock;
static volatile BOOL g_setprop_hooked = FALSE;
static volatile LONG g_setprop_log_count = 0;

static void __cdecl hooked_set_property_number(const char *objName, int idSpace, const char *propName, double value)
{
    LONG n = InterlockedIncrement(&g_setprop_log_count);

    log_write("HOOK_SET #%d: obj=\"%s\" idSpace=%d prop=\"%s\" value=%f",
        n,
        objName ? objName : "(null)",
        idSpace,
        propName ? propName : "(null)",
        value);

    /* Call original: unhook -> call -> rehook */
    EnterCriticalSection(&g_setprop_lock);
    inline_unhook((void *)GE_FUNC_SET_PROP_NUM, g_setprop_hook_bytes);
    ((fn_SetPropertyNumber)GE_FUNC_SET_PROP_NUM)(objName, idSpace, propName, value);
    inline_hook((void *)GE_FUNC_SET_PROP_NUM, hooked_set_property_number, g_setprop_hook_bytes);
    LeaveCriticalSection(&g_setprop_lock);
}

static BOOL install_setprop_hook(void)
{
    if (g_setprop_hooked) {
        log_write("setprop_hook: already installed");
        return TRUE;
    }

    InitializeCriticalSection(&g_setprop_lock);

    if (inline_hook((void *)GE_FUNC_SET_PROP_NUM, hooked_set_property_number, g_setprop_hook_bytes)) {
        g_setprop_hooked = TRUE;
        g_setprop_log_count = 0;
        log_write("setprop_hook: INSTALLED at 0x%08X (orig bytes: %02X %02X %02X %02X %02X)",
            GE_FUNC_SET_PROP_NUM,
            g_setprop_hook_bytes[0], g_setprop_hook_bytes[1],
            g_setprop_hook_bytes[2], g_setprop_hook_bytes[3],
            g_setprop_hook_bytes[4]);
        return TRUE;
    }

    log_write("setprop_hook: FAILED to install");
    DeleteCriticalSection(&g_setprop_lock);
    return FALSE;
}

static void remove_setprop_hook(void)
{
    if (!g_setprop_hooked)
        return;

    inline_unhook((void *)GE_FUNC_SET_PROP_NUM, g_setprop_hook_bytes);
    g_setprop_hooked = FALSE;
    DeleteCriticalSection(&g_setprop_lock);
    log_write("setprop_hook: REMOVED (logged %d calls)", g_setprop_log_count);
}

/* ─── Phase 3: VTable Spy ────────────────────────────────────── */

/**
 * One-shot code cave at the KeepRange GET call site (0x004FEA4B).
 * When the game reads KeepRange from a character object, we capture:
 *   - ESI = character object pointer
 *   - [ESI] = vtable address
 *   - vtable[0x10] = getter function address
 *   - vtable[0x28] = setter function address
 *
 * Hook replaces: push "KeepRange" (68 70 27 B8 00) with JMP to cave.
 * Cave captures once, then passes through transparently.
 */

static volatile DWORD g_spy_obj_ptr = 0;
static volatile DWORD g_spy_vtable = 0;
static volatile DWORD g_spy_vtable_get = 0;
static volatile DWORD g_spy_vtable_set = 0;
static volatile BOOL  g_spy_armed = FALSE;
static volatile BOOL  g_spy_done = FALSE;
static volatile LONG  g_spy_trigger_count = 0;
static BYTE g_spy_orig_bytes[5];
static BYTE g_spy2_orig_bytes[5];     /* separate saved bytes for xref #2 */
static volatile BOOL g_spy_installed = FALSE;
static volatile int  g_spy_site = 0;  /* which site: 0=none, 1=xref#1, 2=xref#2 */

/* Additional captures for xref #2 (setter — carries a double value) */
static volatile DWORD g_spy_set_val_lo = 0;
static volatile DWORD g_spy_set_val_hi = 0;

/* Logging helper callable from asm */
static void __cdecl spy_log_capture(DWORD obj, DWORD vtable, DWORD get_fn, DWORD set_fn)
{
    log_write("VTABLE_SPY: obj=0x%08X vtable=0x%08X get_fn=0x%08X set_fn=0x%08X",
        obj, vtable, get_fn, set_fn);
}

/**
 * Naked code cave — entered via JMP from 0x004FEA4B.
 * At entry: ESI = character object, stack has &[ebp-4] from previous push.
 */
__declspec(naked) static void __cdecl vtable_spy_cave(void)
{
    __asm {
        /* Save all registers + flags */
        pushad
        pushfd

        /* Always count triggers */
        lock inc g_spy_trigger_count

        /* Only capture when armed */
        cmp g_spy_armed, 1
        jne _spy_skip

        /* Capture object pointer */
        mov g_spy_obj_ptr, esi

        /* Read vtable from [esi] */
        mov eax, [esi]
        mov g_spy_vtable, eax

        /* Read vtable[0x10] = getter function */
        mov ecx, [eax + 0x10]
        mov g_spy_vtable_get, ecx

        /* Read vtable[0x28] = setter function */
        mov edx, [eax + 0x28]
        mov g_spy_vtable_set, edx

        /* Log the capture (safe to call from pushad block) */
        push edx
        push ecx
        push eax
        push esi
        call spy_log_capture
        add esp, 16

        /* Signal done, disarm */
        mov g_spy_armed, 0
        mov g_spy_done, 1

    _spy_skip:
        /* Restore all registers + flags */
        popfd
        popad

        /* Execute original instruction: push 0x00B82770 ("KeepRange") */
        push 0x00B82770

        /* Return to 0x004FEA50 (instruction after the replaced push) */
        push 0x004FEA50
        ret
    }
}

/**
 * Code cave for xref #2 (setter site) — entered via JMP from 0x0050A942.
 *
 * At entry: ESI = character object, EDI = vtable (already loaded!),
 *           [ESP] = double value being SET (8 bytes on stack).
 */
static void __cdecl spy_log_capture2(DWORD obj, DWORD vtable, DWORD get_fn, DWORD set_fn,
                                     DWORD val_lo, DWORD val_hi)
{
    double val;
    memcpy(&val, &val_lo, 4);
    memcpy((char *)&val + 4, &val_hi, 4);
    log_write("VTABLE_SPY(xref2): obj=0x%08X vtable=0x%08X get=0x%08X set=0x%08X set_value=%.6f",
        obj, vtable, get_fn, set_fn, val);
}

__declspec(naked) static void __cdecl vtable_spy_cave2(void)
{
    __asm {
        /* Save all registers + flags */
        pushad
        pushfd

        /* Always count triggers */
        lock inc g_spy_trigger_count

        /* Only capture when armed */
        cmp g_spy_armed, 1
        jne _spy2_skip

        /* At xref #2: ESI = object, EDI = vtable (already loaded before push) */
        mov g_spy_obj_ptr, esi
        mov g_spy_vtable, edi

        /* Read vtable[0x10] = getter function */
        mov eax, [edi + 0x10]
        mov g_spy_vtable_get, eax

        /* Read vtable[0x28] = setter function */
        mov ecx, [edi + 0x28]
        mov g_spy_vtable_set, ecx

        /* Read double from original stack.
         * pushad = 32 bytes, pushfd = 4 bytes → original ESP at [ESP + 36]
         * The double was stored at [original_ESP] by movsd [esp], xmm0 */
        mov edx, [esp + 36]
        mov g_spy_set_val_lo, edx
        mov edx, [esp + 40]
        mov g_spy_set_val_hi, edx

        /* Log the capture */
        push g_spy_set_val_hi
        push g_spy_set_val_lo
        push ecx
        push eax
        push edi
        push esi
        call spy_log_capture2
        add esp, 24

        /* Signal done, disarm */
        mov g_spy_armed, 0
        mov g_spy_done, 1

    _spy2_skip:
        /* Restore all registers + flags */
        popfd
        popad

        /* Execute original instruction: push 0x00B82770 ("KeepRange") */
        push 0x00B82770

        /* Return to 0x0050A947 (instruction after the replaced push) */
        push 0x0050A947
        ret
    }
}

/* Forward declaration — install needs to call remove when switching sites */
static void remove_vtable_spy(void);

static BOOL install_vtable_spy(int site)
{
    DWORD hook_addr;
    BYTE *orig_bytes;
    void *cave;

    if (g_spy_installed) {
        if (g_spy_site == site) {
            log_write("vtable_spy: already installed at site %d, re-arming", site);
            g_spy_done = FALSE;
            g_spy_armed = TRUE;
            return TRUE;
        }
        /* Different site requested — remove old one first */
        remove_vtable_spy();
    }

    /* Select site parameters */
    if (site == 1) {
        hook_addr = GE_KEEPRANGE_SPY_SITE;
        orig_bytes = g_spy_orig_bytes;
        cave = vtable_spy_cave;
    } else if (site == 2) {
        hook_addr = GE_KEEPRANGE_SET_SITE;
        orig_bytes = g_spy2_orig_bytes;
        cave = vtable_spy_cave2;
    } else {
        log_write("vtable_spy: invalid site %d", site);
        return FALSE;
    }

    g_spy_done = FALSE;
    g_spy_armed = TRUE;
    g_spy_trigger_count = 0;
    g_spy_set_val_lo = 0;
    g_spy_set_val_hi = 0;

    if (inline_hook((void *)hook_addr, cave, orig_bytes)) {
        g_spy_installed = TRUE;
        g_spy_site = site;
        log_write("vtable_spy: INSTALLED site %d at 0x%08X (orig: %02X %02X %02X %02X %02X)",
            site, hook_addr,
            orig_bytes[0], orig_bytes[1], orig_bytes[2],
            orig_bytes[3], orig_bytes[4]);
        return TRUE;
    }

    log_write("vtable_spy: FAILED to install at site %d", site);
    return FALSE;
}

static void remove_vtable_spy(void)
{
    DWORD hook_addr;
    BYTE *orig_bytes;

    if (!g_spy_installed)
        return;

    g_spy_armed = FALSE;

    if (g_spy_site == 1) {
        hook_addr = GE_KEEPRANGE_SPY_SITE;
        orig_bytes = g_spy_orig_bytes;
    } else {
        hook_addr = GE_KEEPRANGE_SET_SITE;
        orig_bytes = g_spy2_orig_bytes;
    }

    inline_unhook((void *)hook_addr, orig_bytes);
    g_spy_installed = FALSE;
    log_write("vtable_spy: REMOVED site %d (triggered %d times)", g_spy_site, g_spy_trigger_count);
    g_spy_site = 0;
}

/* ─── Phase 3: VTable GET Hook ───────────────────────────────── */

/**
 * Persistent hook at the KeepRange vtable call site (0x004FEA58).
 * Intercepts every KeepRange property read, logs the result,
 * and optionally overrides the return value.
 *
 * Hook replaces: mov ecx,esi; call [edi+0x10] (8B CE FF 57 10)
 * with JMP to cave.
 *
 * The cave executes the original two instructions, then captures
 * the return value from FPU ST(0).
 */

static BYTE g_vtget_orig_bytes[5];
static volatile BOOL  g_vtget_hooked = FALSE;
static volatile LONG  g_vtget_count = 0;
static volatile DWORD g_vtget_last_obj = 0;
static volatile double g_vtget_last_value = 0.0;
static volatile BOOL   g_vtget_override_active = FALSE;
static volatile double g_vtget_override_value = 0.0;

/* Helper: log a vtable get call (called from asm, cdecl) */
static void __cdecl vtget_log_call(DWORD count, DWORD obj)
{
    /* Only log first 10 and then every 100th to avoid spam */
    if (count <= 10 || (count % 100) == 0) {
        log_write("VTGET #%u: obj=0x%08X value=%f%s",
            count, obj, g_vtget_last_value,
            g_vtget_override_active ? " [OVERRIDE]" : "");
    }
}

/**
 * Naked code cave for vtable GET hook.
 * At entry: ESI = object, EDI = vtable ptr, stack has prop_id on top.
 */
__declspec(naked) static void __cdecl vtable_get_cave(void)
{
    __asm {
        /* Execute original: mov ecx, esi (this = object) */
        mov ecx, esi

        /* Execute original: call [edi+0x10] (vtable GET) */
        /* After call: result double in FPU ST(0), stack cleaned by callee */
        call dword ptr [edi + 0x10]

        /* Now: ST(0) = property value (double), prop_id cleaned from stack */

        /* Save registers (FPU state NOT saved by pushad — that's what we want) */
        pushad
        pushfd

        /* Increment counter */
        lock inc g_vtget_count

        /* Store object pointer */
        mov g_vtget_last_obj, esi

        /* Store FPU value to global (fst = store without popping) */
        fst qword ptr [g_vtget_last_value]

        /* Log the call */
        push esi
        push g_vtget_count
        call vtget_log_call
        add esp, 8

        /* Check if override is active */
        cmp g_vtget_override_active, 1
        jne _vtget_no_override

        /* Replace ST(0) with override value */
        fstp st(0)
        fld qword ptr [g_vtget_override_value]

    _vtget_no_override:
        popfd
        popad

        /* Jump back to 0x004FEA5D (mov eax, [ebp-4]) */
        push 0x004FEA5D
        ret
    }
}

static BOOL install_vtable_get_hook(void)
{
    if (g_vtget_hooked) {
        log_write("vtable_get_hook: already installed");
        return TRUE;
    }

    g_vtget_count = 0;
    g_vtget_last_obj = 0;
    g_vtget_last_value = 0.0;

    if (inline_hook((void *)GE_KEEPRANGE_GET_SITE, vtable_get_cave, g_vtget_orig_bytes)) {
        g_vtget_hooked = TRUE;
        log_write("vtable_get_hook: INSTALLED at 0x%08X (orig: %02X %02X %02X %02X %02X)",
            GE_KEEPRANGE_GET_SITE,
            g_vtget_orig_bytes[0], g_vtget_orig_bytes[1], g_vtget_orig_bytes[2],
            g_vtget_orig_bytes[3], g_vtget_orig_bytes[4]);
        return TRUE;
    }

    log_write("vtable_get_hook: FAILED to install");
    return FALSE;
}

static void remove_vtable_get_hook(void)
{
    if (!g_vtget_hooked)
        return;

    g_vtget_override_active = FALSE;
    inline_unhook((void *)GE_KEEPRANGE_GET_SITE, g_vtget_orig_bytes);
    g_vtget_hooked = FALSE;
    log_write("vtable_get_hook: REMOVED (intercepted %d calls, last_value=%f)",
        g_vtget_count, g_vtget_last_value);
}

/* ─── Phase 2: Command Handler ───────────────────────────────── */

/**
 * Initialize the command shared memory (separate from Phase 1 ctl shmem).
 */
static char g_cmd_shmem_name[64];  /* per-PID shmem name */

static void cmd_shmem_init(void)
{
    /* Per-PID shared memory: "Local\\ge_phantom_cmd_<PID>" */
    sprintf(g_cmd_shmem_name, "Local\\ge_phantom_cmd_%u", GetCurrentProcessId());

    g_cmd_shmem_handle = CreateFileMappingA(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
        0, CMD_SHMEM_SIZE, g_cmd_shmem_name
    );

    if (g_cmd_shmem_handle) {
        g_cmd = (volatile BYTE *)MapViewOfFile(
            g_cmd_shmem_handle, FILE_MAP_ALL_ACCESS,
            0, 0, CMD_SHMEM_SIZE
        );
        if (g_cmd) {
            memset((void *)g_cmd, 0, CMD_SHMEM_SIZE);
            log_write("cmd_shmem: mapped at %p name=\"%s\"", g_cmd, g_cmd_shmem_name);
        }
    } else {
        log_write("cmd_shmem: CreateFileMapping failed (err=%u)", GetLastError());
    }
}

/**
 * Process a single command from the shared memory command interface.
 */
static void process_command(void)
{
    BYTE cmd;
    volatile BYTE *mem = g_cmd;

    if (!mem) return;

    cmd = mem[CMD_OFF_COMMAND];
    if (cmd == CMD_NOP) return;

    /* Echo sequence number — proves THIS DLL handled the command.
     * Detects stale DLLs: if another DLL processes the command,
     * it won't echo the seq, so Python knows the ack is invalid. */
    mem[CMD_OFF_ACK_SEQ] = mem[CMD_OFF_CMD_SEQ];

    /* Mark busy */
    mem[CMD_OFF_STATUS] = CMD_STATUS_BUSY;

    switch (cmd) {
    case CMD_PING:
        log_write("CMD: PING");
        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = 0xDEADBEEF;
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;

    case CMD_SCAN:
        log_write("CMD: SCAN");
        scan_xrefs();
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;

    case CMD_GET_PROP:
    case CMD_SET_PROP:
    case CMD_CHAT:
    case CMD_SYSMSG:
    case CMD_UPDATE_ITEM_TABLE:
    case CMD_HOOK_WNDPROC:
    case CMD_UNHOOK_WNDPROC:
        /* These must run on the main game thread (via hooked_send/recv).
         * Signal the main thread and leave the command in shared memory. */
        log_write("CMD: %s → deferred to main thread",
            cmd == CMD_GET_PROP          ? "GET_PROP" :
            cmd == CMD_SET_PROP          ? "SET_PROP" :
            cmd == CMD_CHAT              ? "CHAT"     :
            cmd == CMD_SYSMSG            ? "SYSMSG"   :
            cmd == CMD_UPDATE_ITEM_TABLE ? "UPDATE_ITEM_TABLE" :
            cmd == CMD_HOOK_WNDPROC      ? "HOOK_WNDPROC" :
            cmd == CMD_UNHOOK_WNDPROC    ? "UNHOOK_WNDPROC" : "?");
        g_mainthread_cmd = cmd;
        /* Don't clear CMD_OFF_COMMAND — main thread will handle it */
        return;

    case CMD_READ_ADDR:
    {
        DWORD addr = *(volatile DWORD *)(mem + CMD_OFF_PARAM1);
        log_write("CMD: READ_ADDR 0x%08X", addr);

        __try {
            DWORD val = *(DWORD *)addr;
            *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = val;
            log_write("  → 0x%08X", val);
            mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            log_write("  → ACCESS VIOLATION!");
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
        }
        break;
    }

    case CMD_SET_FUNC_ADDR:
    {
        DWORD addr = *(volatile DWORD *)(mem + CMD_OFF_PARAM1);
        DWORD which = *(volatile DWORD *)(mem + CMD_OFF_PARAM2);
        log_write("CMD: SET_FUNC_ADDR which=%u addr=0x%08X", which, addr);

        if (which == 0) {
            g_fn_get_prop = (fn_GetPropertyNumber)addr;
            log_write("  → GetPropertyNumber = 0x%08X", addr);
        } else if (which == 1) {
            g_fn_set_prop = (fn_SetPropertyNumber)addr;
            log_write("  → SetPropertyNumber = 0x%08X", addr);
        } else if (which == 2) {
            g_fn_update_item_table = (fn_UpdateItemTable)addr;
            log_write("  → UpdateItemTable = 0x%08X", addr);
        } else {
            log_write("  → unknown which=%u", which);
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
            break;
        }

        /* Return current addresses in result fields */
        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = addr;
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;
    }

    case CMD_FIND_STRING:
    {
        char needle[64];
        DWORD search_start, search_end;
        BYTE *p;
        int needle_len;
        DWORD param2 = *(volatile DWORD *)(mem + CMD_OFF_PARAM2);

        memcpy(needle, (const void *)(mem + CMD_OFF_STR_PARAM), 64);
        needle[63] = '\0';
        needle_len = (int)strlen(needle);

        /* param1 = start addr hint (0 = .rdata default), param2 = nth match (0=first) */
        search_start = *(volatile DWORD *)(mem + CMD_OFF_PARAM1);
        if (search_start == 0) search_start = GE_RDATA_BASE;
        search_end = 0x00C50000;  /* well past .rdata end */

        log_write("CMD: FIND_STRING \"%s\" (len=%d) range=0x%08X-0x%08X nth=%u",
            needle, needle_len, search_start, search_end, param2);

        {
            DWORD match_count = 0;
            DWORD found_addr = 0;

            for (p = (BYTE *)search_start; p < (BYTE *)search_end - needle_len; p++) {
                if (memcmp(p, needle, needle_len) == 0) {
                    DWORD addr = (DWORD)(DWORD_PTR)p;
                    log_write("  FIND: \"%s\" at 0x%08X (match #%u)", needle, addr, match_count);
                    if (match_count == param2) {
                        found_addr = addr;
                    }
                    match_count++;
                }
            }

            *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = found_addr;
            *(volatile DWORD *)(mem + CMD_OFF_PARAM2) = match_count;

            if (found_addr) {
                log_write("  → returning 0x%08X (%u total matches)", found_addr, match_count);
                /* Also write result as string for convenience */
                {
                    char result[96];
                    sprintf(result, "0x%08X (%u matches)", found_addr, match_count);
                    memcpy((void *)(mem + CMD_OFF_STR_RESULT), result, strlen(result) + 1);
                }
                mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
            } else {
                log_write("  → not found (%u partial matches)", match_count);
                mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
            }
        }
        break;
    }

    case CMD_HOOK_GETPROP:
        log_write("CMD: HOOK_GETPROP");
        if (install_getprop_hook()) {
            *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = g_getprop_log_count;
            mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        } else {
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
        }
        break;

    case CMD_UNHOOK_GETPROP:
        log_write("CMD: UNHOOK_GETPROP");
        remove_getprop_hook();
        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = g_getprop_log_count;
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;

    case CMD_HOOK_SETPROP:
        log_write("CMD: HOOK_SETPROP");
        if (install_setprop_hook()) {
            *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = g_setprop_log_count;
            mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        } else {
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
        }
        break;

    case CMD_UNHOOK_SETPROP:
        log_write("CMD: UNHOOK_SETPROP");
        remove_setprop_hook();
        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = g_setprop_log_count;
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;

    /* ── Phase 3: VTable Commands ─────────────────────────── */

    case CMD_VTABLE_SPY:
    {
        int wait_ms;
        int site = (int)*(volatile DWORD *)(mem + CMD_OFF_PARAM1);
        DWORD site_addr;

        if (site == 0) site = 1;  /* default to xref #1 for backward compat */
        site_addr = (site == 2) ? GE_KEEPRANGE_SET_SITE : GE_KEEPRANGE_SPY_SITE;

        log_write("CMD: VTABLE_SPY site=%d — installing one-shot spy at 0x%08X", site, site_addr);

        if (!install_vtable_spy(site)) {
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
            break;
        }

        /* Wait up to 30 seconds for trigger */
        for (wait_ms = 0; wait_ms < 30000 && !g_spy_done; wait_ms += 100) {
            Sleep(100);
        }

        if (g_spy_done) {
            log_write("VTABLE_SPY: CAPTURED site=%d after %d ms (triggers=%d)",
                site, wait_ms, g_spy_trigger_count);
            log_write("  obj_ptr    = 0x%08X", g_spy_obj_ptr);
            log_write("  vtable     = 0x%08X", g_spy_vtable);
            log_write("  vtable_get = 0x%08X (vtable[0x10])", g_spy_vtable_get);
            log_write("  vtable_set = 0x%08X (vtable[0x28])", g_spy_vtable_set);

            if (site == 2) {
                double set_val;
                memcpy(&set_val, (void *)&g_spy_set_val_lo, 4);
                memcpy((char *)&set_val + 4, (void *)&g_spy_set_val_hi, 4);
                log_write("  set_value  = %.6f (lo=0x%08X hi=0x%08X)",
                    set_val, g_spy_set_val_lo, g_spy_set_val_hi);
            }

            /* Write results to shared memory */
            *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = g_spy_obj_ptr;
            *(volatile DWORD *)(mem + CMD_OFF_PARAM1)     = g_spy_vtable_get;
            *(volatile DWORD *)(mem + CMD_OFF_PARAM2)     = g_spy_vtable_set;

            /* Write set_value to f64 result for site 2 */
            if (site == 2) {
                *(volatile DWORD *)(mem + CMD_OFF_RESULT_F64)     = g_spy_set_val_lo;
                *(volatile DWORD *)(mem + CMD_OFF_RESULT_F64 + 4) = g_spy_set_val_hi;
            }

            {
                char result[96];
                if (site == 2) {
                    double sv;
                    memcpy(&sv, (void *)&g_spy_set_val_lo, 4);
                    memcpy((char *)&sv + 4, (void *)&g_spy_set_val_hi, 4);
                    sprintf(result, "obj=0x%08X vt=0x%08X get=0x%08X set=0x%08X val=%.4f",
                        g_spy_obj_ptr, g_spy_vtable, g_spy_vtable_get, g_spy_vtable_set, sv);
                } else {
                    sprintf(result, "obj=0x%08X vt=0x%08X get=0x%08X set=0x%08X",
                        g_spy_obj_ptr, g_spy_vtable, g_spy_vtable_get, g_spy_vtable_set);
                }
                memcpy((void *)(mem + CMD_OFF_STR_RESULT), result, strlen(result) + 1);
            }
            mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        } else {
            log_write("VTABLE_SPY: TIMEOUT site=%d — game did not trigger in 30s (triggers=%d)",
                site, g_spy_trigger_count);
            remove_vtable_spy();
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
        }
        break;
    }

    case CMD_HOOK_VTABLE_GET:
    {
        log_write("CMD: HOOK_VTABLE_GET — hooking vtable call at 0x%08X", GE_KEEPRANGE_GET_SITE);

        /* Remove spy if still installed (they're at adjacent sites) */
        if (g_spy_installed) {
            log_write("  removing spy first...");
            remove_vtable_spy();
        }

        if (install_vtable_get_hook()) {
            *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = 0;
            mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        } else {
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
        }
        break;
    }

    case CMD_UNHOOK_VTABLE_GET:
        log_write("CMD: UNHOOK_VTABLE_GET");
        remove_vtable_get_hook();
        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = g_vtget_count;
        *(volatile double *)(mem + CMD_OFF_RESULT_F64) = g_vtget_last_value;
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;

    case CMD_SET_VTGET_OVERRIDE:
    {
        DWORD active = *(volatile DWORD *)(mem + CMD_OFF_PARAM1);
        double val   = *(volatile double *)(mem + CMD_OFF_RESULT_F64);

        if (active) {
            g_vtget_override_value = val;
            g_vtget_override_active = TRUE;
            log_write("CMD: SET_VTGET_OVERRIDE ON value=%f", val);
        } else {
            g_vtget_override_active = FALSE;
            log_write("CMD: SET_VTGET_OVERRIDE OFF");
        }
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;
    }

    case CMD_VTGET_STATUS:
    {
        log_write("CMD: VTGET_STATUS count=%d last_obj=0x%08X last_val=%f override=%s",
            g_vtget_count, g_vtget_last_obj, g_vtget_last_value,
            g_vtget_override_active ? "ON" : "OFF");

        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = g_vtget_count;
        *(volatile double *)(mem + CMD_OFF_RESULT_F64) = g_vtget_last_value;
        *(volatile DWORD *)(mem + CMD_OFF_PARAM1)      = g_vtget_last_obj;
        *(volatile DWORD *)(mem + CMD_OFF_PARAM2)      = g_vtget_override_active ? 1 : 0;
        {
            char result[96];
            sprintf(result, "count=%d obj=0x%08X val=%f ovr=%s",
                g_vtget_count, g_vtget_last_obj, g_vtget_last_value,
                g_vtget_override_active ? "ON" : "OFF");
            memcpy((void *)(mem + CMD_OFF_STR_RESULT), result, strlen(result) + 1);
        }
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;
    }

    /* ── Phase 5: Memory Dump & Xref Scanner ─────────────── */

    case CMD_DUMP_MEM:
    {
        DWORD addr = *(volatile DWORD *)(mem + CMD_OFF_PARAM1);
        DWORD count = *(volatile DWORD *)(mem + CMD_OFF_PARAM2);
        char hex_buf[96];
        int i, pos = 0;

        if (count == 0) count = 32;    /* default: 32 bytes */
        if (count > 44) count = 44;    /* max: 44 bytes (88 hex chars + 7 spaces = 95 < 96) */

        log_write("CMD: DUMP_MEM addr=0x%08X count=%u", addr, count);

        __try {
            BYTE *src = (BYTE *)addr;
            for (i = 0; i < (int)count && pos < 94; i++) {
                if (i > 0 && (i % 8) == 0) {
                    hex_buf[pos++] = ' ';
                }
                pos += sprintf(hex_buf + pos, "%02X", src[i]);
            }
            hex_buf[pos] = '\0';

            log_write("  [0x%08X] %s", addr, hex_buf);

            memcpy((void *)(mem + CMD_OFF_STR_RESULT), hex_buf, pos + 1);
            *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = count;
            mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            log_write("  → ACCESS VIOLATION at 0x%08X!", addr);
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
        }
        break;
    }

    case CMD_SCAN_XREF_STR:
    {
        char needle[64];
        BYTE addr_needle[4];
        BYTE *text_start = (BYTE *)GE_TEXT_START;
        DWORD text_size  = GE_TEXT_END - GE_TEXT_START;
        DWORD string_addr = 0;
        BYTE *p;
        int needle_len;
        int xref_count = 0;
        char result_buf[96];
        int rpos = 0;

        memcpy(needle, (const void *)(mem + CMD_OFF_STR_PARAM), 64);
        needle[63] = '\0';
        needle_len = (int)strlen(needle);

        log_write("CMD: SCAN_XREF_STR \"%s\"", needle);

        /* Step 1: Find string in .rdata */
        {
            BYTE *search_start = (BYTE *)GE_RDATA_BASE;
            BYTE *search_end   = (BYTE *)0x00C50000;

            for (p = search_start; p < search_end - needle_len; p++) {
                if (memcmp(p, needle, needle_len + 1) == 0) {  /* +1 to match null terminator */
                    string_addr = (DWORD)(DWORD_PTR)p;
                    log_write("  string \"%s\" found at 0x%08X", needle, string_addr);
                    break;
                }
            }
        }

        if (!string_addr) {
            log_write("  string \"%s\" NOT FOUND in .rdata", needle);
            sprintf(result_buf, "string not found");
            memcpy((void *)(mem + CMD_OFF_STR_RESULT), result_buf, strlen(result_buf) + 1);
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
            break;
        }

        /* Step 2: Build LE needle from string address */
        addr_needle[0] = (BYTE)(string_addr & 0xFF);
        addr_needle[1] = (BYTE)((string_addr >> 8) & 0xFF);
        addr_needle[2] = (BYTE)((string_addr >> 16) & 0xFF);
        addr_needle[3] = (BYTE)((string_addr >> 24) & 0xFF);

        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = string_addr;

        /* Step 3: Scan .text for xrefs */
        {
            DWORD first_xref = 0;
            DWORD first_callback = 0;
            DWORD i;

            for (i = 0; i < text_size - 4; i++) {
                if (text_start[i]   == addr_needle[0] &&
                    text_start[i+1] == addr_needle[1] &&
                    text_start[i+2] == addr_needle[2] &&
                    text_start[i+3] == addr_needle[3])
                {
                    DWORD xref_addr = GE_TEXT_START + i;
                    xref_count++;

                    /* Check if it's a PUSH imm32 (tolua registration pattern) */
                    if (i >= 1 && text_start[i-1] == 0x68) {
                        log_write("  XREF #%d: PUSH 0x%08X at 0x%08X",
                            xref_count, string_addr, xref_addr - 1);

                        if (!first_xref) first_xref = xref_addr - 1;

                        /* Check for preceding PUSH (callback address in tolua pattern):
                         * PUSH callback ; PUSH "FuncName" ; CALL register_func */
                        if (i >= 6 && text_start[i-6] == 0x68) {
                            DWORD callback = *(DWORD *)(text_start + i - 5);
                            log_write("    prev PUSH: 0x%08X (probable callback)", callback);
                            if (!first_callback) first_callback = callback;
                        }
                    } else {
                        const char *insn = decode_instruction_type(text_start, i);
                        log_write("  XREF #%d: %s at 0x%08X", xref_count, insn, xref_addr);
                        if (!first_xref) first_xref = xref_addr;
                    }
                }
            }

            log_write("  total xrefs for \"%s\": %d", needle, xref_count);

            /* Write results */
            *(volatile DWORD *)(mem + CMD_OFF_PARAM1) = first_xref;
            *(volatile DWORD *)(mem + CMD_OFF_PARAM2) = first_callback;

            rpos = sprintf(result_buf, "str=0x%08X xrefs=%d", string_addr, xref_count);
            if (first_xref)
                rpos += sprintf(result_buf + rpos, " xref1=0x%08X", first_xref);
            if (first_callback)
                rpos += sprintf(result_buf + rpos, " cb=0x%08X", first_callback);

            memcpy((void *)(mem + CMD_OFF_STR_RESULT), result_buf, rpos + 1);
        }

        mem[CMD_OFF_STATUS] = (xref_count > 0) ? CMD_STATUS_DONE : CMD_STATUS_ERROR;
        break;
    }

    /* ── Phase 6: Keyboard Input Discovery ──────────────── */
    /* note: CMD_HOOK_WNDPROC / CMD_UNHOOK_WNDPROC are deferred to main thread above */

    case CMD_CHECK_RAW_INPUT:
    {
        int found;
        log_write("CMD: CHECK_RAW_INPUT — scanning ge.exe IAT...");
        found = check_raw_input_imports();
        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = (DWORD)found;

        {
            char buf[96];
            sprintf(buf, "raw_input_iat=%d", found);
            memcpy((void *)(mem + CMD_OFF_STR_RESULT), buf, strlen(buf) + 1);
        }

        log_write("  -> Raw Input imports found: %d", found);
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;
    }

    case CMD_WNDPROC_STATUS:
    {
        char buf[96];
        LONG total = g_wnd_keydown + g_wnd_keyup + g_wnd_char +
                     g_wnd_syskeydown + g_wnd_syskeyup +
                     g_wnd_input + g_wnd_hotkey + g_wnd_other_kb;

        /* Format: "hooked=1 KD:5 KU:3 CH:2 SKD:0 SKU:0 IN:0 HK:0 OT:0" */
        sprintf(buf, "hooked=%d KD:%d KU:%d CH:%d SKD:%d SKU:%d IN:%d HK:%d OT:%d",
                g_wndproc_hooked ? 1 : 0,
                (int)g_wnd_keydown, (int)g_wnd_keyup, (int)g_wnd_char,
                (int)g_wnd_syskeydown, (int)g_wnd_syskeyup,
                (int)g_wnd_input, (int)g_wnd_hotkey, (int)g_wnd_other_kb);

        memcpy((void *)(mem + CMD_OFF_STR_RESULT), buf, strlen(buf) + 1);
        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = (DWORD)total;

        /* Also log last 5 messages from ring buffer */
        {
            LONG idx = g_wndproc_log_idx;
            int i, start = (idx > 5) ? (int)(idx - 5) : 0;
            for (i = start; i < (int)idx && i < start + 5; i++) {
                WndProcLogEntry *e = &g_wndproc_log[i % WNDPROC_LOG_SIZE];
                log_write("  recent[%d]: %s(0x%04X) wP=0x%04X lP=0x%08X t=%u",
                          i, kb_msg_name(e->msg), e->msg, e->wParam, e->lParam, e->tick);
            }
        }

        log_write("CMD: WNDPROC_STATUS -> %s (total=%d)", buf, (int)total);
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;
    }

    case CMD_KB_DIAG:
    {
        /*
         * Full keyboard input diagnostic:
         * 1. Check which DLLs are loaded (dinput8, dinput, user32)
         * 2. Install API hooks if not already active
         * 3. Report call counts for GetKeyState / GetAsyncKeyState
         */
        HMODULE hDI8   = GetModuleHandleA("dinput8.dll");
        HMODULE hDI    = GetModuleHandleA("dinput.dll");
        HMODULE hUser32 = GetModuleHandleA("user32.dll");
        char buf[96];

        log_write("CMD: KB_DIAG — Full keyboard input diagnostic");
        log_write("  dinput8.dll  = %p %s", hDI8,  hDI8  ? "LOADED" : "not loaded");
        log_write("  dinput.dll   = %p %s", hDI,   hDI   ? "LOADED" : "not loaded");
        log_write("  user32.dll   = %p %s", hUser32, hUser32 ? "LOADED" : "not loaded");

        /* Install hooks if not yet */
        if (!g_keystate_hooked || !g_asynckeystate_hooked) {
            install_keystate_hook();
        }

        log_write("  GetKeyState hook:      %s (total=%d, faked=%d)",
                  g_keystate_hooked ? "ON" : "OFF",
                  (int)g_keystate_total_calls, (int)g_keystate_hook_count);
        log_write("  GetAsyncKeyState hook: %s (total=%d, faked=%d)",
                  g_asynckeystate_hooked ? "ON" : "OFF",
                  (int)g_asynckeystate_total_calls, (int)g_asynckeystate_hook_count);

        sprintf(buf, "DI8:%s GKS:%d/%d GAKS:%d/%d",
                hDI8 ? "YES" : "NO",
                (int)g_keystate_hook_count, (int)g_keystate_total_calls,
                (int)g_asynckeystate_hook_count, (int)g_asynckeystate_total_calls);

        memcpy((void *)(mem + CMD_OFF_STR_RESULT), buf, strlen(buf) + 1);
        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = (hDI8 ? 1 : 0);
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;
    }

    /* ── Phase 5: Keyboard Input ─────────────────────────── */

    case CMD_SEND_KEY:
    {
        DWORD vk    = *(volatile DWORD *)(mem + CMD_OFF_PARAM1);
        DWORD flags = *(volatile DWORD *)(mem + CMD_OFF_PARAM2);
        BYTE scan   = (BYTE)MapVirtualKey(vk, 0);
        HWND hwnd   = find_game_window();
        HWND prev_fg = GetForegroundWindow();
        BOOL need_focus = hwnd && (prev_fg != hwnd);

        if (vk >= 256) {
            log_write("CMD: SEND_KEY — invalid vk=0x%X", vk);
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
            break;
        }

        log_write("CMD: SEND_KEY vk=0x%02X scan=0x%02X flags=%u hwnd=%p fg=%p (poll thread)",
                   vk, scan, flags, hwnd, prev_fg);

        {
            /* flags 0/1/2: keybd_event approach (proven working, needs focus) */
            if (need_focus) {
                SetForegroundWindow(hwnd);
                Sleep(15);
                log_write("  -> SetForegroundWindow to game (was %p)", prev_fg);
            }

            if (flags == 0 || flags == 1) {
                keybd_event((BYTE)vk, scan, 0, 0);
                log_write("  -> keybd_event DOWN");
            }
            if (flags == 0) {
                Sleep(g_key_hold_ms);
                keybd_event((BYTE)vk, scan, KEYEVENTF_KEYUP, 0);
                log_write("  -> keybd_event UP");
            }
            if (flags == 2) {
                keybd_event((BYTE)vk, scan, KEYEVENTF_KEYUP, 0);
                log_write("  -> keybd_event UP");
            }

            if (need_focus && prev_fg) {
                Sleep(10);
                SetForegroundWindow(prev_fg);
                log_write("  -> restored foreground to %p", prev_fg);
            }
        }

        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;
    }

    case CMD_SEND_KEYS:
    {
        char seq[64];
        DWORD delay_ms = *(volatile DWORD *)(mem + CMD_OFF_PARAM1);
        HWND hwnd = find_game_window();
        HWND prev_fg = GetForegroundWindow();
        BOOL need_focus = hwnd && (prev_fg != hwnd);
        int i, sent = 0;

        memcpy(seq, (const void *)(mem + CMD_OFF_STR_PARAM), 64);
        seq[63] = '\0';

        if (delay_ms == 0) delay_ms = 80;  /* default 80ms between keys */

        log_write("CMD: SEND_KEYS seq=\"%s\" delay=%u (keybd_event)", seq, delay_ms);

        if (need_focus) {
            SetForegroundWindow(hwnd);
            Sleep(15);
            log_write("  -> SetForegroundWindow to game (was %p)", prev_fg);
        }

        for (i = 0; seq[i] != '\0'; i++) {
            BYTE vk;
            BYTE scan;
            char ch = seq[i];

            /* Convert character to virtual key code */
            if (ch >= 'a' && ch <= 'z')
                vk = (BYTE)(ch - 'a' + 'A');  /* VK_A..VK_Z = 0x41..0x5A */
            else if (ch >= 'A' && ch <= 'Z')
                vk = (BYTE)ch;
            else if (ch >= '0' && ch <= '9')
                vk = (BYTE)ch;  /* VK_0..VK_9 = 0x30..0x39 */
            else if (ch == ' ')
                vk = VK_SPACE;
            else if (ch == '\t')
                vk = VK_TAB;
            else if (ch == '\n' || ch == '\r')
                vk = VK_RETURN;
            else {
                /* Try VkKeyScan for other characters */
                SHORT vks = VkKeyScanA(ch);
                if (vks == -1) continue;
                vk = (BYTE)(vks & 0xFF);
            }

            /* Key tap via keybd_event — proven working method */
            scan = (BYTE)MapVirtualKey(vk, 0);
            keybd_event(vk, scan, 0, 0);
            Sleep(g_key_hold_ms);
            keybd_event(vk, scan, KEYEVENTF_KEYUP, 0);
            sent++;

            /* Inter-key delay */
            Sleep(delay_ms);
        }

        if (need_focus && prev_fg) {
            Sleep(10);
            SetForegroundWindow(prev_fg);
            log_write("  -> restored foreground to %p", prev_fg);
        }

        log_write("  -> sent %d keys (keybd_event)", sent);
        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = sent;
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;
    }

    case CMD_KEY_COMBO:
    {
        DWORD vk   = *(volatile DWORD *)(mem + CMD_OFF_PARAM1);
        DWORD mods = *(volatile DWORD *)(mem + CMD_OFF_PARAM2);

        if (vk >= 256) {
            log_write("CMD: KEY_COMBO — invalid vk=0x%X", vk);
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
            break;
        }

        log_write("CMD: KEY_COMBO vk=0x%02X mods=0x%02X (ctrl=%d shift=%d alt=%d)",
                   vk, mods, mods & 1, (mods >> 1) & 1, (mods >> 2) & 1);
        send_key_combo((BYTE)vk, (BYTE)mods);
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;
    }

    /* ── Bot Control Commands ──────────────────────────── */

    case CMD_BOT_STATUS:
    {
        char buf[96];
        int active_skills = 0, active_items = 0;
        int c, s;

        for (c = 0; c < 3; c++)
            for (s = 0; s < 6; s++)
                if (g_bot.skill[c][s].interval_ms > 0) active_skills++;
        for (s = 0; s < 12; s++)
            if (g_bot.item[s].interval_ms > 0) active_items++;

        sprintf(buf, "en=%d pick=%d/%u atk=%d/%u skills=%d items=%d",
                g_bot.enabled ? 1 : 0,
                g_bot.auto_pick ? 1 : 0, g_bot.pick_interval_ms,
                g_bot.auto_attack ? 1 : 0, g_bot.attack_interval_ms,
                active_skills, active_items);

        memcpy((void *)(mem + CMD_OFF_STR_RESULT), buf, strlen(buf) + 1);
        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = g_bot.enabled ? 1 : 0;
        log_write("CMD: BOT_STATUS -> %s", buf);
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;
    }

    case CMD_BOT_TOGGLE:
    {
        DWORD feature = *(volatile DWORD *)(mem + CMD_OFF_PARAM1);
        DWORD value   = *(volatile DWORD *)(mem + CMD_OFF_PARAM2);  /* 0=off, 1=on, 0xFFFFFFFF=toggle */

        switch (feature) {
        case 0: /* master */
            g_bot.enabled = (value == 0xFFFFFFFF) ? !g_bot.enabled : (BOOL)value;
            log_write("CMD: BOT_TOGGLE master=%d", g_bot.enabled);
            {
                char m[32]; sprintf(m, "[Bot] Master: %s", g_bot.enabled ? "ON" : "OFF");
                safe_sysmsg(m);
            }
            break;
        case 1: /* auto_pick */
            g_bot.auto_pick = (value == 0xFFFFFFFF) ? !g_bot.auto_pick : (BOOL)value;
            if (g_bot.auto_pick && g_bot.pick_interval_ms == 0) g_bot.pick_interval_ms = 500;
            g_bot.pick_last_tick = GetTickCount();
            log_write("CMD: BOT_TOGGLE pick=%d interval=%u", g_bot.auto_pick, g_bot.pick_interval_ms);
            break;
        case 2: /* auto_attack */
            g_bot.auto_attack = (value == 0xFFFFFFFF) ? !g_bot.auto_attack : (BOOL)value;
            if (g_bot.auto_attack && g_bot.attack_interval_ms == 0) g_bot.attack_interval_ms = 2000;
            g_bot.attack_last_tick = GetTickCount();
            log_write("CMD: BOT_TOGGLE attack=%d interval=%u", g_bot.auto_attack, g_bot.attack_interval_ms);
            break;
        default:
            log_write("CMD: BOT_TOGGLE unknown feature=%u", feature);
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
            goto bot_toggle_done;
        }
        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = g_bot.enabled ? 1 : 0;
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
    bot_toggle_done:
        break;
    }

    case CMD_BOT_SET_TIMER:
    {
        DWORD timer_id    = *(volatile DWORD *)(mem + CMD_OFF_PARAM1);
        DWORD interval_ms = *(volatile DWORD *)(mem + CMD_OFF_PARAM2);
        DWORD now = GetTickCount();

        /*
         * Timer ID encoding:
         *   0 = pick_interval
         *   1 = attack_interval
         *   0x10-0x15 = PC1 skills (char 0, skill 0-5)
         *   0x20-0x25 = PC2 skills (char 1, skill 0-5)
         *   0x30-0x35 = PC3 skills (char 2, skill 0-5)
         *   0x40-0x4B = items (slot 0-11)
         */
        if (timer_id == 0) {
            g_bot.pick_interval_ms = interval_ms;
            g_bot.pick_last_tick = now;
            log_write("CMD: BOT_SET_TIMER pick=%u", interval_ms);
        } else if (timer_id == 1) {
            g_bot.attack_interval_ms = interval_ms;
            g_bot.attack_last_tick = now;
            log_write("CMD: BOT_SET_TIMER attack=%u", interval_ms);
        } else if (timer_id >= 0x10 && timer_id <= 0x35) {
            int ch = (timer_id >> 4) - 1;    /* 0x10→0, 0x20→1, 0x30→2 */
            int sk = timer_id & 0x0F;
            if (ch >= 0 && ch < 3 && sk < 6) {
                g_bot.skill[ch][sk].interval_ms = interval_ms;
                g_bot.skill[ch][sk].last_tick = now;
                log_write("CMD: BOT_SET_TIMER skill[%d][%d]=%u", ch, sk, interval_ms);
            } else {
                log_write("CMD: BOT_SET_TIMER invalid skill id=0x%02X", timer_id);
                mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
                break;
            }
        } else if (timer_id >= 0x40 && timer_id <= 0x4B) {
            int slot = timer_id - 0x40;
            g_bot.item[slot].interval_ms = interval_ms;
            g_bot.item[slot].last_tick = now;
            log_write("CMD: BOT_SET_TIMER item[%d]=%u", slot, interval_ms);
        } else {
            log_write("CMD: BOT_SET_TIMER unknown id=0x%02X", timer_id);
            mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
            break;
        }

        *(volatile DWORD *)(mem + CMD_OFF_RESULT_I32) = interval_ms;
        mem[CMD_OFF_STATUS] = CMD_STATUS_DONE;
        break;
    }

    default:
        log_write("CMD: UNKNOWN 0x%02X", cmd);
        mem[CMD_OFF_STATUS] = CMD_STATUS_ERROR;
        break;
    }

    /* Clear command — ready for next */
    mem[CMD_OFF_COMMAND] = CMD_NOP;
}

/**
 * Background thread: polls command shared memory every 50ms.
 */
static volatile BOOL g_cmd_thread_running = FALSE;

static DWORD WINAPI cmd_poll_thread(LPVOID param)
{
    (void)param;
    log_write("cmd_poll_thread: started");

    while (g_cmd_thread_running) {
        /* Auto-install WndProc hook on first tick (deferred from DllMain) */
        if (g_auto_wndproc_pending) {
            HWND hwnd = find_game_window();
            if (hwnd) {
                g_auto_wndproc_pending = FALSE;
                /* Defer to main thread */
                g_mainthread_cmd = CMD_HOOK_WNDPROC;
                log_write("cmd_poll_thread: auto-installing WndProc hook");
            }
        }

        process_command();
        bot_tick();
        Sleep(50);
    }

    log_write("cmd_poll_thread: stopped");
    return 0;
}

static HANDLE g_cmd_thread = NULL;

static void cmd_start(void)
{
    g_cmd_thread_running = TRUE;
    g_cmd_thread = CreateThread(NULL, 0, cmd_poll_thread, NULL, 0, NULL);
    if (g_cmd_thread) {
        log_write("cmd: poll thread started");
    } else {
        log_write("cmd: FAILED to create poll thread");
    }
}

static void cmd_stop(void)
{
    if (g_cmd_thread) {
        g_cmd_thread_running = FALSE;
        WaitForSingleObject(g_cmd_thread, 2000);
        CloseHandle(g_cmd_thread);
        g_cmd_thread = NULL;
    }
}

/* ─── Phase 2: Manual Address Setup ──────────────────────────── */

/**
 * Set function addresses manually (after analyzing xref scan results).
 * Called via CMD_SET_PROP with special idSpace = 0xFFFF to set addresses.
 *
 * For now, addresses are logged by scan — user reads log, then sets
 * via range_control.py which writes addresses to shared memory.
 */
static void set_function_addresses(DWORD get_addr, DWORD set_addr)
{
    if (get_addr) {
        g_fn_get_prop = (fn_GetPropertyNumber)get_addr;
        log_write("set_function_addresses: GetPropertyNumber = 0x%08X", get_addr);
    }
    if (set_addr) {
        g_fn_set_prop = (fn_SetPropertyNumber)set_addr;
        log_write("set_function_addresses: SetPropertyNumber = 0x%08X", set_addr);
    }
}

/* ─── DLL Entry Point ─────────────────────────────────────────── */

static BOOL g_using_detour = FALSE;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        /* Debug log first — everything else depends on this */
        log_init(hModule);
        log_write("=== phantom_hook DLL_PROCESS_ATTACH ===");
        log_write("DLL base=%p, ge.exe base=%p", hModule, GetModuleHandleA(NULL));

        InitializeCriticalSection(&g_pipe_lock);

        /* Initialize shared memory for control flags */
        shmem_init();
        log_write("shmem: ctl=%p flags=0x%02X", g_ctl, g_ctl ? g_ctl[0] : 0);

        /* Initialize named pipe */
        pipe_init();

        /* Try IAT hook first (cleanest approach) */
        if (!install_hooks()) {
            log_write("IAT hook failed, trying inline detour...");
            /* IAT hook failed — fall back to inline detour */
            if (install_detour_hooks()) {
                g_using_detour = TRUE;
                log_write("using DETOUR hooks");
            } else {
                /* Both methods failed */
                log_write("FATAL: All hook methods failed!");
                log_close();
                return FALSE;  /* Refuse to load */
            }
        } else {
            log_write("using IAT hooks");
        }

        log_write("=== hooks installed, ready ===");

        /* Phase 2: Initialize command interface */
        cmd_shmem_init();

        /* Phase 2: Run xref scan immediately on attach */
        log_write("Phase 2: running initial xref scan...");
        scan_xrefs();

        /* Phase 2: Set resolved function addresses */
        set_function_addresses(GE_FUNC_GET_PROP_NUM, GE_FUNC_SET_PROP_NUM);

        /* Phase 2: Start command poll thread */
        cmd_start();

        /* Initialize bot defaults */
        g_bot.pick_interval_ms = 500;
        g_bot.attack_interval_ms = 2000;

        log_write("=== Phase 2 initialized (PID=%u shmem=%s) ===",
                  GetCurrentProcessId(), g_cmd_shmem_name);
        break;

    case DLL_PROCESS_DETACH:
        log_write("=== DLL_PROCESS_DETACH === send=%d recv=%d",
            g_send_count, g_recv_count);

        /* Phase 2: Stop command thread */
        cmd_stop();

        /* Phase 6: Remove hooks if active */
        remove_di_keyboard_hook();
        remove_wndproc_hook();
        remove_keystate_hook();

        /* Phase 3: Remove vtable hooks if active */
        remove_vtable_get_hook();
        remove_vtable_spy();

        /* Phase 2: Remove hooks if active */
        remove_getprop_hook();
        remove_setprop_hook();

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

        /* Clean up shared memory (Phase 1) */
        if (g_ctl) {
            UnmapViewOfFile((void *)g_ctl);
            g_ctl = NULL;
        }
        if (g_shmem_handle) {
            CloseHandle(g_shmem_handle);
            g_shmem_handle = NULL;
        }

        /* Clean up shared memory (Phase 2) */
        if (g_cmd) {
            UnmapViewOfFile((void *)g_cmd);
            g_cmd = NULL;
        }
        if (g_cmd_shmem_handle) {
            CloseHandle(g_cmd_shmem_handle);
            g_cmd_shmem_handle = NULL;
        }

        DeleteCriticalSection(&g_pipe_lock);
        log_write("cleanup done, goodbye");
        log_close();
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
