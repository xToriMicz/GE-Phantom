"""
GE_Phantom — DLL Injector

Injects a DLL into ge.exe using CreateRemoteThread + LoadLibraryA.
Pure ctypes — no external dependencies.

Usage:
  python tools/dll_injector.py inject                          # Inject phantom_hook.dll
  python tools/dll_injector.py inject --dll path/to/custom.dll # Inject custom DLL
  python tools/dll_injector.py list                            # List DLLs loaded in ge.exe
  python tools/dll_injector.py eject --dll phantom_hook.dll    # Unload DLL from ge.exe

Requires: Run as Administrator
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys
from pathlib import Path

# ── Win32 Constants ────────────────────────────────────────────

PROCESS_ALL_ACCESS     = 0x001FFFFF
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ        = 0x0010

MEM_COMMIT             = 0x00001000
MEM_RESERVE            = 0x00002000
MEM_RELEASE            = 0x00008000
PAGE_READWRITE         = 0x04

CREATE_SUSPENDED       = 0x00000004

INFINITE               = 0xFFFFFFFF
TH32CS_SNAPPROCESS     = 0x02
TH32CS_SNAPMODULE      = 0x08
TH32CS_SNAPMODULE32    = 0x10
MAX_PATH               = 260
MAX_MODULE_NAME32      = 255

GE_PROCESS_NAME        = "ge.exe"
DEFAULT_DLL            = "phantom_hook.dll"

# ── Structures ─────────────────────────────────────────────────

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wt.DWORD),
        ("cntUsage",            wt.DWORD),
        ("th32ProcessID",       wt.DWORD),
        ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID",        wt.DWORD),
        ("cntThreads",          wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             wt.DWORD),
        ("szExeFile",           ctypes.c_char * MAX_PATH),
    ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",          wt.DWORD),
        ("th32ModuleID",    wt.DWORD),
        ("th32ProcessID",   wt.DWORD),
        ("GlblcntUsage",    wt.DWORD),
        ("ProccntUsage",    wt.DWORD),
        ("modBaseAddr",     ctypes.c_void_p),
        ("modBaseSize",     wt.DWORD),
        ("hModule",         ctypes.c_void_p),
        ("szModule",        ctypes.c_char * (MAX_MODULE_NAME32 + 1)),
        ("szExePath",       ctypes.c_char * MAX_PATH),
    ]


class STARTUPINFOA(ctypes.Structure):
    _fields_ = [
        ("cb",              wt.DWORD),
        ("lpReserved",      ctypes.c_char_p),
        ("lpDesktop",       ctypes.c_char_p),
        ("lpTitle",         ctypes.c_char_p),
        ("dwX",             wt.DWORD),
        ("dwY",             wt.DWORD),
        ("dwXSize",         wt.DWORD),
        ("dwYSize",         wt.DWORD),
        ("dwXCountChars",   wt.DWORD),
        ("dwYCountChars",   wt.DWORD),
        ("dwFillAttribute", wt.DWORD),
        ("dwFlags",         wt.DWORD),
        ("wShowWindow",     wt.WORD),
        ("cbReserved2",     wt.WORD),
        ("lpReserved2",     ctypes.c_void_p),
        ("hStdInput",       wt.HANDLE),
        ("hStdOutput",      wt.HANDLE),
        ("hStdError",       wt.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess",    wt.HANDLE),
        ("hThread",     wt.HANDLE),
        ("dwProcessId", wt.DWORD),
        ("dwThreadId",  wt.DWORD),
    ]

# ── Win32 API Handles ─────────────────────────────────────────

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi    = ctypes.WinDLL("psapi", use_last_error=True)
ntdll    = ctypes.WinDLL("ntdll", use_last_error=True)

# ── Helper Functions ───────────────────────────────────────────

def find_ge_pid() -> int | None:
    """Find ge.exe process ID using CreateToolhelp32Snapshot."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        raise OSError(f"CreateToolhelp32Snapshot failed: {ctypes.get_last_error()}")

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    found_pid = None

    if kernel32.Process32First(snap, ctypes.byref(entry)):
        while True:
            name = entry.szExeFile.decode("utf-8", errors="ignore").lower()
            if name == GE_PROCESS_NAME:
                found_pid = entry.th32ProcessID
                break
            if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                break

    kernel32.CloseHandle(snap)
    return found_pid


def find_ge_pids() -> list[tuple[int, str]]:
    """Find all ge.exe process IDs."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        raise OSError(f"CreateToolhelp32Snapshot failed: {ctypes.get_last_error()}")

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    results = []

    if kernel32.Process32First(snap, ctypes.byref(entry)):
        while True:
            name = entry.szExeFile.decode("utf-8", errors="ignore").lower()
            if name == GE_PROCESS_NAME:
                results.append((entry.th32ProcessID, name))
            if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                break

    kernel32.CloseHandle(snap)
    return results


def list_modules(pid: int) -> list[tuple[str, int, int]]:
    """List all modules loaded in a process. Returns [(name, base, size)]."""
    snap = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid
    )
    if snap == -1:
        err = ctypes.get_last_error()
        raise OSError(
            f"CreateToolhelp32Snapshot(SNAPMODULE) failed: error {err}\n"
            "Make sure you're running as Administrator."
        )

    entry = MODULEENTRY32()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32)
    modules = []

    if kernel32.Module32First(snap, ctypes.byref(entry)):
        while True:
            name = entry.szModule.decode("utf-8", errors="ignore")
            base = entry.modBaseAddr or 0
            size = entry.modBaseSize
            modules.append((name, base, size))
            if not kernel32.Module32Next(snap, ctypes.byref(entry)):
                break

    kernel32.CloseHandle(snap)
    return modules


def is_dll_loaded(pid: int, dll_name: str) -> bool:
    """Check if a DLL is already loaded in the target process."""
    try:
        modules = list_modules(pid)
        dll_lower = dll_name.lower()
        return any(m[0].lower() == dll_lower for m in modules)
    except OSError:
        return False


def resolve_dll_path(dll_arg: str) -> str:
    """Resolve DLL path — check phantom_hook/ subdirectory first."""
    # Absolute path
    if os.path.isabs(dll_arg) and os.path.isfile(dll_arg):
        return os.path.abspath(dll_arg)

    # Relative to CWD
    if os.path.isfile(dll_arg):
        return os.path.abspath(dll_arg)

    # Check phantom_hook/ subdirectory (common case)
    tools_dir = Path(__file__).parent
    hook_dir = tools_dir / "phantom_hook"
    candidate = hook_dir / dll_arg
    if candidate.is_file():
        return str(candidate.resolve())

    # Check tools/ directory
    candidate = tools_dir / dll_arg
    if candidate.is_file():
        return str(candidate.resolve())

    raise FileNotFoundError(
        f"DLL not found: {dll_arg}\n"
        f"Searched: CWD, {hook_dir}, {tools_dir}"
    )


# ── Remote PE Resolution (64-bit Python → 32-bit target) ──────

def read_process_memory(hProcess, address: int, size: int) -> bytes | None:
    """Read memory from a remote process."""
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        hProcess, ctypes.c_void_p(address), buf, size, ctypes.byref(read)
    )
    if not ok or read.value == 0:
        return None
    return buf.raw[:read.value]


def find_kernel32_via_peb(hProcess, hThread) -> int | None:
    """
    Find kernel32.dll base in a 32-bit SUSPENDED process from 64-bit Python.
    Uses NtQueryInformationProcess to read the WoW64 PEB, then walks
    the PEB_LDR_DATA module list.

    This works even when the process is suspended because the PEB and
    initial module list are populated by the kernel before any user code runs.
    """
    # For WoW64: use NtQueryInformationProcess with ProcessWow64Information (26)
    # to get the 32-bit PEB address. On 64-bit Windows, this returns a
    # ULONG_PTR (8 bytes) containing the 32-bit PEB address.
    peb32_addr = ctypes.c_ulonglong(0)
    status = ntdll.NtQueryInformationProcess(
        hProcess,
        26,  # ProcessWow64Information
        ctypes.byref(peb32_addr),
        ctypes.sizeof(peb32_addr),
        None
    )
    if status != 0 or peb32_addr.value == 0:
        print(f"[!] NtQueryInformationProcess(Wow64) failed: status=0x{status & 0xFFFFFFFF:08X}")
        return None

    peb_addr = peb32_addr.value
    print(f"[*] WoW64 PEB at 0x{peb_addr:08X}")

    # Read PEB32.Ldr (at offset 0x0C in 32-bit PEB)
    peb_data = read_process_memory(hProcess, peb_addr, 0x10)
    if not peb_data:
        print("[!] Failed to read PEB")
        return None

    ldr_addr = struct.unpack_from("<I", peb_data, 0x0C)[0]
    if ldr_addr == 0:
        print("[!] PEB.Ldr is NULL")
        return None

    print(f"[*] PEB_LDR_DATA at 0x{ldr_addr:08X}")

    # Read PEB_LDR_DATA.InLoadOrderModuleList.Flink (offset 0x0C)
    ldr_data = read_process_memory(hProcess, ldr_addr, 0x14)
    if not ldr_data:
        print("[!] Failed to read LDR_DATA")
        return None

    head = struct.unpack_from("<I", ldr_data, 0x0C)[0]
    current = head

    # Walk the InLoadOrderModuleList (up to 50 entries)
    for _ in range(50):
        # Each LDR_DATA_TABLE_ENTRY32:
        # +0x00 InLoadOrderLinks.Flink
        # +0x04 InLoadOrderLinks.Blink
        # +0x18 DllBase
        # +0x2C BaseDllName (UNICODE_STRING: +0x00=Length, +0x02=MaxLength, +0x04=Buffer)
        entry_data = read_process_memory(hProcess, current, 0x38)
        if not entry_data:
            break

        flink = struct.unpack_from("<I", entry_data, 0x00)[0]
        dll_base = struct.unpack_from("<I", entry_data, 0x18)[0]

        # Read the BaseDllName UNICODE_STRING
        name_len = struct.unpack_from("<H", entry_data, 0x2C)[0]
        name_buf_ptr = struct.unpack_from("<I", entry_data, 0x30)[0]

        if name_len > 0 and name_buf_ptr != 0 and name_len < 512:
            name_data = read_process_memory(hProcess, name_buf_ptr, name_len)
            if name_data:
                try:
                    dll_name = name_data.decode("utf-16-le").lower()
                    if "kernel32" in dll_name:
                        print(f"[*] Found kernel32.dll at 0x{dll_base:08X}")
                        return dll_base
                except UnicodeDecodeError:
                    pass

        if flink == head or flink == 0:
            break
        current = flink

    print("[!] kernel32.dll not found in PEB module list")
    return None


def find_loadlibrary_from_peb(hProcess, hThread, pid: int) -> int | None:
    """
    Find LoadLibraryA in the target SUSPENDED process by:
    1. Walking the PEB to find kernel32.dll base
    2. Reading kernel32's PE export table for LoadLibraryA
    """
    k32_base = find_kernel32_via_peb(hProcess, hThread)
    if k32_base is None:
        return None

    # Now walk the PE export table (same as find_remote_function but with known base)
    dos = read_process_memory(hProcess, k32_base, 64)
    if not dos or len(dos) < 64:
        return None

    magic = struct.unpack_from("<H", dos, 0)[0]
    if magic != 0x5A4D:
        return None

    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    nt = read_process_memory(hProcess, k32_base + e_lfanew, 248)
    if not nt or len(nt) < 248:
        return None

    export_rva = struct.unpack_from("<I", nt, 0x78)[0]
    if export_rva == 0:
        return None

    export_dir = read_process_memory(hProcess, k32_base + export_rva, 40)
    if not export_dir or len(export_dir) < 40:
        return None

    num_names      = struct.unpack_from("<I", export_dir, 24)[0]
    addr_table_rva = struct.unpack_from("<I", export_dir, 28)[0]
    name_table_rva = struct.unpack_from("<I", export_dir, 32)[0]
    ord_table_rva  = struct.unpack_from("<I", export_dir, 36)[0]

    name_ptrs = read_process_memory(hProcess, k32_base + name_table_rva, num_names * 4)
    ordinals  = read_process_memory(hProcess, k32_base + ord_table_rva, num_names * 2)
    if not name_ptrs or not ordinals:
        return None

    target_name = b"LoadLibraryA"
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", name_ptrs, i * 4)[0]
        name_bytes = read_process_memory(hProcess, k32_base + name_rva, 64)
        if not name_bytes:
            continue
        name_str = name_bytes.split(b"\x00")[0]
        if name_str == target_name:
            ordinal = struct.unpack_from("<H", ordinals, i * 2)[0]
            func_rva_data = read_process_memory(
                hProcess, k32_base + addr_table_rva + ordinal * 4, 4
            )
            if not func_rva_data:
                return None
            func_rva = struct.unpack_from("<I", func_rva_data, 0)[0]
            return k32_base + func_rva

    return None


def find_remote_function(hProcess, pid: int, dll_name: str, func_name: str) -> int | None:
    """
    Find a function address in a remote 32-bit process by walking its
    PE export table. This is necessary because 64-bit Python's kernel32
    addresses are useless for a 32-bit target.

    Steps:
    1. Find DLL base via module snapshot
    2. Read DOS header → NT headers → export directory from target memory
    3. Walk export name table to find the function
    4. Return base + RVA
    """
    # 1. Find DLL base in target process
    modules = list_modules(pid)
    target_base = None
    for name, base, size in modules:
        if name.lower() == dll_name.lower():
            target_base = base
            break

    if target_base is None:
        print(f"[!] {dll_name} not found in target process")
        return None

    print(f"[*] Target {dll_name} at 0x{target_base:08X}")

    # 2. Read DOS header to get e_lfanew
    dos = read_process_memory(hProcess, target_base, 64)
    if not dos or len(dos) < 64:
        print("[!] Failed to read DOS header")
        return None

    magic = struct.unpack_from("<H", dos, 0)[0]
    if magic != 0x5A4D:  # "MZ"
        print(f"[!] Bad DOS signature: 0x{magic:04X}")
        return None

    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]

    # 3. Read NT headers (32-bit PE)
    nt = read_process_memory(hProcess, target_base + e_lfanew, 248)
    if not nt or len(nt) < 248:
        print("[!] Failed to read NT headers")
        return None

    nt_sig = struct.unpack_from("<I", nt, 0)[0]
    if nt_sig != 0x00004550:  # "PE\0\0"
        print(f"[!] Bad NT signature: 0x{nt_sig:08X}")
        return None

    # Export directory RVA is at offset 0x78 in NT headers
    # (signature=4 + file_header=20 + optional_header offset 96 for export = 120 = 0x78)
    export_rva = struct.unpack_from("<I", nt, 0x78)[0]
    if export_rva == 0:
        print("[!] No export directory")
        return None

    # 4. Read export directory (IMAGE_EXPORT_DIRECTORY = 40 bytes)
    export_dir = read_process_memory(hProcess, target_base + export_rva, 40)
    if not export_dir or len(export_dir) < 40:
        print("[!] Failed to read export directory")
        return None

    num_names       = struct.unpack_from("<I", export_dir, 24)[0]
    addr_table_rva  = struct.unpack_from("<I", export_dir, 28)[0]
    name_table_rva  = struct.unpack_from("<I", export_dir, 32)[0]
    ord_table_rva   = struct.unpack_from("<I", export_dir, 36)[0]

    # 5. Read name pointer table and ordinal table
    name_ptrs = read_process_memory(hProcess, target_base + name_table_rva, num_names * 4)
    ordinals  = read_process_memory(hProcess, target_base + ord_table_rva, num_names * 2)

    if not name_ptrs or not ordinals:
        print("[!] Failed to read export tables")
        return None

    # 6. Binary search / linear scan for function name
    target_name = func_name.encode("ascii")
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", name_ptrs, i * 4)[0]
        name_bytes = read_process_memory(hProcess, target_base + name_rva, 64)
        if not name_bytes:
            continue
        name_str = name_bytes.split(b"\x00")[0]
        if name_str == target_name:
            ordinal = struct.unpack_from("<H", ordinals, i * 2)[0]
            func_rva_data = read_process_memory(
                hProcess, target_base + addr_table_rva + ordinal * 4, 4
            )
            if not func_rva_data:
                return None
            func_rva = struct.unpack_from("<I", func_rva_data, 0)[0]
            return target_base + func_rva

    print(f"[!] {func_name} not found in {dll_name} export table")
    return None


# ── Core Operations ────────────────────────────────────────────

def inject_dll(pid: int, dll_path: str) -> bool:
    """
    Inject a DLL into the target process using CreateRemoteThread + LoadLibraryA.

    Handles 64-bit Python → 32-bit target by resolving LoadLibraryA from
    the target's own kernel32.dll PE export table.
    """
    dll_bytes = dll_path.encode("ascii") + b"\x00"

    print(f"[*] Opening process {pid}...")
    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not hProcess:
        err = ctypes.get_last_error()
        print(f"[!] OpenProcess failed: error {err}")
        print("    Make sure you're running as Administrator.")
        return False

    try:
        # Find LoadLibraryA in the TARGET process's kernel32
        print("[*] Resolving LoadLibraryA in target process...")
        load_library_addr = find_remote_function(
            hProcess, pid, "KERNEL32.DLL", "LoadLibraryA"
        )
        # Fallback: try lowercase name (module name varies)
        if load_library_addr is None:
            load_library_addr = find_remote_function(
                hProcess, pid, "kernel32.dll", "LoadLibraryA"
            )
        if load_library_addr is None:
            print("[!] Could not resolve LoadLibraryA in target")
            return False

        print(f"[*] LoadLibraryA at 0x{load_library_addr:08X}")

        # Allocate memory in target process for the DLL path
        print(f"[*] Allocating {len(dll_bytes)} bytes in target process...")
        remote_addr = kernel32.VirtualAllocEx(
            hProcess,
            None,
            len(dll_bytes),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
        if not remote_addr:
            print(f"[!] VirtualAllocEx failed: {ctypes.get_last_error()}")
            return False

        print(f"[*] Remote buffer at 0x{remote_addr:08X}")

        # Write DLL path to allocated memory
        written = ctypes.c_size_t(0)
        ok = kernel32.WriteProcessMemory(
            hProcess,
            remote_addr,
            dll_bytes,
            len(dll_bytes),
            ctypes.byref(written),
        )
        if not ok:
            print(f"[!] WriteProcessMemory failed: {ctypes.get_last_error()}")
            return False

        print(f"[*] Wrote {written.value} bytes to remote process")

        # Create remote thread: LoadLibraryA(remote_addr)
        print("[*] Creating remote thread...")
        thread_id = wt.DWORD(0)
        hThread = kernel32.CreateRemoteThread(
            hProcess,
            None,       # No security attributes
            0,          # Default stack size
            ctypes.c_void_p(load_library_addr),
            ctypes.c_void_p(remote_addr),
            0,          # Run immediately
            ctypes.byref(thread_id),
        )

        if not hThread:
            print(f"[!] CreateRemoteThread failed: {ctypes.get_last_error()}")
            return False

        print(f"[*] Remote thread ID: {thread_id.value}")

        # Wait for the thread to finish (LoadLibrary to complete)
        print("[*] Waiting for DLL to load...")
        kernel32.WaitForSingleObject(hThread, INFINITE)

        # Check exit code (LoadLibraryA returns HMODULE or NULL)
        exit_code = wt.DWORD(0)
        kernel32.GetExitCodeThread(hThread, ctypes.byref(exit_code))
        kernel32.CloseHandle(hThread)

        # Free the remote memory (DLL path no longer needed)
        kernel32.VirtualFreeEx(hProcess, remote_addr, 0, MEM_RELEASE)

        if exit_code.value == 0:
            print("[!] LoadLibraryA returned NULL — DLL failed to load")
            print("    Possible causes:")
            print("    - DLL has missing dependencies (wrong architecture?)")
            print("    - Anti-cheat blocked the injection")
            print("    - DLL path encoding issue")
            return False

        print(f"[+] DLL loaded! HMODULE = 0x{exit_code.value:08X}")
        return True

    finally:
        kernel32.CloseHandle(hProcess)


def eject_dll(pid: int, dll_name: str) -> bool:
    """
    Unload a DLL from the target process using CreateRemoteThread + FreeLibrary.
    """
    # Find the module handle in the target process
    try:
        modules = list_modules(pid)
    except OSError as e:
        print(f"[!] {e}")
        return False

    target_base = None
    for name, base, size in modules:
        if name.lower() == dll_name.lower():
            target_base = base
            break

    if target_base is None:
        print(f"[!] {dll_name} not found in process {pid}")
        return False

    print(f"[*] Found {dll_name} at 0x{target_base:08X}")

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not hProcess:
        print(f"[!] OpenProcess failed: {ctypes.get_last_error()}")
        return False

    try:
        # Resolve FreeLibrary in target's kernel32 (cross-arch safe)
        free_library_addr = find_remote_function(
            hProcess, pid, "KERNEL32.DLL", "FreeLibrary"
        )
        if free_library_addr is None:
            free_library_addr = find_remote_function(
                hProcess, pid, "kernel32.dll", "FreeLibrary"
            )
        if free_library_addr is None:
            print("[!] Could not resolve FreeLibrary in target")
            return False

        print("[*] Creating remote thread for FreeLibrary...")
        thread_id = wt.DWORD(0)
        hThread = kernel32.CreateRemoteThread(
            hProcess,
            None, 0,
            ctypes.c_void_p(free_library_addr),
            ctypes.c_void_p(target_base),
            0,
            ctypes.byref(thread_id),
        )

        if not hThread:
            print(f"[!] CreateRemoteThread failed: {ctypes.get_last_error()}")
            return False

        kernel32.WaitForSingleObject(hThread, INFINITE)

        exit_code = wt.DWORD(0)
        kernel32.GetExitCodeThread(hThread, ctypes.byref(exit_code))
        kernel32.CloseHandle(hThread)

        if exit_code.value:
            print(f"[+] DLL ejected successfully")
            return True
        else:
            print("[!] FreeLibrary returned FALSE")
            return False

    finally:
        kernel32.CloseHandle(hProcess)


def launch_and_inject(exe_path: str, dll_path: str, working_dir: str | None = None) -> bool:
    """
    Launch ge.exe in SUSPENDED state, inject DLL, then resume.
    This ensures our DLL loads before the game initializes.
    """
    si = STARTUPINFOA()
    si.cb = ctypes.sizeof(STARTUPINFOA)
    pi = PROCESS_INFORMATION()

    if working_dir is None:
        working_dir = os.path.dirname(exe_path)

    exe_bytes = exe_path.encode("ascii")
    dir_bytes = working_dir.encode("ascii") if working_dir else None

    print(f"[*] Launching: {exe_path}")
    print(f"[*] Working dir: {working_dir}")
    print(f"[*] Flags: CREATE_SUSPENDED")

    ok = kernel32.CreateProcessA(
        exe_bytes,          # lpApplicationName
        None,               # lpCommandLine
        None,               # lpProcessAttributes
        None,               # lpThreadAttributes
        False,              # bInheritHandles
        CREATE_SUSPENDED,   # dwCreationFlags
        None,               # lpEnvironment
        dir_bytes,          # lpCurrentDirectory
        ctypes.byref(si),
        ctypes.byref(pi),
    )

    if not ok:
        err = ctypes.get_last_error()
        print(f"[!] CreateProcess failed: error {err}")
        return False

    pid = pi.dwProcessId
    print(f"[+] Process created — PID {pid} (SUSPENDED)")

    try:
        # Inject DLL while process is suspended
        dll_bytes = dll_path.encode("ascii") + b"\x00"

        # 64-bit Python can't use CreateToolhelp32Snapshot on a 32-bit
        # SUSPENDED process (error 299). Instead, walk the PEB directly
        # to find kernel32 and resolve LoadLibraryA — works even while
        # the main thread is suspended because the kernel populates the
        # PEB module list before any user code runs.
        print("[*] Resolving LoadLibraryA via PEB (process SUSPENDED)...")
        load_library_addr = find_loadlibrary_from_peb(
            pi.hProcess, pi.hThread, pid
        )

        # Fallback: resume the process fully, wait for initialization,
        # then inject into the running process (no re-suspend to avoid
        # loader lock issues that cause LoadLibraryA to return NULL)
        if load_library_addr is None:
            import time
            print("[*] PEB walk failed. Resuming process for full init...")
            kernel32.ResumeThread(pi.hThread)
            time.sleep(3)  # Let process fully initialize
            print("[*] Trying module snapshot on running process...")
            load_library_addr = find_remote_function(
                pi.hProcess, pid, "KERNEL32.DLL", "LoadLibraryA"
            )
            if load_library_addr is None:
                load_library_addr = find_remote_function(
                    pi.hProcess, pid, "kernel32.dll", "LoadLibraryA"
                )
            # Process is now running — no need to resume at the end
            # We'll skip the final ResumeThread below

        if load_library_addr is None:
            print("[!] Could not resolve LoadLibraryA — terminating process")
            kernel32.TerminateProcess(pi.hProcess, 1)
            return False

        print(f"[*] LoadLibraryA at 0x{load_library_addr:08X}")

        # Allocate + write DLL path
        remote_addr = kernel32.VirtualAllocEx(
            pi.hProcess, None, len(dll_bytes),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        )
        if not remote_addr:
            print(f"[!] VirtualAllocEx failed — terminating process")
            kernel32.TerminateProcess(pi.hProcess, 1)
            return False

        written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(
            pi.hProcess, remote_addr, dll_bytes,
            len(dll_bytes), ctypes.byref(written),
        )

        # Create remote thread to load DLL
        print("[*] Injecting DLL...")
        thread_id = wt.DWORD(0)
        hThread = kernel32.CreateRemoteThread(
            pi.hProcess, None, 0,
            ctypes.c_void_p(load_library_addr),
            ctypes.c_void_p(remote_addr),
            0, ctypes.byref(thread_id),
        )

        if not hThread:
            print(f"[!] CreateRemoteThread failed — terminating process")
            kernel32.TerminateProcess(pi.hProcess, 1)
            return False

        # Wait for DLL to load
        print("[*] Waiting for DLL to load...")
        kernel32.WaitForSingleObject(hThread, INFINITE)

        exit_code = wt.DWORD(0)
        kernel32.GetExitCodeThread(hThread, ctypes.byref(exit_code))
        kernel32.CloseHandle(hThread)
        kernel32.VirtualFreeEx(pi.hProcess, remote_addr, 0, MEM_RELEASE)

        if exit_code.value == 0:
            print("[!] LoadLibraryA returned NULL — DLL failed to load")
            # Get last error from the remote process for debugging
            print("    Possible causes:")
            print("    - DLL has missing dependencies (CRT DLLs)")
            print("    - Loader lock held by initializing process")
            print("    - Anti-cheat blocked the load")
            print("[!] Terminating process")
            kernel32.TerminateProcess(pi.hProcess, 1)
            return False

        print(f"[+] DLL loaded! HMODULE = 0x{exit_code.value:08X}")

        # Resume the main thread if still suspended
        # (If PEB walk worked, the main thread was never resumed)
        print("[*] Resuming main thread...")
        result = kernel32.ResumeThread(pi.hThread)
        if result == -1:
            err = ctypes.get_last_error()
            if err != 0:
                print(f"[!] ResumeThread failed: {err}")
        elif result == 0:
            print(f"[*] Thread was already running")
        else:
            print(f"[+] Thread resumed (prev suspend count: {result})")

        print(f"[+] Game starting with hooks active — PID: {pid}")
        print(f"[*] Check phantom_hook.log for xref scan results")
        return True

    finally:
        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)


# ── CLI ────────────────────────────────────────────────────────

def cmd_inject(args):
    """Inject DLL into ge.exe."""
    # Find ge.exe
    pids = find_ge_pids()
    if not pids:
        print("[!] ge.exe not found. Is the game running?")
        return 1

    if len(pids) > 1:
        print(f"[!] Multiple ge.exe instances found:")
        for pid, _ in pids:
            print(f"    PID {pid}")
        print("[*] Using first instance")

    pid = pids[0][0]
    print(f"[*] Found ge.exe — PID {pid}")

    # Resolve DLL path
    try:
        dll_path = resolve_dll_path(args.dll)
    except FileNotFoundError as e:
        print(f"[!] {e}")
        return 1

    print(f"[*] DLL path: {dll_path}")

    # Check if already injected
    dll_name = os.path.basename(dll_path)
    if is_dll_loaded(pid, dll_name):
        print(f"[!] {dll_name} is already loaded in ge.exe")
        print("    Use 'eject' first if you want to re-inject")
        return 1

    # Inject
    if inject_dll(pid, dll_path):
        print()
        print("[+] Injection successful!")
        print(f"    Now run: python tools/packet_logger.py")
        return 0
    else:
        print()
        print("[!] Injection failed")
        return 1


def cmd_eject(args):
    """Eject DLL from ge.exe."""
    pids = find_ge_pids()
    if not pids:
        print("[!] ge.exe not found")
        return 1

    pid = pids[0][0]
    dll_name = os.path.basename(args.dll)

    if eject_dll(pid, dll_name):
        return 0
    return 1


def cmd_launch(args):
    """Launch ge.exe suspended, inject DLL, then resume."""
    # Resolve DLL path
    try:
        dll_path = resolve_dll_path(args.dll)
    except FileNotFoundError as e:
        print(f"[!] {e}")
        return 1

    # Resolve exe path
    exe_path = args.exe
    if not os.path.isfile(exe_path):
        print(f"[!] ge.exe not found at: {exe_path}")
        print("    Use --exe to specify the full path to ge.exe")
        return 1

    exe_path = os.path.abspath(exe_path)
    print(f"[*] DLL: {dll_path}")
    print(f"[*] EXE: {exe_path}")

    # Check if already running
    pids = find_ge_pids()
    if pids:
        print(f"[!] ge.exe is already running (PID {pids[0][0]})")
        print("    Close it first, or use 'inject' to hook the running instance")
        return 1

    if launch_and_inject(exe_path, dll_path, args.workdir):
        print()
        print("[+] Launch + inject successful!")
        print(f"    DLL hooks active from process start")
        return 0
    else:
        print()
        print("[!] Launch + inject failed")
        return 1


def cmd_list(args):
    """List modules loaded in ge.exe."""
    pids = find_ge_pids()
    if not pids:
        print("[!] ge.exe not found")
        return 1

    pid = pids[0][0]
    print(f"[*] Modules in ge.exe (PID {pid}):\n")

    try:
        modules = list_modules(pid)
    except OSError as e:
        print(f"[!] {e}")
        return 1

    # Sort by base address
    modules.sort(key=lambda m: m[1])

    print(f"  {'Base':>12}  {'Size':>10}  Name")
    print(f"  {'─' * 12}  {'─' * 10}  {'─' * 40}")

    for name, base, size in modules:
        marker = " <<<" if "phantom" in name.lower() else ""
        print(f"  0x{base:08X}  {size:>10,}  {name}{marker}")

    print(f"\n  Total: {len(modules)} modules")
    return 0


def cmd_clean(args):
    """Eject ALL phantom_hook DLLs from ge.exe.

    Finds all modules matching phantom_hook*.dll and ejects them.
    Use this to clear stale DLLs that cause command conflicts.
    After cleaning, re-inject the desired version.
    """
    pids = find_ge_pids()
    if not pids:
        print("[!] ge.exe not found")
        return 1

    pid = pids[0][0]
    print(f"[*] Scanning ge.exe (PID {pid}) for phantom_hook DLLs...")

    try:
        modules = list_modules(pid)
    except OSError as e:
        print(f"[!] {e}")
        return 1

    # Find all phantom_hook DLLs
    phantom_dlls = [
        (name, base, size) for name, base, size in modules
        if "phantom_hook" in name.lower()
    ]

    if not phantom_dlls:
        print("[*] No phantom_hook DLLs found — already clean")
        return 0

    print(f"[*] Found {len(phantom_dlls)} phantom_hook DLL(s):")
    for name, base, size in phantom_dlls:
        print(f"    0x{base:08X}  {size:>10,}  {name}")

    # Eject all of them
    ejected = 0
    failed = 0
    for name, base, size in phantom_dlls:
        print(f"\n[*] Ejecting {name}...")
        if eject_dll(pid, name):
            ejected += 1
        else:
            failed += 1
            print(f"[!] Failed to eject {name} — may need a second pass")

    print(f"\n[{'+'if failed == 0 else '!'}] Clean complete: {ejected} ejected, {failed} failed")
    if ejected > 0:
        print("[*] Shared memory will be released once all DLLs unload")
        print("[*] Re-inject with: python tools/dll_injector.py inject --dll phantom_hook_v8.dll")
    return 0 if failed == 0 else 1


def main():
    parser = argparse.ArgumentParser(
        description="GE_Phantom DLL Injector — inject hooks into ge.exe"
    )
    sub = parser.add_subparsers(dest="command")

    # inject
    p_inject = sub.add_parser("inject", help="Inject DLL into ge.exe")
    p_inject.add_argument(
        "--dll", default=DEFAULT_DLL,
        help=f"DLL to inject (default: {DEFAULT_DLL})"
    )
    p_inject.set_defaults(func=cmd_inject)

    # launch
    p_launch = sub.add_parser("launch", help="Launch ge.exe suspended, inject DLL, resume")
    p_launch.add_argument(
        "--dll", default=DEFAULT_DLL,
        help=f"DLL to inject (default: {DEFAULT_DLL})"
    )
    p_launch.add_argument(
        "--exe", default=r"C:\Granado Espada\ge.exe",
        help="Path to ge.exe (default: C:\\Granado Espada\\ge.exe)"
    )
    p_launch.add_argument(
        "--workdir", default=None,
        help="Working directory (default: same as exe)"
    )
    p_launch.set_defaults(func=cmd_launch)

    # eject
    p_eject = sub.add_parser("eject", help="Unload DLL from ge.exe")
    p_eject.add_argument(
        "--dll", default=DEFAULT_DLL,
        help="DLL name to eject"
    )
    p_eject.set_defaults(func=cmd_eject)

    # list
    p_list = sub.add_parser("list", help="List modules in ge.exe")
    p_list.set_defaults(func=cmd_list)

    # clean
    p_clean = sub.add_parser("clean", help="Eject ALL phantom_hook DLLs (fix stale DLL conflicts)")
    p_clean.set_defaults(func=cmd_clean)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
