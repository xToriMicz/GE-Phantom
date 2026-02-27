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
        ("modBaseAddr",     ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize",     wt.DWORD),
        ("hModule",         wt.HMODULE),
        ("szModule",        ctypes.c_char * (MAX_MODULE_NAME32 + 1)),
        ("szExePath",       ctypes.c_char * MAX_PATH),
    ]

# ── Win32 API Handles ─────────────────────────────────────────

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi    = ctypes.WinDLL("psapi", use_last_error=True)

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
            base = ctypes.addressof(entry.modBaseAddr.contents)
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


# ── Core Operations ────────────────────────────────────────────

def inject_dll(pid: int, dll_path: str) -> bool:
    """
    Inject a DLL into the target process using CreateRemoteThread + LoadLibraryA.

    Steps:
    1. OpenProcess with full access
    2. VirtualAllocEx — allocate memory for DLL path string
    3. WriteProcessMemory — write the DLL path
    4. GetProcAddress(kernel32, "LoadLibraryA") — get loader address
    5. CreateRemoteThread — call LoadLibraryA(dll_path) in target
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

        # Get address of LoadLibraryA in kernel32
        hKernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
        if not hKernel32:
            print("[!] GetModuleHandle(kernel32) failed")
            return False

        load_library_addr = kernel32.GetProcAddress(hKernel32, b"LoadLibraryA")
        if not load_library_addr:
            print("[!] GetProcAddress(LoadLibraryA) failed")
            return False

        print(f"[*] LoadLibraryA at 0x{load_library_addr:08X}")

        # Create remote thread: LoadLibraryA(remote_addr)
        print("[*] Creating remote thread...")
        thread_id = wt.DWORD(0)
        hThread = kernel32.CreateRemoteThread(
            hProcess,
            None,       # No security attributes
            0,          # Default stack size
            load_library_addr,
            remote_addr,
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
        hKernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
        free_library_addr = kernel32.GetProcAddress(hKernel32, b"FreeLibrary")

        if not free_library_addr:
            print("[!] GetProcAddress(FreeLibrary) failed")
            return False

        print("[*] Creating remote thread for FreeLibrary...")
        thread_id = wt.DWORD(0)
        hThread = kernel32.CreateRemoteThread(
            hProcess,
            None, 0,
            free_library_addr,
            target_base,
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

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
