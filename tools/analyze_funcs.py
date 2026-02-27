"""Analyze resolved function addresses at runtime."""
import ctypes
import ctypes.wintypes as wt
import struct
import sys

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

TH32CS_SNAPPROCESS = 0x02
MAX_PATH = 260

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * MAX_PATH),
    ]

def find_ge_pid():
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    pid = None
    if kernel32.Process32First(snap, ctypes.byref(entry)):
        while True:
            if entry.szExeFile.decode("utf-8", errors="ignore").lower() == "ge.exe":
                pid = entry.th32ProcessID
                break
            if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                break
    kernel32.CloseHandle(snap)
    return pid

def rpm(hProcess, addr, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        hProcess, ctypes.c_void_p(addr), buf, size, ctypes.byref(read)
    )
    return buf.raw[:read.value] if ok and read.value > 0 else None

def hexdump(addr, data):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    0x{addr+i:08X}: {hex_str:<48s}  {ascii_str}")

def main():
    pid = find_ge_pid()
    if not pid:
        print("[!] ge.exe not found")
        return 1

    print(f"[*] ge.exe PID: {pid}")
    hProcess = kernel32.OpenProcess(0x0410, False, pid)
    if not hProcess:
        print(f"[!] OpenProcess failed: {ctypes.get_last_error()}")
        return 1

    try:
        # Function addresses from tolua++ registration pattern
        SET_FUNC = 0x006C6449
        GET_FUNC = 0x008ABD73

        print()
        print("=== SetPropertyNumber function at 0x{:08X} ===".format(SET_FUNC))
        data = rpm(hProcess, SET_FUNC, 96)
        if data:
            hexdump(SET_FUNC, data)
        else:
            print("    (failed to read)")

        print()
        print("=== GetPropertyNumber function at 0x{:08X} ===".format(GET_FUNC))
        data = rpm(hProcess, GET_FUNC, 96)
        if data:
            hexdump(GET_FUNC, data)
        else:
            print("    (failed to read)")

        # Registration context
        print()
        print("=== SetPropertyNumber registration context (0x006C5C10) ===")
        data = rpm(hProcess, 0x006C5C10, 48)
        if data:
            hexdump(0x006C5C10, data)

        print()
        print("=== GetPropertyNumber registration context (0x008B0728) ===")
        data = rpm(hProcess, 0x008B0728, 48)
        if data:
            hexdump(0x008B0728, data)

        # SplRange usage pattern
        print()
        print("=== SplRange usage at 0x004180B0 (first xref context) ===")
        data = rpm(hProcess, 0x004180B0, 80)
        if data:
            hexdump(0x004180B0, data)

        # KeepRange usage
        print()
        print("=== KeepRange usage at 0x004FEA30 ===")
        data = rpm(hProcess, 0x004FEA30, 80)
        if data:
            hexdump(0x004FEA30, data)

        # Second KeepRange xref (0x0050A943) - has CALL 0x005E79F2
        print()
        print("=== KeepRange usage #2 at 0x0050A920 ===")
        data = rpm(hProcess, 0x0050A920, 80)
        if data:
            hexdump(0x0050A920, data)

    finally:
        kernel32.CloseHandle(hProcess)

    return 0

if __name__ == "__main__":
    sys.exit(main())
