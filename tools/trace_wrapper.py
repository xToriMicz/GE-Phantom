"""
Trace through GetPropertyNumber tolua++ wrapper to find the actual C++ function.
Reads 512 bytes of the wrapper and analyzes all CALL instructions.
"""
import ctypes
import ctypes.wintypes as wt
import struct
import sys

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
TH32CS_SNAPPROCESS = 0x02

class PE32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]

def find_ge_pid():
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    entry = PE32()
    entry.dwSize = ctypes.sizeof(PE32)
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

def find_calls(addr, data):
    """Find all E8 (CALL rel32) instructions in data."""
    calls = []
    i = 0
    while i < len(data) - 5:
        if data[i] == 0xE8:
            rel = struct.unpack_from("<i", data, i + 1)[0]
            target = addr + i + 5 + rel
            calls.append((addr + i, target))
            i += 5
        else:
            i += 1
    return calls

def read_string(hProcess, addr, max_len=64):
    data = rpm(hProcess, addr, max_len)
    if not data:
        return None
    end = data.find(b"\x00")
    if end >= 0:
        data = data[:end]
    try:
        return data.decode("ascii", errors="replace")
    except:
        return None

def main():
    pid = find_ge_pid()
    if not pid:
        print("[!] ge.exe not found")
        return 1

    hProcess = kernel32.OpenProcess(0x0410, False, pid)
    if not hProcess:
        print(f"[!] OpenProcess failed: {ctypes.get_last_error()}")
        return 1

    try:
        # Read GetPropertyNumber wrapper (0x008ABD73) - 512 bytes
        GET_FUNC = 0x008ABD73
        print(f"=== GetPropertyNumber wrapper at 0x{GET_FUNC:08X} ===")
        data = rpm(hProcess, GET_FUNC, 512)
        if not data:
            print("    (failed to read)")
            return 1
        hexdump(GET_FUNC, data[:256])

        print()
        print("=== CALL instructions in GetPropertyNumber wrapper ===")
        calls = find_calls(GET_FUNC, data)
        for call_addr, target in calls:
            offset = call_addr - GET_FUNC
            # Read first 16 bytes of target to identify it
            target_data = rpm(hProcess, target, 16)
            prologue = ""
            if target_data:
                if target_data[0] == 0x55 and target_data[1] == 0x8B:
                    prologue = " [PUSH EBP; MOV EBP,ESP — function start]"
                elif target_data[0] == 0xFF and target_data[1] == 0x25:
                    # JMP [addr] — import thunk
                    import_addr = struct.unpack_from("<I", target_data, 2)[0]
                    prologue = f" [JMP [{import_addr:08X}] — import]"
                hex_preview = " ".join(f"{b:02X}" for b in target_data[:8])
                prologue += f" bytes: {hex_preview}"
            print(f"  +{offset:3d} 0x{call_addr:08X} -> 0x{target:08X}{prologue}")

        # Read SetPropertyNumber wrapper too
        SET_FUNC = 0x006C6449
        print()
        print(f"=== SetPropertyNumber wrapper at 0x{SET_FUNC:08X} ===")
        data = rpm(hProcess, SET_FUNC, 512)
        if not data:
            print("    (failed to read)")
            return 1
        hexdump(SET_FUNC, data[:256])

        print()
        print("=== CALL instructions in SetPropertyNumber wrapper ===")
        calls = find_calls(SET_FUNC, data)
        for call_addr, target in calls:
            offset = call_addr - SET_FUNC
            target_data = rpm(hProcess, target, 16)
            prologue = ""
            if target_data:
                if target_data[0] == 0x55 and target_data[1] == 0x8B:
                    prologue = " [PUSH EBP; MOV EBP,ESP — function start]"
                elif target_data[0] == 0xFF and target_data[1] == 0x25:
                    import_addr = struct.unpack_from("<I", target_data, 2)[0]
                    prologue = f" [JMP [{import_addr:08X}] — import]"
                hex_preview = " ".join(f"{b:02X}" for b in target_data[:8])
                prologue += f" bytes: {hex_preview}"
            print(f"  +{offset:3d} 0x{call_addr:08X} -> 0x{target:08X}{prologue}")

        # Also check what's at the KeepRange usage sites
        # KeepRange #3 at 0x0064EC74 has a direct CALL
        print()
        print("=== KeepRange #3 usage context (0x0064EC50-0x0064ECA0) ===")
        data = rpm(hProcess, 0x0064EC50, 96)
        if data:
            hexdump(0x0064EC50, data)
            calls = find_calls(0x0064EC50, data)
            for call_addr, target in calls:
                target_data = rpm(hProcess, target, 16)
                prologue = ""
                if target_data:
                    hex_preview = " ".join(f"{b:02X}" for b in target_data[:8])
                    prologue = f" bytes: {hex_preview}"
                print(f"  0x{call_addr:08X} -> 0x{target:08X}{prologue}")

    finally:
        kernel32.CloseHandle(hProcess)

    return 0

if __name__ == "__main__":
    sys.exit(main())
