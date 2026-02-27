"""Analyze the actual property accessor function at 0x005E79F2."""
import ctypes
import ctypes.wintypes as wt
import struct
import sys

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
TH32CS_SNAPPROCESS = 0x02
MAX_PATH = 260

class PE32(ctypes.Structure):
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

def hexdump(addr, data, highlight_range=None):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    0x{addr+i:08X}: {hex_str:<48s}  {ascii_str}")

def read_string(hProcess, addr, max_len=64):
    data = rpm(hProcess, addr, max_len)
    if not data:
        return None
    end = data.find(b"\x00")
    if end >= 0:
        data = data[:end]
    return data.decode("ascii", errors="replace")

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
        # 1. Read the function at 0x005E79F0 (the common SplRange call target)
        print("=== Property accessor function at 0x005E79F0 ===")
        data = rpm(hProcess, 0x005E79F0, 128)
        if data:
            hexdump(0x005E79F0, data)
        else:
            print("    (failed)")

        # Also check 0x005E79E0 for potential function start
        print()
        print("=== Context before 0x005E79F0 (0x005E79D0) ===")
        data = rpm(hProcess, 0x005E79D0, 48)
        if data:
            hexdump(0x005E79D0, data)

        # 2. Read the SplRange thunk objects to understand what ECX points to
        print()
        print("=== SplRange thunk ECX values (object pointers) ===")
        # From the first few SplRange xrefs:
        ecx_values = [
            0x00D1EBF8,  # first thunk
            0x00D1FA94,  # second thunk
            0x00D20590,  # third thunk
        ]

        # Read first ECX value from thunk context
        # Actually, let me extract ECX from the thunk patterns directly
        TEXT_START = 0x00401000
        xref_addrs = [
            0x004180CE,  # SplRange #1
            0x0041AA81,  # SplRange #2
            0x004180B0,  # context before #1 (different string thunk)
        ]

        for xref in xref_addrs[:2]:
            thunk_data = rpm(hProcess, xref, 15)
            if thunk_data and thunk_data[0] == 0x68 and thunk_data[5] == 0xB9:
                # PUSH imm32 followed by MOV ECX, imm32
                str_addr = struct.unpack_from("<I", thunk_data, 1)[0]
                ecx_val = struct.unpack_from("<I", thunk_data, 6)[0]
                str_name = read_string(hProcess, str_addr)
                print(f"  0x{xref:08X}: PUSH \"{str_name}\" (0x{str_addr:08X}), ECX=0x{ecx_val:08X}")

                # Read the object at ECX to see what it looks like
                obj_data = rpm(hProcess, ecx_val, 32)
                if obj_data:
                    print(f"    Object at 0x{ecx_val:08X}:")
                    hexdump(ecx_val, obj_data)

        # 3. Check 0x005E79F2 specifically
        print()
        print("=== Disassembly hint at 0x005E79F2 ===")
        data = rpm(hProcess, 0x005E79F0, 32)
        if data:
            # Show what's at F0, F1, F2, F3
            for off in range(4):
                byte = data[off]
                # Common function prologues
                if byte == 0x55:
                    print(f"    0x005E79F{off:X}: 55 = PUSH EBP (function start!)")
                elif byte == 0x8B:
                    print(f"    0x005E79F{off:X}: 8B = MOV ...")
                elif byte == 0xCC:
                    print(f"    0x005E79F{off:X}: CC = INT3 (breakpoint/padding)")
                elif byte == 0x90:
                    print(f"    0x005E79F{off:X}: 90 = NOP")
                elif byte == 0xC3:
                    print(f"    0x005E79F{off:X}: C3 = RET (end of prev function)")
                else:
                    print(f"    0x005E79F{off:X}: {byte:02X}")

        # 4. Also look for lua_State global (needed for tolua++ wrappers)
        print()
        print("=== Looking for lua_State patterns ===")
        # Common pattern: the game stores lua_State* in a global variable
        # Search for "luaL_dostring" or "lua_newstate" strings
        for name in ["lua_State", "luaL_newstate", "lua_pcall"]:
            rdata = rpm(hProcess, 0x00B6B000, 0x150000)
            if rdata:
                needle = name.encode("ascii")
                idx = rdata.find(needle)
                if idx >= 0:
                    va = 0x00B6B000 + idx
                    print(f"  Found \"{name}\" at 0x{va:08X}")

    finally:
        kernel32.CloseHandle(hProcess)

    return 0

if __name__ == "__main__":
    sys.exit(main())
