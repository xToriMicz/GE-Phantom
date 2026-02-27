"""
Find IES property string addresses in ge.exe RUNTIME MEMORY.

ge.exe is packed — the on-disk binary doesn't contain the real strings.
We need to search the running process's memory directly.

Two modes:
  1. Via ReadProcessMemory (needs admin + running ge.exe)
  2. Via phantom_hook CMD_READ_ADDR (needs DLL injected, very slow)
"""
import ctypes
import ctypes.wintypes as wt
import struct
import sys
from pathlib import Path

IMAGE_BASE = 0x00400000

# Runtime memory layout (from DLL xref scan log):
# .text: 0x00401000 - 0x00B6B000 (~7.7 MB)
# .rdata: starts around 0x00B6B000
# We'll search a generous range to find strings
SEARCH_START = 0x00B6B000
SEARCH_END   = 0x00D00000  # generous

# Strings to find
TARGETS = [
    "SetPropertyNumber",
    "GetPropertyNumber",
    "SplRange",
    "KeepRange",
    "ViewRange",
    "AiRange",
    "MaxLinkRange",
]

# Win32
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPPROCESS = 0x02
MAX_PATH = 260

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


def find_ge_pid():
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return None
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    found = None
    if kernel32.Process32First(snap, ctypes.byref(entry)):
        while True:
            name = entry.szExeFile.decode("utf-8", errors="ignore").lower()
            if name == "ge.exe":
                found = entry.th32ProcessID
                break
            if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                break
    kernel32.CloseHandle(snap)
    return found


def read_process_memory(hProcess, address, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        hProcess, ctypes.c_void_p(address), buf, size, ctypes.byref(read)
    )
    if not ok or read.value == 0:
        return None
    return buf.raw[:read.value]


def main():
    pid = find_ge_pid()
    if not pid:
        print("[!] ge.exe not found")
        return 1

    print(f"[*] ge.exe PID: {pid}")

    hProcess = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
    )
    if not hProcess:
        err = ctypes.get_last_error()
        print(f"[!] OpenProcess failed: error {err}")
        print("    Run as Administrator!")
        return 1

    try:
        # Read the entire search range in one big chunk
        total_size = SEARCH_END - SEARCH_START
        print(f"[*] Reading memory 0x{SEARCH_START:08X}-0x{SEARCH_END:08X} ({total_size // 1024}KB)...")

        # Read in 64KB chunks
        full_data = b""
        addr = SEARCH_START
        while addr < SEARCH_END:
            chunk_size = min(65536, SEARCH_END - addr)
            chunk = read_process_memory(hProcess, addr, chunk_size)
            if chunk:
                full_data += chunk
            else:
                full_data += b"\x00" * chunk_size
            addr += chunk_size

        print(f"[*] Read {len(full_data):,} bytes")
        print()

        # Search for strings
        print("=== String Search Results ===")
        found = {}

        for target in TARGETS:
            needle = target.encode("ascii")
            results = []
            offset = 0
            while True:
                idx = full_data.find(needle, offset)
                if idx < 0:
                    break
                va = SEARCH_START + idx
                # Check if null-terminated (exact match)
                end_byte = full_data[idx + len(needle)] if idx + len(needle) < len(full_data) else 0
                is_exact = (end_byte == 0)
                results.append((va, is_exact))
                offset = idx + 1

            if results:
                for va, is_exact in results:
                    tag = " (exact)" if is_exact else " (substring)"
                    print(f"  \"{target}\" -> 0x{va:08X}{tag}")
                exact = [r for r in results if r[1]]
                found[target] = exact[0][0] if exact else results[0][0]
            else:
                print(f"  \"{target}\" NOT FOUND")

        print()

        # Generate header defines
        key_strings = {
            "SetPropertyNumber": "GE_STR_SET_PROP_NUM",
            "GetPropertyNumber": "GE_STR_GET_PROP_NUM",
            "SplRange": "GE_STR_SPL_RANGE",
            "KeepRange": "GE_STR_KEEP_RANGE",
        }

        print("=== Updated phantom_hook.h defines ===")
        for target, define_name in key_strings.items():
            if target in found:
                va = found[target]
                print(f'#define {define_name:24s} 0x{va:08X}   /* "{target}" */')
            else:
                print(f'/* {define_name}: NOT FOUND */')

        # Now scan .text for xrefs to found strings
        if any(t in found for t in key_strings):
            print()
            print("=== Reading .text section for xref scan ===")
            TEXT_START = 0x00401000
            TEXT_END = 0x00B6B000
            text_size = TEXT_END - TEXT_START
            print(f"[*] Reading .text 0x{TEXT_START:08X}-0x{TEXT_END:08X} ({text_size // 1024}KB)...")

            text_data = b""
            addr = TEXT_START
            while addr < TEXT_END:
                chunk_size = min(65536, TEXT_END - addr)
                chunk = read_process_memory(hProcess, addr, chunk_size)
                if chunk:
                    text_data += chunk
                else:
                    text_data += b"\x00" * chunk_size
                addr += chunk_size

            print(f"[*] Read {len(text_data):,} bytes")
            print()

            for target, define_name in key_strings.items():
                if target not in found:
                    continue

                str_va = found[target]
                needle = struct.pack("<I", str_va)

                print(f"--- Xrefs to \"{target}\" (0x{str_va:08X}) ---")

                offset = 0
                xref_count = 0
                while True:
                    idx = text_data.find(needle, offset)
                    if idx < 0:
                        break

                    xref_va = TEXT_START + idx
                    xref_count += 1

                    # Decode instruction type
                    insn = "unknown"
                    if idx >= 1 and text_data[idx - 1] == 0x68:
                        insn = "PUSH imm32"
                    elif idx >= 1 and 0xB8 <= text_data[idx - 1] <= 0xBF:
                        regs = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
                        insn = f"MOV {regs[text_data[idx-1]-0xB8]}, imm32"
                    elif idx >= 2 and text_data[idx - 2] == 0x8D:
                        insn = "LEA reg, [imm32]"
                    elif idx >= 2 and text_data[idx - 2] == 0xC7:
                        insn = "MOV [mem], imm32"

                    # Show context bytes
                    ctx_start = max(0, idx - 16)
                    ctx_end = min(len(text_data), idx + 4 + 16)
                    ctx = text_data[ctx_start:ctx_end]
                    hex_ctx = ""
                    for i, b in enumerate(ctx):
                        real_i = ctx_start + i
                        if real_i == idx:
                            hex_ctx += "["
                        hex_ctx += f"{b:02X}"
                        if real_i == idx + 3:
                            hex_ctx += "]"
                        elif i < len(ctx) - 1:
                            hex_ctx += " "

                    print(f"  #{xref_count} at 0x{xref_va:08X} -- {insn}")
                    print(f"    {hex_ctx}")

                    # For PUSH instructions: look for tolua++ registration pattern
                    if idx >= 1 and text_data[idx - 1] == 0x68:
                        # Check prev PUSH (5 bytes before)
                        if idx >= 6 and text_data[idx - 6] == 0x68:
                            prev_push = struct.unpack_from("<I", text_data, idx - 5)[0]
                            in_text = TEXT_START <= prev_push < TEXT_END
                            marker = " *** FUNC PTR ***" if in_text else ""
                            print(f"    prev PUSH: 0x{prev_push:08X}{marker}")

                        # Check next PUSH
                        if idx + 4 < len(text_data) - 5 and text_data[idx + 4] == 0x68:
                            next_push = struct.unpack_from("<I", text_data, idx + 5)[0]
                            in_text = TEXT_START <= next_push < TEXT_END
                            marker = " *** FUNC PTR ***" if in_text else ""
                            print(f"    next PUSH: 0x{next_push:08X}{marker}")

                        # Check CALL after
                        for call_off in [4, 9, 14]:
                            check_pos = idx + call_off
                            if check_pos < len(text_data) - 5:
                                if text_data[check_pos] == 0xE8:
                                    rel = struct.unpack_from("<i", text_data, check_pos + 1)[0]
                                    call_target = TEXT_START + check_pos + 5 + rel
                                    print(f"    CALL at +{call_off}: 0x{call_target:08X}")

                    offset = idx + 1

                if xref_count == 0:
                    print("  (none found)")
                else:
                    print(f"  Total: {xref_count} xrefs")
                print()

    finally:
        kernel32.CloseHandle(hProcess)

    return 0


if __name__ == "__main__":
    sys.exit(main())
