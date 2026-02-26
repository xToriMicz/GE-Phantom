"""
GE_Phantom — Attack Range Scanner & Modifier

Scans ge.exe memory for attack range float values and optionally modifies them.
Must run as Administrator!

Usage:
  python tools/range_scanner.py                    # Scan only
  python tools/range_scanner.py --set 2000         # Set all range values to 2000
  python tools/range_scanner.py --scan 803.0       # Scan specific value
"""

import ctypes
import ctypes.wintypes as wt
import struct
import sys
import argparse


# Windows API constants
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

READABLE_PROTECTIONS = {
    0x02,  # PAGE_READONLY
    0x04,  # PAGE_READWRITE
    0x20,  # PAGE_EXECUTE_READ
    0x40,  # PAGE_EXECUTE_READWRITE
}

WRITABLE_PROTECTIONS = {
    0x04,  # PAGE_READWRITE
    0x40,  # PAGE_EXECUTE_READWRITE
}

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


def find_ge_pid() -> int | None:
    """Find ge.exe process ID."""
    import subprocess
    result = subprocess.run(
        ["powershell", "-Command",
         'Get-Process -Name "ge" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id'],
        capture_output=True, text=True
    )
    pids = result.stdout.strip().split()
    return int(pids[0]) if pids else None


def scan_memory(pid: int, target_float: float) -> list[int]:
    """Scan process memory for a float value. Returns list of addresses."""
    target_bytes = struct.pack("<f", target_float)

    access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        err = ctypes.get_last_error()
        if err == 5:
            print("[!] Access denied — run as Administrator!")
        else:
            print(f"[!] OpenProcess failed: error {err}")
        return []

    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    found = []
    bytes_scanned = 0

    while address < 0x7FFFFFFFFFFF:
        result = kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        if result == 0:
            break

        if (mbi.State == MEM_COMMIT
                and mbi.Protect in READABLE_PROTECTIONS
                and mbi.RegionSize < 100_000_000):

            buf = ctypes.create_string_buffer(mbi.RegionSize)
            bytes_read = ctypes.c_size_t(0)

            if kernel32.ReadProcessMemory(
                handle, ctypes.c_void_p(mbi.BaseAddress),
                buf, mbi.RegionSize, ctypes.byref(bytes_read)
            ):
                data = buf.raw[:bytes_read.value]
                pos = 0
                while True:
                    pos = data.find(target_bytes, pos)
                    if pos == -1:
                        break
                    addr = mbi.BaseAddress + pos
                    # Check if it's in a writable region (more likely to be data, not code)
                    is_writable = mbi.Protect in WRITABLE_PROTECTIONS
                    found.append((addr, is_writable))
                    pos += 4

                bytes_scanned += bytes_read.value

        address = mbi.BaseAddress + mbi.RegionSize

    kernel32.CloseHandle(handle)
    print(f"[*] Scanned {bytes_scanned / 1024 / 1024:.0f} MB")
    return found


def write_float(pid: int, address: int, value: float) -> bool:
    """Write a float value to a specific address in process memory."""
    access = PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        print(f"[!] OpenProcess for write failed: {ctypes.get_last_error()}")
        return False

    data = struct.pack("<f", value)
    bytes_written = ctypes.c_size_t(0)
    result = kernel32.WriteProcessMemory(
        handle, ctypes.c_void_p(address),
        data, len(data), ctypes.byref(bytes_written)
    )

    kernel32.CloseHandle(handle)
    return bool(result)


def read_float(pid: int, address: int) -> float | None:
    """Read a float value from a specific address."""
    access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        return None

    buf = ctypes.create_string_buffer(4)
    bytes_read = ctypes.c_size_t(0)
    result = kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(address),
        buf, 4, ctypes.byref(bytes_read)
    )

    kernel32.CloseHandle(handle)
    if result and bytes_read.value == 4:
        return struct.unpack("<f", buf.raw)[0]
    return None


def main():
    parser = argparse.ArgumentParser(description="GE_Phantom Attack Range Scanner")
    parser.add_argument("--scan", type=float, help="Float value to scan for")
    parser.add_argument("--set", type=float, help="New range value to set")
    parser.add_argument("--pid", type=int, help="Game process ID (auto-detected if omitted)")
    args = parser.parse_args()

    # Check admin
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[!] Not running as Administrator!")
        print("[!] Right-click terminal -> Run as Administrator")
        sys.exit(1)

    # Find game
    pid = args.pid or find_ge_pid()
    if not pid:
        print("[!] ge.exe not found!")
        sys.exit(1)
    print(f"[*] Found ge.exe PID: {pid}")

    # Known range values from packet analysis
    known_ranges = [850.0, 803.0]
    scan_values = [args.scan] if args.scan else known_ranges

    all_addresses = {}  # value -> [(addr, writable)]

    for target in scan_values:
        print(f"\n[*] Scanning for float {target} ({struct.pack('<f', target).hex()})...")
        results = scan_memory(pid, target)

        writable = [(addr, w) for addr, w in results if w]
        readonly = [(addr, w) for addr, w in results if not w]

        print(f"[*] Found {len(results)} total ({len(writable)} writable, {len(readonly)} read-only)")

        all_addresses[target] = writable  # Only care about writable for modification

        if writable:
            print(f"\n  Writable addresses (candidates for modification):")
            for addr, _ in writable[:20]:
                print(f"    0x{addr:016X}")
            if len(writable) > 20:
                print(f"    ... and {len(writable) - 20} more")

    # Modify if requested
    if args.set is not None:
        new_value = args.set
        print(f"\n{'='*60}")
        print(f"  MODIFYING RANGE: {scan_values} -> {new_value}")
        print(f"{'='*60}")

        total_modified = 0
        for old_value, addresses in all_addresses.items():
            if not addresses:
                continue
            print(f"\n  Changing {old_value} -> {new_value} ({len(addresses)} locations)...")

            for addr, _ in addresses:
                # Verify current value before writing
                current = read_float(pid, addr)
                if current is not None and abs(current - old_value) < 0.1:
                    if write_float(pid, addr, new_value):
                        verify = read_float(pid, addr)
                        if verify is not None and abs(verify - new_value) < 0.1:
                            total_modified += 1
                        else:
                            print(f"    [!] Write to 0x{addr:016X} didn't stick")

        print(f"\n[*] Modified {total_modified} memory locations")
        print(f"[*] Try attacking a monster now to see if range changed!")
        print(f"[*] Note: server may still validate range — if it doesn't work,")
        print(f"    the range check is server-side and can't be bypassed.")


if __name__ == "__main__":
    main()
