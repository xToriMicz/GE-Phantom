"""
thunk_full_scan.py -- Scan a wide range to find ALL resolver thunks

The thunks at 0x00418000+ only covered S-Z. Need to find the full table
(A-Z) to discover class names for GetPropertyNumber objName parameter.

Each thunk: 68 XX XX XX XX B9 XX XX XX XX E8 XX XX XX XX C3 (16 bytes)
"""

import sys
import struct
sys.path.insert(0, ".")

from range_control import PhantomCmd


def read_block(cmd, start, size):
    data = bytearray()
    for offset in range(0, size, 4):
        val = cmd.read_addr(start + offset)
        if val is None:
            return None
        data.extend(struct.pack("<I", val))
    return bytes(data)


def read_string_at(cmd, addr, max_len=64):
    chars = []
    for offset in range(0, max_len, 4):
        val = cmd.read_addr(addr + offset)
        if val is None:
            break
        for shift in range(4):
            b = (val >> (shift * 8)) & 0xFF
            if b == 0:
                return "".join(chars)
            if 32 <= b < 127:
                chars.append(chr(b))
            else:
                return "".join(chars)
    return "".join(chars)


def main():
    try:
        cmd = PhantomCmd()
    except RuntimeError as e:
        print(f"[!] {e}")
        return 1

    if not cmd.ping():
        print("[!] DLL not responding")
        cmd.close()
        return 1

    print("[+] Connected\n")

    # Scan a much wider range: 0x00410000 to 0x00420000 (64KB)
    # The thunks are likely in a contiguous block
    SCAN_START = 0x00410000
    SCAN_SIZE = 0x10000  # 64KB

    print(f"Scanning 0x{SCAN_START:08X}..0x{SCAN_START+SCAN_SIZE:08X} for thunks...")
    print("(this may take a minute - reading 16384 DWORDs)\n")

    data = read_block(cmd, SCAN_START, SCAN_SIZE)
    if not data:
        print("[!] Failed to read")
        cmd.close()
        return 1

    # Find all thunk patterns
    thunks = []
    i = 0
    while i < len(data) - 16:
        if (data[i] == 0x68 and data[i+5] == 0xB9 and
            data[i+10] == 0xE8 and data[i+15] == 0xC3):

            str_addr = struct.unpack_from("<I", data, i+1)[0]
            slot_addr = struct.unpack_from("<I", data, i+6)[0]
            call_rel = struct.unpack_from("<i", data, i+11)[0]
            call_target = (SCAN_START + i + 10) + 5 + call_rel

            # Sanity check: string should be in .rdata, slot in .data
            if (0x00B00000 <= str_addr <= 0x00C50000 and
                0x00C50000 <= slot_addr <= 0x01400000 and
                call_target == 0x005E79F2):
                thunks.append({
                    "addr": SCAN_START + i,
                    "str_addr": str_addr,
                    "slot_addr": slot_addr,
                })
                i += 16
            else:
                i += 1
        else:
            i += 1

    print(f"Found {len(thunks)} resolver thunks\n")

    # Resolve all names
    all_names = []
    for t in thunks:
        name = read_string_at(cmd, t["str_addr"])
        t["name"] = name
        all_names.append(name)

    # Print sorted by name
    print(f"{'#':>4s}  {'Thunk':>10s}  {'Slot':>10s}  Name")
    print("-" * 60)

    for idx, t in enumerate(thunks):
        marker = ""
        n = t["name"].lower()
        if "range" in n:
            marker = " <<< RANGE"
        elif "class" in n:
            marker = " <<< CLASS"
        elif n in ("skill", "stance", "weapon", "type", "item"):
            marker = " <<< CANDIDATE"
        print(f"{idx+1:4d}  0x{t['addr']:08X}  0x{t['slot_addr']:08X}  {t['name']}{marker}")

    # Categorize interesting names for GetPropertyNumber
    print(f"\n{'='*60}")
    print("POTENTIAL objName CANDIDATES (class-like names):")
    print(f"{'='*60}")

    class_candidates = []
    range_props = []
    for t in thunks:
        n = t["name"]
        nl = n.lower()
        if "range" in nl:
            range_props.append(n)
        if (nl in ("skill", "stance", "weapon", "item", "character",
                   "monster", "npc", "map", "quest", "buff", "pet",
                   "recipe", "world", "pc", "char") or
            "class" in nl or "idspace" in nl or "table" in nl or
            "property" in nl):
            class_candidates.append(n)

    print(f"\nRange properties: {range_props}")
    print(f"Class candidates: {class_candidates}")

    # Also check for KeepRange specifically
    has_keep = any(t["name"] == "KeepRange" for t in thunks)
    print(f"\nKeepRange found: {has_keep}")

    cmd.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
