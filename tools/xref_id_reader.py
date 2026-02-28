"""
xref_id_reader.py — Read resolved IDs from known xref locations

From disassembly, SplRange xrefs follow the pattern:
    PUSH <string_addr>    ; "SplRange"
    MOV ECX, <obj_addr>   ; this pointer for string resolver
    CALL 0x005E79F2       ; resolve string → ID

The resolver is thiscall at 0x005E79F2 — MOV ECX sets `this`.
We want to read what's AT those addresses to understand the resolver's
context and find the correct parameters for GetPropertyNumber.

Key addresses from handoff:
    0x00D1EBF8  — SplRange xref #1 `this` pointer (MOV ECX, 0x00D1EBF8)
    0x00D200D8  — IES manager singleton
    0x00D219A8  — Default string ID → 0x017A4968
    0x0132CDA8  — TLS index
    0x00D201F8  — Global state counter
"""

import sys
import struct
sys.path.insert(0, ".")

from range_control import PhantomCmd

# ── Addresses to investigate ─────────────────────────────────

ADDR_MAP = {
    # xref resolver context
    0x00D1EBF8: "SplRange xref#1 this ptr (MOV ECX)",

    # IES system globals
    0x00D200D8: "IES manager singleton",
    0x00D219A8: "Default string ID global",
    0x00D201F8: "Global state counter",
    0x0132CDA8: "TLS index global",

    # String addresses (should point to ASCII)
    0x00B9BD64: "SplRange string (.rdata)",
    0x00B82770: "KeepRange string (.rdata)",
    0x00BAF04C: "SetPropertyNumber string",
    0x00BE30C8: "GetPropertyNumber string",
}

# Surrounding context — read a block around the SplRange xref this ptr
DUMP_REGIONS = [
    (0x00D1EBE0, 0x40, "SplRange xref region (0x00D1EBE0..0x00D1EC20)"),
    (0x00D200D0, 0x30, "IES manager region (0x00D200D0..0x00D20100)"),
    (0x00D219A0, 0x20, "Default string ID region"),
]


def hexdump(data: bytes, base_addr: int, width: int = 16) -> str:
    """Format bytes as hex dump with ASCII."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        # Mark DWORD boundaries
        addr = base_addr + offset
        lines.append(f"  {addr:08X}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)


def read_block(cmd: PhantomCmd, start: int, size: int) -> bytes | None:
    """Read a block of memory as 4-byte chunks."""
    data = bytearray()
    for offset in range(0, size, 4):
        val = cmd.read_addr(start + offset)
        if val is None:
            return None
        data.extend(struct.pack("<I", val))
    return bytes(data)


def read_string_at(cmd: PhantomCmd, addr: int, max_len: int = 64) -> str:
    """Read a null-terminated ASCII string starting at addr."""
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
                chars.append(".")
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

    print("[+] Connected to phantom_hook DLL")
    print()

    # ── Step 1: Read all key addresses ──────────────────────
    print("=" * 70)
    print("  STEP 1: Key Address Values")
    print("=" * 70)

    for addr, label in ADDR_MAP.items():
        val = cmd.read_addr(addr)
        if val is not None:
            # Also try to interpret as pointer and read what it points to
            ascii_chars = ""
            for shift in range(4):
                b = (val >> (shift * 8)) & 0xFF
                ascii_chars += chr(b) if 32 <= b < 127 else "."

            extra = ""
            # If this looks like a string address in .rdata, try reading it
            if 0x00B00000 <= addr <= 0x00C00000:
                s = read_string_at(cmd, addr)
                extra = f'  -> "{s}"'
            # If value looks like a pointer, try dereferencing
            elif 0x00400000 <= val <= 0x02000000:
                deref = cmd.read_addr(val)
                if deref is not None:
                    extra = f"  -> *[0x{val:08X}] = 0x{deref:08X}"

            print(f"  [{addr:08X}] = 0x{val:08X}  {ascii_chars}  -- {label}{extra}")
        else:
            print(f"  [{addr:08X}] = (error)  -- {label}")

    print()

    # ── Step 2: Dump memory regions ─────────────────────────
    print("=" * 70)
    print("  STEP 2: Memory Region Dumps")
    print("=" * 70)

    for start, size, label in DUMP_REGIONS:
        print(f"\n  --- {label} ---")
        data = read_block(cmd, start, size)
        if data:
            print(hexdump(data, start))
            # Also show as DWORD array
            dwords = []
            for i in range(0, len(data), 4):
                d = struct.unpack_from("<I", data, i)[0]
                dwords.append(f"0x{d:08X}")
            print(f"  DWORDs: {' '.join(dwords)}")
        else:
            print(f"  (failed to read)")

    print()

    # ── Step 3: Follow pointer chains ───────────────────────
    print("=" * 70)
    print("  STEP 3: Pointer Chain from 0x00D1EBF8")
    print("=" * 70)

    # 0x00D1EBF8 is MOV ECX target — likely a this pointer to an object
    # Read [0x00D1EBF8] to get the object address
    val = cmd.read_addr(0x00D1EBF8)
    if val and 0x00400000 <= val <= 0x20000000:
        print(f"\n  [0x00D1EBF8] = 0x{val:08X} (pointer to object)")
        print(f"  Reading object at 0x{val:08X}:")
        obj_data = read_block(cmd, val, 0x40)
        if obj_data:
            print(hexdump(obj_data, val))
            # The first DWORD is often a vtable pointer
            vtable = struct.unpack_from("<I", obj_data, 0)[0]
            if 0x00400000 <= vtable <= 0x01000000:
                print(f"\n  Possible vtable at 0x{vtable:08X}:")
                vt_data = read_block(cmd, vtable, 0x20)
                if vt_data:
                    print(hexdump(vt_data, vtable))
    elif val is not None:
        print(f"\n  [0x00D1EBF8] = 0x{val:08X} (not a pointer — may be raw ID value)")
    else:
        print(f"\n  [0x00D1EBF8] = (error)")

    print()

    # ── Step 4: IES manager exploration ─────────────────────
    print("=" * 70)
    print("  STEP 4: IES Manager at 0x00D200D8")
    print("=" * 70)

    mgr = cmd.read_addr(0x00D200D8)
    if mgr and 0x00400000 <= mgr <= 0x20000000:
        print(f"\n  [0x00D200D8] = 0x{mgr:08X} (IES manager pointer)")
        print(f"  Reading manager object at 0x{mgr:08X}:")
        mgr_data = read_block(cmd, mgr, 0x60)
        if mgr_data:
            print(hexdump(mgr_data, mgr))
    elif mgr is not None:
        print(f"\n  [0x00D200D8] = 0x{mgr:08X}")
    else:
        print(f"\n  [0x00D200D8] = (error)")

    print()

    # ── Step 5: Check the xref call site ────────────────────
    print("=" * 70)
    print("  STEP 5: Xref Call Site at 0x004180CE (SplRange xref#1)")
    print("=" * 70)

    # Read the code around the xref site to see the full instruction pattern
    xref_data = read_block(cmd, 0x004180B0, 0x60)
    if xref_data:
        print(f"\n  Code at 0x004180B0..0x00418110:")
        print(hexdump(xref_data, 0x004180B0))

        # Try to find the PUSH + MOV ECX + CALL pattern
        print(f"\n  Looking for PUSH/MOV/CALL pattern near 0x004180CE:")
        for i in range(len(xref_data) - 10):
            addr = 0x004180B0 + i
            b = xref_data[i]
            # PUSH imm32: 68 xx xx xx xx
            if b == 0x68 and i + 5 <= len(xref_data):
                imm = struct.unpack_from("<I", xref_data, i + 1)[0]
                if 0x00B00000 <= imm <= 0x00D30000:  # .rdata or .data range
                    s = read_string_at(cmd, imm) if 0x00B00000 <= imm <= 0x00C00000 else ""
                    extra = f' -> "{s}"' if s else ""
                    print(f"    {addr:08X}: PUSH 0x{imm:08X}{extra}")
            # MOV ECX, imm32: B9 xx xx xx xx
            if b == 0xB9 and i + 5 <= len(xref_data):
                imm = struct.unpack_from("<I", xref_data, i + 1)[0]
                print(f"    {addr:08X}: MOV ECX, 0x{imm:08X}")
            # CALL rel32: E8 xx xx xx xx
            if b == 0xE8 and i + 5 <= len(xref_data):
                rel = struct.unpack_from("<i", xref_data, i + 1)[0]  # signed
                target = addr + 5 + rel
                print(f"    {addr:08X}: CALL 0x{target:08X}")

    print()
    print("[*] Done. Check results above for resolver context.")

    cmd.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
