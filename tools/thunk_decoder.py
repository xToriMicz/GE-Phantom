"""
thunk_decoder.py -- Decode the resolver thunk table at 0x00418080+

Each thunk is 16 bytes:
    68 XX XX XX XX    PUSH <string_addr>       ; .rdata string
    B9 XX XX XX XX    MOV ECX, <slot_addr>     ; global cache slot
    E8 XX XX XX XX    CALL <resolver>          ; 0x005E79F2
    C3                RET

We decode these to find ALL interned string names and their resolved values.
This gives us the complete vocabulary the game uses with IES.
"""

import sys
import struct
sys.path.insert(0, ".")

from range_control import PhantomCmd


def read_block(cmd, start, size):
    """Read memory block as bytes."""
    data = bytearray()
    for offset in range(0, size, 4):
        val = cmd.read_addr(start + offset)
        if val is None:
            return None
        data.extend(struct.pack("<I", val))
    return bytes(data)


def read_string_at(cmd, addr, max_len=64):
    """Read null-terminated ASCII string."""
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
                return "".join(chars)  # non-printable = end
    return "".join(chars)


def decode_thunks(cmd, start, count=64):
    """Decode resolver thunks starting at `start`. Each is 16 bytes."""
    thunks = []
    data = read_block(cmd, start, count * 16)
    if not data:
        return thunks

    for i in range(count):
        off = i * 16
        chunk = data[off:off + 16]
        if len(chunk) < 16:
            break

        # Check pattern: 68 xx xx xx xx B9 xx xx xx xx E8 xx xx xx xx C3
        if chunk[0] != 0x68 or chunk[5] != 0xB9 or chunk[10] != 0xE8 or chunk[15] != 0xC3:
            # Not a thunk -- stop
            break

        str_addr = struct.unpack_from("<I", chunk, 1)[0]
        slot_addr = struct.unpack_from("<I", chunk, 6)[0]
        call_rel = struct.unpack_from("<i", chunk, 11)[0]  # signed
        call_target = (start + off + 10) + 5 + call_rel
        thunk_addr = start + off

        thunks.append({
            "addr": thunk_addr,
            "str_addr": str_addr,
            "slot_addr": slot_addr,
            "call_target": call_target,
        })

    return thunks


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

    print("[+] Connected to phantom_hook DLL\n")

    # We know the thunks are at 0x004180B0 area. Let's scan a wider range
    # to find the start and extent of the thunk table.

    # First, scan backwards from 0x004180B0 to find the start
    KNOWN_THUNK = 0x004180CD  # SplRange thunk (PUSH at this addr -1)
    # Actually the SplRange PUSH is at 0x004180CD, thunk starts there
    # Let's try scanning from 0x00418000

    # Scan a large range and decode thunks
    SCAN_START = 0x00418000
    SCAN_SIZE = 0x800  # 2KB should cover many thunks

    print(f"Scanning for resolver thunks from 0x{SCAN_START:08X}...")
    data = read_block(cmd, SCAN_START, SCAN_SIZE)
    if not data:
        print("[!] Failed to read code region")
        cmd.close()
        return 1

    # Find all thunk patterns in the data
    thunks = []
    i = 0
    while i < len(data) - 16:
        # Look for: 68 xx xx xx xx B9 xx xx xx xx E8 xx xx xx xx C3
        if (data[i] == 0x68 and data[i+5] == 0xB9 and
            data[i+10] == 0xE8 and data[i+15] == 0xC3):

            str_addr = struct.unpack_from("<I", data, i+1)[0]
            slot_addr = struct.unpack_from("<I", data, i+6)[0]
            call_rel = struct.unpack_from("<i", data, i+11)[0]
            call_target = (SCAN_START + i + 10) + 5 + call_rel

            thunks.append({
                "addr": SCAN_START + i,
                "str_addr": str_addr,
                "slot_addr": slot_addr,
                "call_target": call_target,
            })
            i += 16
        else:
            i += 1

    print(f"Found {len(thunks)} resolver thunks\n")

    if not thunks:
        print("[!] No thunks found")
        cmd.close()
        return 1

    # For each thunk, read the string name and the resolved value
    print(f"{'Thunk':>10s}  {'String':>10s}  {'Slot':>10s}  {'Resolver':>10s}  {'Resolved':>10s}  Name")
    print("-" * 90)

    names_by_slot = {}

    for t in thunks:
        # Read the string name from .rdata
        name = read_string_at(cmd, t["str_addr"])

        # Read the resolved value from the global slot
        resolved = cmd.read_addr(t["slot_addr"])
        resolved_str = f"0x{resolved:08X}" if resolved else "(null)"

        # If resolved is a pointer, try reading what's there (should be the interned string)
        interned = ""
        if resolved and 0x01000000 <= resolved <= 0x30000000:
            interned = read_string_at(cmd, resolved)

        marker = ""
        if name == "SplRange":
            marker = " <<<"
        elif name == "KeepRange":
            marker = " <<<"

        print(f"0x{t['addr']:08X}  0x{t['str_addr']:08X}  0x{t['slot_addr']:08X}  "
              f"0x{t['call_target']:08X}  {resolved_str}  {name}{marker}")

        names_by_slot[t["slot_addr"]] = name

    # Now let's look at what the resolver returns for interned strings
    # The resolved pointer should point to the string data in a string pool
    print(f"\n{'='*90}")
    print("INTERNED STRING OBJECTS (reading resolved pointers)")
    print(f"{'='*90}\n")

    # Focus on range-related properties
    range_props = ["SplRange", "KeepRange", "ViewRange", "AiRange",
                   "MaxLinkRange", "Level", "HP", "STR", "ClassName"]

    for t in thunks:
        name = read_string_at(cmd, t["str_addr"])
        if not name:
            continue

        resolved = cmd.read_addr(t["slot_addr"])
        if not resolved or resolved < 0x01000000:
            continue

        # Read 32 bytes of the interned object
        obj_data = read_block(cmd, resolved, 32)
        if not obj_data:
            continue

        # Show details for interesting properties
        show = (name in range_props or
                "range" in name.lower() or
                "class" in name.lower() or
                "obj" in name.lower() or
                "id" in name.lower())

        if show:
            hex_str = " ".join(f"{b:02X}" for b in obj_data[:32])
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in obj_data[:32])
            print(f"  {name}: [0x{resolved:08X}]")
            print(f"    {hex_str}")
            print(f"    {ascii_str}")
            print()

    # Summary: slot address range
    if thunks:
        slots = sorted(t["slot_addr"] for t in thunks)
        print(f"\nSlot address range: 0x{slots[0]:08X} .. 0x{slots[-1]:08X}")
        print(f"Total interned strings: {len(thunks)}")

        # Dump the full slot table (these are all in a contiguous global array)
        print(f"\nSlot table ({len(slots)} entries):")
        for slot in slots:
            name = names_by_slot.get(slot, "?")
            val = cmd.read_addr(slot)
            val_str = f"0x{val:08X}" if val else "(null)"
            if val and 0x01000000 <= val <= 0x30000000:
                interned = read_string_at(cmd, val)
                print(f"  [0x{slot:08X}] = {val_str}  -> \"{interned}\"")
            else:
                print(f"  [0x{slot:08X}] = {val_str}")

    cmd.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
