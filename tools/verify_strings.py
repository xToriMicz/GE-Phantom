"""Verify string addresses in ge.exe memory via phantom_hook shared memory."""
import struct
import sys
import time

# Add parent to path
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent))

from range_control import PhantomCmd

def read_string(cmd, addr, max_len=32):
    """Read a null-terminated string from ge.exe memory."""
    data = b""
    for offset in range(0, max_len, 4):
        val = cmd.read_addr(addr + offset)
        if val is None:
            return None
        chunk = struct.pack("<I", val)
        data += chunk
        if b"\x00" in chunk:
            break
    end = data.find(b"\x00")
    if end >= 0:
        data = data[:end]
    return data.decode("ascii", errors="replace")

def main():
    try:
        cmd = PhantomCmd()
    except RuntimeError as e:
        print(f"[!] {e}")
        return 1

    # Verify connection
    if not cmd.ping():
        print("[!] DLL not responding to ping")
        cmd.close()
        return 1
    print("[+] DLL alive — ping OK")
    print()

    # Known string addresses from phantom_hook.h
    addresses = {
        0x00BAD84C: "SetPropertyNumber",
        0x00BE18C8: "GetPropertyNumber",
        0x00B9A564: "SplRange",
        0x00B80F70: "KeepRange",
    }

    print("=== Verifying String Addresses ===")
    for addr, expected in addresses.items():
        text = read_string(cmd, addr)
        if text is None:
            print(f"  0x{addr:08X}: (read failed)")
        elif text == expected:
            print(f"  0x{addr:08X}: \"{text}\" == \"{expected}\" OK")
        else:
            print(f"  0x{addr:08X}: \"{text}\" != \"{expected}\" MISMATCH")
    print()

    # Also read the context around the SplRange xref at 0x005A9FD1
    print("=== SplRange Xref Context (0x005A9FD1) ===")
    for offset in range(-20, 40, 4):
        addr = 0x005A9FD1 + offset
        val = cmd.read_addr(addr)
        if val is not None:
            # Show as hex bytes
            b = struct.pack("<I", val)
            hex_str = " ".join(f"{x:02X}" for x in b)
            ascii_str = "".join(chr(x) if 32 <= x < 127 else "." for x in b)
            marker = " <<<" if offset == 0 else ""
            print(f"  0x{addr:08X}: {hex_str}  {ascii_str}{marker}")

    # Let's also try to find the actual string locations by reading
    # a wider range in .rdata
    print()
    print("=== Searching for strings in .rdata (0x00B6B000+) ===")
    print("  Looking for 'SetPropertyNumber'...")

    # Search in chunks
    target = b"SetPropertyNumber"
    found_addrs = []
    for base in range(0x00B6B000, 0x00C00000, 4096):
        chunk = b""
        for off in range(0, 256, 4):
            val = cmd.read_addr(base + off)
            if val is not None:
                chunk += struct.pack("<I", val)
            else:
                chunk += b"\x00\x00\x00\x00"
        idx = chunk.find(target)
        if idx >= 0:
            found_addr = base + idx
            found_addrs.append(found_addr)
            print(f"  Found at 0x{found_addr:08X}")

    if not found_addrs:
        print("  Not found in scanned range")

    print()
    print("  Looking for 'GetPropertyNumber'...")
    target2 = b"GetPropertyNumber"
    for base in range(0x00B6B000, 0x00C00000, 4096):
        chunk = b""
        for off in range(0, 256, 4):
            val = cmd.read_addr(base + off)
            if val is not None:
                chunk += struct.pack("<I", val)
            else:
                chunk += b"\x00\x00\x00\x00"
        idx = chunk.find(target2)
        if idx >= 0:
            found_addr = base + idx
            print(f"  Found at 0x{found_addr:08X}")

    cmd.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
