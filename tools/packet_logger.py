"""
GE_Phantom — Packet Logger

Reads packets from phantom_hook.dll via named pipe and displays them
in real-time. This is the first time we see C2S packets in plaintext!

Usage:
  python tools/packet_logger.py                    # Live display
  python tools/packet_logger.py --save             # Save to JSON
  python tools/packet_logger.py --filter c2s       # Only client→server
  python tools/packet_logger.py --filter s2c       # Only server→client
  python tools/packet_logger.py --opcode 0x540c    # Filter by opcode
  python tools/packet_logger.py --raw              # Show full hex dump

Requires: phantom_hook.dll injected into ge.exe (via dll_injector.py)
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

# ── Constants (must match phantom_hook.h) ──────────────────────

PIPE_NAME        = r"\\.\pipe\ge_phantom"
PIPE_HEADER_SIZE = 8
DIR_C2S          = 0x01
DIR_S2C          = 0x02
MAX_PACKET_LOG   = 65536

# Named pipe access
GENERIC_READ     = 0x80000000
OPEN_EXISTING    = 3
INVALID_HANDLE   = -1

# Shared memory
SHMEM_NAME       = "Local\\ge_phantom_ctl"
CTL_HOOK_ACTIVE  = 0x01
CTL_LOG_SEND     = 0x02
CTL_LOG_RECV     = 0x04

# ── Protocol knowledge (from our packet analysis) ─────────────

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from src.protocol.packet_types import KNOWN_PACKETS, HEADER_SIZE
    HAS_PROTOCOL = True
except ImportError:
    KNOWN_PACKETS = {}
    HEADER_SIZE = 4
    HAS_PROTOCOL = False

DIR_LABELS = {
    DIR_C2S: "C2S",
    DIR_S2C: "S2C",
}

DIR_COLORS = {
    DIR_C2S: "\033[93m",  # Yellow
    DIR_S2C: "\033[96m",  # Cyan
}
RESET = "\033[0m"
DIM   = "\033[90m"
BOLD  = "\033[1m"

# ── Win32 pipe API via ctypes ──────────────────────────────────

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


def open_pipe() -> int:
    """Connect to the named pipe created by phantom_hook.dll."""
    handle = kernel32.CreateFileA(
        PIPE_NAME.encode("ascii"),
        GENERIC_READ,
        0,      # No sharing
        None,   # Default security
        OPEN_EXISTING,
        0,      # Default attributes
        None,
    )
    if handle == INVALID_HANDLE:
        return None
    return handle


def read_pipe(handle, size: int) -> bytes | None:
    """Read exactly `size` bytes from the pipe."""
    buf = ctypes.create_string_buffer(size)
    read = wt.DWORD(0)
    ok = kernel32.ReadFile(
        handle,
        buf,
        size,
        ctypes.byref(read),
        None,
    )
    if not ok or read.value == 0:
        return None
    return buf.raw[:read.value]


# ── Packet Display ─────────────────────────────────────────────

def hex_dump(data: bytes, max_bytes: int = 128) -> str:
    """Format bytes as a hex dump."""
    lines = []
    show = data[:max_bytes]
    for i in range(0, len(show), 16):
        chunk = show[i:i+16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04X}  {hex_part:<48s}  {ascii_part}")

    if len(data) > max_bytes:
        lines.append(f"  ... ({len(data) - max_bytes} more bytes)")

    return "\n".join(lines)


def decode_opcode(data: bytes) -> tuple[int | None, str]:
    """Extract opcode from packet and look up name."""
    if len(data) < 2:
        return None, "???"

    opcode = struct.unpack_from("<H", data, 0)[0]
    name = KNOWN_PACKETS.get(opcode, {}).get("name", "") if HAS_PROTOCOL else ""
    return opcode, name


def format_packet(direction: int, data: bytes, tick: int, seq: int,
                  show_raw: bool = False, max_hex: int = 128) -> str:
    """Format a single packet for display."""
    dir_label = DIR_LABELS.get(direction, "???")
    color = DIR_COLORS.get(direction, "")
    opcode, name = decode_opcode(data)

    # Header line
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    opcode_str = f"0x{opcode:04X}" if opcode is not None else "????"
    name_str = f" {name}" if name else ""

    header = (
        f"{DIM}{ts}{RESET} "
        f"{color}{BOLD}{dir_label}{RESET} "
        f"#{seq:<6d} "
        f"{color}{opcode_str}{name_str}{RESET} "
        f"({len(data)} bytes)"
    )

    if show_raw:
        return f"{header}\n{hex_dump(data, max_hex)}"
    else:
        # Compact: show first 32 bytes inline
        preview = " ".join(f"{b:02X}" for b in data[:32])
        if len(data) > 32:
            preview += " ..."
        return f"{header}\n  {DIM}{preview}{RESET}"


# ── Packet Recording ──────────────────────────────────────────

class PacketRecorder:
    """Records packets to a JSON file for offline analysis."""

    def __init__(self, path: Path):
        self.path = path
        self.packets: list[dict] = []
        self.start_time = time.time()

    def add(self, direction: int, data: bytes, tick: int, seq: int):
        opcode, name = decode_opcode(data)
        self.packets.append({
            "seq": seq,
            "time": time.time() - self.start_time,
            "tick": tick,
            "dir": DIR_LABELS.get(direction, "???"),
            "opcode": f"0x{opcode:04X}" if opcode is not None else None,
            "name": name or None,
            "len": len(data),
            "hex": data.hex(),
        })

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as f:
            json.dump({
                "capture_time": datetime.now().isoformat(),
                "total_packets": len(self.packets),
                "packets": self.packets,
            }, f, indent=2)
        print(f"\n[*] Saved {len(self.packets)} packets to {self.path}")


# ── Main Loop ──────────────────────────────────────────────────

def run_logger(
    direction_filter: str | None = None,
    opcode_filter: int | None = None,
    show_raw: bool = False,
    save_path: Path | None = None,
    max_hex: int = 128,
):
    """Main packet reading loop."""
    print("[*] GE_Phantom Packet Logger")
    print(f"[*] Connecting to pipe: {PIPE_NAME}")
    print()

    # Try to connect to pipe
    handle = None
    for attempt in range(30):
        handle = open_pipe()
        if handle is not None:
            break
        if attempt == 0:
            print("[*] Waiting for phantom_hook.dll pipe...")
        time.sleep(1)

    if handle is None:
        print("[!] Could not connect to pipe after 30 seconds")
        print("    Is phantom_hook.dll injected? Run:")
        print("    python tools/dll_injector.py inject")
        return 1

    print("[+] Connected to phantom_hook pipe!")
    print("[*] Listening for packets... (Ctrl+C to stop)")
    print()

    # Filter setup
    dir_code = None
    if direction_filter:
        if direction_filter.lower() == "c2s":
            dir_code = DIR_C2S
            print(f"[*] Filter: C2S only")
        elif direction_filter.lower() == "s2c":
            dir_code = DIR_S2C
            print(f"[*] Filter: S2C only")

    if opcode_filter is not None:
        print(f"[*] Filter: opcode 0x{opcode_filter:04X}")

    # Recorder
    recorder = PacketRecorder(save_path) if save_path else None

    seq = 0
    c2s_count = 0
    s2c_count = 0

    try:
        while True:
            # Read pipe header
            header_data = read_pipe(handle, PIPE_HEADER_SIZE)
            if header_data is None or len(header_data) < PIPE_HEADER_SIZE:
                print("\n[!] Pipe disconnected")
                break

            direction = header_data[0]
            payload_len = struct.unpack_from("<H", header_data, 2)[0]
            tick = struct.unpack_from("<I", header_data, 4)[0]

            if payload_len <= 0 or payload_len > MAX_PACKET_LOG:
                continue

            # Read payload
            payload = read_pipe(handle, payload_len)
            if payload is None or len(payload) < payload_len:
                print("\n[!] Incomplete packet read")
                break

            seq += 1

            # Update counters
            if direction == DIR_C2S:
                c2s_count += 1
            elif direction == DIR_S2C:
                s2c_count += 1

            # Apply filters
            if dir_code is not None and direction != dir_code:
                continue

            if opcode_filter is not None:
                pkt_opcode, _ = decode_opcode(payload)
                if pkt_opcode != opcode_filter:
                    continue

            # Display
            print(format_packet(direction, payload, tick, seq, show_raw, max_hex))

            # Record
            if recorder:
                recorder.add(direction, payload, tick, seq)

    except KeyboardInterrupt:
        print(f"\n\n[*] Stopped. Captured: {c2s_count} C2S, {s2c_count} S2C ({seq} total)")

    finally:
        kernel32.CloseHandle(handle)
        if recorder:
            recorder.save()

    return 0


# ── CLI ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="GE_Phantom Packet Logger — read hooked packets from ge.exe"
    )
    parser.add_argument(
        "--filter", choices=["c2s", "s2c"],
        help="Filter by direction"
    )
    parser.add_argument(
        "--opcode", type=lambda x: int(x, 0),
        help="Filter by opcode (hex, e.g. 0x540c)"
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="Show full hex dump for each packet"
    )
    parser.add_argument(
        "--save", nargs="?", const="auto",
        help="Save packets to JSON (default: auto-named in captures/)"
    )
    parser.add_argument(
        "--max-hex", type=int, default=128,
        help="Max bytes to show in hex dump (default: 128)"
    )

    args = parser.parse_args()

    # Resolve save path
    save_path = None
    if args.save:
        if args.save == "auto":
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = ROOT / "captures" / f"hooked_{ts}.json"
        else:
            save_path = Path(args.save)

    return run_logger(
        direction_filter=args.filter,
        opcode_filter=args.opcode,
        show_raw=args.raw,
        save_path=save_path,
        max_hex=args.max_hex,
    )


if __name__ == "__main__":
    sys.exit(main())
