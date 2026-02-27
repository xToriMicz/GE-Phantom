"""Analyze packet framing by running captures through the reassembler.

Logs what sizes the reassembler produces for unknown-framing opcodes.
The scan-to-next-opcode strategy reveals actual game packet boundaries.
"""

import json
import sys
import struct
from pathlib import Path
from collections import defaultdict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.sniffer.capture import GEPacket
from src.sniffer.stream import TCPStreamReassembler
from src.protocol.packet_types import KNOWN_PACKETS, HEADER_SIZE

CAPTURES_DIR = Path(__file__).parent.parent / "captures"

# Opcodes we want to investigate
INVESTIGATE = {
    0xa50c: "COMBAT_DATA",
    0x5d0c: "ENTITY_STATE_F64",
    0x4b0c: "ITEM_EVENT",
    0x330e: "EFFECT_DATA",
}


def load_capture(name: str) -> list[dict]:
    path = CAPTURES_DIR / name
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    return data.get("packets", data) if isinstance(data, dict) else data


def analyze_reassembler_output():
    """Run captures through reassembler and log sizes for unknown opcodes."""
    opcode_samples: dict[int, list[dict]] = defaultdict(list)

    for capture_file in sorted(CAPTURES_DIR.glob("*.json")):
        print(f"\n{'='*60}")
        print(f"Processing: {capture_file.name}")
        print(f"{'='*60}")

        packets = load_capture(capture_file.name)
        if not packets:
            print("  (empty or missing)")
            continue

        reassembler = TCPStreamReassembler()
        reassembler.set_framing("opcode_registry")

        game_packets = []
        reassembler.on_game_packet(lambda d, data: game_packets.append((d, data)))

        for pkt_data in packets:
            payload_hex = pkt_data.get("payload_hex", "")
            if not payload_hex:
                continue
            payload = bytes.fromhex(payload_hex)
            direction = pkt_data.get("direction", "S2C")

            src_parts = pkt_data.get("src", "0.0.0.0:0").rsplit(":", 1)
            dst_parts = pkt_data.get("dst", "0.0.0.0:0").rsplit(":", 1)

            pkt = GEPacket(
                timestamp=pkt_data.get("timestamp", 0.0),
                direction=direction,
                src_ip=src_parts[0],
                dst_ip=dst_parts[0],
                src_port=int(src_parts[1]),
                dst_port=int(dst_parts[1]),
                payload=payload,
                seq=pkt_data.get("seq", 0),
                ack=pkt_data.get("ack", 0),
                flags=pkt_data.get("flags", ""),
            )
            reassembler.feed(pkt)

        # Examine game packets for our target opcodes
        for direction, data in game_packets:
            if len(data) < 2:
                continue
            opcode = int.from_bytes(data[:2], "big")
            if opcode in INVESTIGATE:
                b24 = int.from_bytes(data[2:4], "little") if len(data) >= 4 else 0
                sample = {
                    "file": capture_file.name,
                    "size": len(data),
                    "b24_u16le": b24,
                    "hex_20": data[:20].hex(),
                    "direction": direction,
                }
                opcode_samples[opcode].append(sample)
                print(f"  {INVESTIGATE[opcode]:20s} size={len(data):4d}  "
                      f"b[2:4]={b24:5d} (0x{b24:04x})  "
                      f"hex={data[:min(30, len(data))].hex()}")

    # Summary
    print(f"\n\n{'='*60}")
    print("SUMMARY: Sizes per opcode (from reassembler output)")
    print(f"{'='*60}")

    for opcode, name in sorted(INVESTIGATE.items()):
        samples = opcode_samples.get(opcode, [])
        if not samples:
            print(f"\n{name} (0x{opcode:04x}): NO SAMPLES FOUND")
            continue

        sizes = sorted(set(s["size"] for s in samples))
        print(f"\n{name} (0x{opcode:04x}): {len(samples)} samples")
        print(f"  Unique sizes: {sizes}")

        if len(sizes) == 1:
            print(f"  >>> FIXED SIZE: {sizes[0]} bytes")
        else:
            print(f"  >>> VARIABLE: {len(sizes)} different sizes")
            # Check if sizes are multiples of smallest
            smallest = sizes[0]
            multiples = [s / smallest for s in sizes]
            clean = all(m == int(m) for m in multiples)
            if clean:
                print(f"  >>> All sizes are multiples of {smallest}: {[int(m) for m in multiples]}")

        # Per-size detail with length field check
        for sz in sizes:
            matching = [s for s in samples if s["size"] == sz]
            b24_vals = sorted(set(s["b24_u16le"] for s in matching))
            flags = []
            for b24 in b24_vals[:3]:
                if b24 == sz:
                    flags.append(f"b24={b24}==size")
                if b24 == sz - 2:
                    flags.append(f"b24={b24}==size-2")
                if b24 == sz - 4:
                    flags.append(f"b24={b24}==size-4")
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            print(f"  size={sz:4d}: count={len(matching):3d}, "
                  f"b[2:4]={b24_vals[:5]}{flag_str}")

    # Also check: after reassembler, what's left in buffers?
    print(f"\n\nReassembler buffer state at end:")
    # (Can't easily check since we used one per file, but the summary above
    #  shows what the reassembler could extract)


if __name__ == "__main__":
    analyze_reassembler_output()
