"""Verify packet coverage after framing updates.

Replays capture data through the reassembler with updated packet_types
and reports:
- Total game packets parsed
- Known vs unknown opcode ratio
- Per-opcode breakdown
- Coverage percentage
"""

import json
import sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.protocol.packet_types import KNOWN_PACKETS, get_packet_size, HEADER_SIZE
from src.sniffer.capture import GEPacket
from src.sniffer.stream import TCPStreamReassembler

CAPTURES_DIR = Path(__file__).parent.parent / "captures"


def main():
    # Count registered opcodes with known framing
    fixed_count = sum(1 for p in KNOWN_PACKETS.values() if p.size is not None)
    length_field_count = sum(1 for p in KNOWN_PACKETS.values()
                            if p.size is None and p.length_field_offset is not None)
    unknown_framing = sum(1 for p in KNOWN_PACKETS.values()
                          if p.size is None and p.length_field_offset is None)
    total_registered = len(KNOWN_PACKETS)

    print(f"REGISTERED OPCODES: {total_registered}")
    print(f"  Fixed size: {fixed_count}")
    print(f"  Length field: {length_field_count}")
    print(f"  Unknown framing: {unknown_framing}")
    confirmed = sum(1 for p in KNOWN_PACKETS.values() if p.confirmed)
    print(f"  Confirmed: {confirmed}/{total_registered}")

    # List unknown-framing opcodes
    if unknown_framing > 0:
        print(f"\n  Unknown framing opcodes:")
        for opc, pdef in sorted(KNOWN_PACKETS.items()):
            if pdef.size is None and pdef.length_field_offset is None:
                print(f"    0x{opc:04x} {pdef.name}")

    # Replay each capture
    for capture_file in sorted(CAPTURES_DIR.glob("*.json")):
        print(f"\n{'='*60}")
        print(f"REPLAYING: {capture_file.name}")
        print(f"{'='*60}")

        data = json.loads(capture_file.read_text())
        raw_packets = data.get("packets", data) if isinstance(data, dict) else data
        if not raw_packets:
            print("  (empty)")
            continue

        # Set up reassembler
        reassembler = TCPStreamReassembler()
        reassembler.set_framing("opcode_registry")

        game_packets = []
        reassembler.on_game_packet(lambda d, pkt_data: game_packets.append((d, pkt_data)))

        # Feed packets
        for pkt_data in raw_packets:
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
                src_port=int(src_parts[1]) if len(src_parts) > 1 else 0,
                dst_port=int(dst_parts[1]) if len(dst_parts) > 1 else 0,
                payload=payload,
                seq=pkt_data.get("seq", 0),
                ack=pkt_data.get("ack", 0),
                flags=pkt_data.get("flags", ""),
            )
            reassembler.feed(pkt)

        # Analyze results
        opcode_counts = Counter()
        known_count = 0
        unknown_count = 0
        unknown_opcodes = Counter()
        boundary_scanned = 0  # packets that needed boundary scanning (no deterministic framing)

        for direction, pkt_data in game_packets:
            if len(pkt_data) < 2:
                continue
            opcode = int.from_bytes(pkt_data[:2], "big")
            pdef = KNOWN_PACKETS.get(opcode)
            if pdef is not None:
                known_count += 1
                opcode_counts[f"{direction}:0x{opcode:04x}:{pdef.name}"] += 1

                # Check if this packet used deterministic framing
                pkt_size = get_packet_size(pkt_data[:min(len(pkt_data), 8)])
                if pkt_size is None:
                    boundary_scanned += 1
            else:
                unknown_count += 1
                unknown_opcodes[f"0x{opcode:04x}"] += 1

        total = known_count + unknown_count
        coverage = (known_count / total * 100) if total > 0 else 0

        print(f"\n  Total game packets: {total}")
        print(f"  Known: {known_count} ({coverage:.1f}%)")
        print(f"  Unknown: {unknown_count} ({100-coverage:.1f}%)")
        print(f"  Boundary-scanned: {boundary_scanned} (needed fallback)")
        print(f"  Reassembler stats: {reassembler.stats()}")

        if unknown_opcodes:
            print(f"\n  Unknown opcodes:")
            for opc, cnt in unknown_opcodes.most_common(20):
                print(f"    {opc}: {cnt}x")

        # Top opcodes
        print(f"\n  Top opcodes:")
        for key, cnt in opcode_counts.most_common(15):
            print(f"    {key}: {cnt}x")


if __name__ == "__main__":
    main()
