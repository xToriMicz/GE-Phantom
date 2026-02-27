"""Analyze remaining unknown packets in reassembled context.

Replays live_test_01.json through the reassembler and dumps details
about each unknown packet — hex, size, what comes before/after.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.protocol.packet_types import KNOWN_PACKETS, get_packet_size
from src.sniffer.capture import GEPacket
from src.sniffer.stream import TCPStreamReassembler


def main():
    capture_file = Path(__file__).parent.parent / "captures" / "live_test_01.json"
    data = json.loads(capture_file.read_text())
    raw_packets = data.get("packets", data) if isinstance(data, dict) else data

    reassembler = TCPStreamReassembler()
    reassembler.set_framing("opcode_registry")

    packets = []  # (direction, data)

    def on_pkt(direction, pkt_data):
        packets.append((direction, pkt_data))

    reassembler.on_game_packet(on_pkt)

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

    # Find unknowns and their context
    unknowns = []
    for i, (direction, pdata) in enumerate(packets):
        opcode = int.from_bytes(pdata[:2], "big")
        pdef = KNOWN_PACKETS.get(opcode)
        if pdef is None:
            prev_pkt = packets[i - 1] if i > 0 else None
            next_pkt = packets[i + 1] if i + 1 < len(packets) else None

            prev_info = "START"
            if prev_pkt:
                prev_op = int.from_bytes(prev_pkt[1][:2], "big")
                prev_def = KNOWN_PACKETS.get(prev_op)
                prev_name = prev_def.name if prev_def else f"UNKNOWN_{prev_op:#06x}"
                prev_info = f"{prev_name} ({len(prev_pkt[1])}b)"

            next_info = "END"
            if next_pkt:
                next_op = int.from_bytes(next_pkt[1][:2], "big")
                next_def = KNOWN_PACKETS.get(next_op)
                next_name = next_def.name if next_def else f"UNKNOWN_{next_op:#06x}"
                next_info = f"{next_name} ({len(next_pkt[1])}b)"

            unknowns.append({
                "index": i,
                "opcode": opcode,
                "size": len(pdata),
                "data": pdata,
                "hex_head": pdata[:40].hex(" "),
                "prev": prev_info,
                "next": next_info,
                "direction": direction,
            })

    print(f"\nTotal packets: {len(packets)}")
    print(f"Unknown packets: {len(unknowns)}")
    print(f"Coverage: {(len(packets) - len(unknowns)) / len(packets) * 100:.2f}%")
    print(f"Need <=17 unknowns for 99% ({len(packets)} * 0.01 = {len(packets) * 0.01:.1f})")
    print()

    # Group by opcode
    by_opcode = defaultdict(list)
    for u in unknowns:
        by_opcode[u["opcode"]].append(u)

    for opcode in sorted(by_opcode.keys(), key=lambda o: -len(by_opcode[o])):
        instances = by_opcode[opcode]
        print(f"{'='*70}")
        print(f"UNKNOWN {opcode:#06x} — {len(instances)} instance(s)")
        print(f"{'='*70}")

        sizes = [u["size"] for u in instances]
        print(f"  Sizes: {sizes}")

        if len(set(sizes)) == 1:
            print(f"  >>> ALL SAME SIZE: {sizes[0]} bytes — likely FIXED")
        else:
            print(f"  >>> VARIABLE sizes: {sorted(set(sizes))}")

        for u in instances:
            print(f"\n  [{u['index']}] {u['size']}b  {u['direction']}")
            hex_str = u['data'].hex(" ") if len(u['data']) <= 80 else u['hex_head'] + "..."
            print(f"    hex: {hex_str}")
            print(f"    prev: {u['prev']}")
            print(f"    next: {u['next']}")

            # Look for embedded known opcodes at various offsets
            data = u['data']
            found_embeds = []
            for off in range(2, min(len(data) - 1, 60)):
                candidate = int.from_bytes(data[off:off + 2], "big")
                if candidate in KNOWN_PACKETS and candidate != 0x0000:
                    pdef = KNOWN_PACKETS[candidate]
                    found_embeds.append((off, pdef.name, candidate))

            if found_embeds:
                for off, name, opc in found_embeds[:5]:
                    print(f"    embed @{off}: {name} ({opc:#06x})")

            # Check if b[2:4] u16le could be length
            if len(data) >= 4:
                v24 = int.from_bytes(data[2:4], "little")
                if v24 == len(data):
                    print(f"    b[2:4] u16le = {v24} == packet size! LENGTH FIELD?")

        print()


if __name__ == "__main__":
    main()
