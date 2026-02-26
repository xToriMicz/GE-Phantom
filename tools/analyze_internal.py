"""Targeted analysis of internal structure for variable packets.

For PLAYER_POSITION and COMBAT_DATA, find where their opcodes repeat
within TCP segments to determine per-entry size.
"""

import json
import sys
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.protocol.packet_types import KNOWN_PACKETS

CAPTURES_DIR = Path(__file__).parent.parent / "captures"

TARGETS = {
    0xa50c: "COMBAT_DATA",
    0x5d0c: "PLAYER_POSITION",
    0x4b0c: "ITEM_EVENT",
    0x330e: "EFFECT_DATA",
}

# Known non-target opcodes for reliable boundary detection
# Exclude HEARTBEAT 0x0000 (too many false positives)
RELIABLE_OPCODES = {
    opc: pdef for opc, pdef in KNOWN_PACKETS.items()
    if opc != 0x0000 and opc not in TARGETS and pdef.size is not None
}


def main():
    for capture_file in sorted(CAPTURES_DIR.glob("*.json")):
        data = json.loads(capture_file.read_text())
        packets = data.get("packets", data) if isinstance(data, dict) else data

        for pkt_data in packets:
            payload_hex = pkt_data.get("payload_hex", "")
            direction = pkt_data.get("direction", "S2C")
            if not payload_hex or direction != "S2C":
                continue

            payload = bytes.fromhex(payload_hex)
            if len(payload) < 4:
                continue

            opcode = int.from_bytes(payload[:2], "big")
            if opcode not in TARGETS:
                continue

            name = TARGETS[opcode]
            opc_bytes = opcode.to_bytes(2, "big")

            # Find all self-opcode occurrences
            self_offsets = []
            for i in range(0, len(payload) - 1):
                if payload[i:i+2] == opc_bytes:
                    self_offsets.append(i)

            # Find all reliable (non-heartbeat, non-target) opcode occurrences
            reliable_offsets = []
            for i in range(2, len(payload) - 1):
                cand = int.from_bytes(payload[i:i+2], "big")
                if cand in RELIABLE_OPCODES:
                    reliable_offsets.append((i, RELIABLE_OPCODES[cand].name, RELIABLE_OPCODES[cand].size))

            if len(self_offsets) > 1 or reliable_offsets:
                print(f"\n{capture_file.name}: {name} | TCP segment = {len(payload)} bytes")
                print(f"  Full hex: {payload.hex()}")

                if len(self_offsets) > 1:
                    print(f"  Self-opcode (0x{opcode:04x}) at offsets: {self_offsets}")
                    # Calculate gaps
                    gaps = [self_offsets[i+1] - self_offsets[i]
                            for i in range(len(self_offsets) - 1)]
                    print(f"  Gaps between self-opcodes: {gaps}")
                    # Size of last entry to end of segment
                    last_entry_size = len(payload) - self_offsets[-1]
                    print(f"  Last entry to end: {last_entry_size} bytes")

                if reliable_offsets:
                    print(f"  Reliable opcode boundaries:")
                    for off, bname, bsize in reliable_offsets:
                        remaining = len(payload) - off
                        print(f"    offset={off}: {bname} (size={bsize}), remaining={remaining}")

                    # The first reliable boundary gives us the unknown packet's size
                    first = reliable_offsets[0]
                    print(f"  >>> First reliable boundary at offset {first[0]} -> unknown size = {first[0]}")

    # Now summarize COMBAT_DATA entries
    print(f"\n\n{'='*60}")
    print("COMBAT_DATA: Analyzing sub-entry structure")
    print(f"{'='*60}")

    all_cd_gaps = []
    for capture_file in sorted(CAPTURES_DIR.glob("*.json")):
        data = json.loads(capture_file.read_text())
        packets = data.get("packets", data) if isinstance(data, dict) else data

        for pkt_data in packets:
            payload_hex = pkt_data.get("payload_hex", "")
            direction = pkt_data.get("direction", "S2C")
            if not payload_hex or direction != "S2C":
                continue

            payload = bytes.fromhex(payload_hex)
            if len(payload) < 4:
                continue

            opcode = int.from_bytes(payload[:2], "big")
            if opcode != 0xa50c:
                continue

            opc_bytes = b"\xa5\x0c"
            offsets = [i for i in range(0, len(payload)-1) if payload[i:i+2] == opc_bytes]
            if len(offsets) > 1:
                gaps = [offsets[i+1] - offsets[i] for i in range(len(offsets)-1)]
                all_cd_gaps.extend(gaps)

    if all_cd_gaps:
        unique_gaps = sorted(set(all_cd_gaps))
        print(f"All inter-entry gaps: {all_cd_gaps}")
        print(f"Unique gaps: {unique_gaps}")
        from collections import Counter
        print(f"Gap frequencies: {Counter(all_cd_gaps).most_common()}")

    # Summarize PLAYER_POSITION entries
    print(f"\n\n{'='*60}")
    print("PLAYER_POSITION: Analyzing sub-entry structure")
    print(f"{'='*60}")

    all_pp_gaps = []
    for capture_file in sorted(CAPTURES_DIR.glob("*.json")):
        data = json.loads(capture_file.read_text())
        packets = data.get("packets", data) if isinstance(data, dict) else data

        for pkt_data in packets:
            payload_hex = pkt_data.get("payload_hex", "")
            direction = pkt_data.get("direction", "S2C")
            if not payload_hex or direction != "S2C":
                continue

            payload = bytes.fromhex(payload_hex)
            if len(payload) < 4:
                continue

            opcode = int.from_bytes(payload[:2], "big")
            if opcode != 0x5d0c:
                continue

            opc_bytes = b"\x5d\x0c"
            offsets = [i for i in range(0, len(payload)-1) if payload[i:i+2] == opc_bytes]
            if len(offsets) >= 1:
                gaps = [offsets[i+1] - offsets[i] for i in range(len(offsets)-1)]
                all_pp_gaps.extend(gaps)
                last_entry_to_end = len(payload) - offsets[-1]
                print(f"  Segment {len(payload)}b: self-offsets={offsets}, gaps={gaps}, "
                      f"last_to_end={last_entry_to_end}")

    if all_pp_gaps:
        unique_gaps = sorted(set(all_pp_gaps))
        print(f"\nAll inter-entry gaps: {all_pp_gaps}")
        print(f"Unique gaps: {unique_gaps}")
        from collections import Counter
        print(f"Gap frequencies: {Counter(all_pp_gaps).most_common()}")


if __name__ == "__main__":
    main()
