"""Analyze top unknown opcodes to determine framing and register them.

Targets from coverage plan (0x5a0c, 0x0064, 0x7b0c already registered):
  0xd20d — new candidate, needs framing analysis
  0x5f0c — entity-related (0xXX0c pattern)
  0x8214 — investigate framing
  0x630c — entity-related (0xXX0c pattern)

Strategy:
  1. Find all instances in raw TCP segments
  2. For each, find embedded known-opcode boundaries after the unknown
  3. Deduce the unknown packet's size from the boundary offset
  4. Check consistency: if all instances give same size → fixed
  5. Check for length field if variable
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.protocol.packet_types import KNOWN_PACKETS, get_packet_size, HEADER_SIZE

CAPTURES_DIR = Path(__file__).parent.parent / "captures"

# Target unknown opcodes
UNKNOWN_TARGETS = [0xd20d, 0x5f0c, 0x8214, 0x630c]

# Also scan for any other unknowns
SCAN_ALL_UNKNOWNS = True


def find_validated_boundary(data: bytes, start: int) -> list[dict]:
    """Find validated known-opcode boundaries after `start` offset.

    A boundary is validated if:
    - The opcode at that offset has known framing
    - The framing size leads to another known opcode or end of segment
    """
    results = []
    for offset in range(start, len(data) - 1):
        candidate = int.from_bytes(data[offset:offset + 2], "big")
        if candidate == 0x0000:  # skip HEARTBEAT — false positive magnet
            continue
        pdef = KNOWN_PACKETS.get(candidate)
        if pdef is None:
            continue

        remaining = data[offset:]
        pkt_size = get_packet_size(remaining[:min(len(remaining), 8)])

        validated = False
        chain_depth = 0

        if pkt_size is not None:
            end = offset + pkt_size
            if end == len(data):
                validated = True
                chain_depth = 1
            elif end + 2 <= len(data):
                next_opc = int.from_bytes(data[end:end + 2], "big")
                if next_opc in KNOWN_PACKETS and next_opc != 0x0000:
                    validated = True
                    chain_depth = 2
                    # Try chaining further for stronger validation
                    next_pdef = KNOWN_PACKETS[next_opc]
                    next_remaining = data[end:]
                    next_size = get_packet_size(next_remaining[:min(len(next_remaining), 8)])
                    if next_size and end + next_size <= len(data):
                        chain_depth = 3

        if validated:
            results.append({
                "offset": offset,
                "opcode": candidate,
                "opcode_hex": f"0x{candidate:04x}",
                "name": pdef.name,
                "size": pkt_size,
                "chain_depth": chain_depth,
            })

    return results


def analyze_unknown_opcode(opcode: int, instances: list[dict]):
    """Analyze all instances of an unknown opcode to determine framing."""
    print(f"\n{'='*70}")
    print(f"UNKNOWN 0x{opcode:04x} — {len(instances)} instances")
    print(f"{'='*70}")

    deduced_sizes = []
    segment_sizes = []

    for inst in instances:
        payload = inst["payload"]
        file_name = inst["file"]
        seg_size = len(payload)
        segment_sizes.append(seg_size)

        # Find validated boundaries after our opcode
        boundaries = find_validated_boundary(payload, 4)

        # The first validated boundary gives our packet's size
        if boundaries:
            first = boundaries[0]
            deduced_size = first["offset"]
            deduced_sizes.append(deduced_size)

            chain_str = " -> ".join(
                f"{b['name']}@{b['offset']}" for b in boundaries[:3])
            print(f"  seg={seg_size:4d}b  deduced_size={deduced_size:4d}  "
                  f"chain=[{chain_str}]")
        else:
            # No boundary found — segment might BE the packet
            print(f"  seg={seg_size:4d}b  NO BOUNDARY (could be solo packet)")
            deduced_sizes.append(seg_size)

        # Hex header
        head = " ".join(f"{b:02x}" for b in payload[:min(20, seg_size)])
        print(f"    head: {head}")

        # Show potential length fields
        if seg_size >= 4:
            b24 = int.from_bytes(payload[2:4], "little")
            print(f"    b[2:4] u16le = {b24}", end="")
            if b24 == seg_size:
                print(" (==seg_size)", end="")
            if deduced_sizes and b24 == deduced_sizes[-1]:
                print(" (==deduced_size)", end="")
            print()

        if seg_size >= 6:
            b46 = int.from_bytes(payload[4:6], "little")
            print(f"    b[4:6] u16le = {b46}", end="")
            if b46 == seg_size:
                print(" (==seg_size)", end="")
            print()

    # Summary
    print(f"\n  Segment sizes: {sorted(Counter(segment_sizes).items())}")
    print(f"  Deduced sizes: {sorted(Counter(deduced_sizes).items())}")

    unique_deduced = sorted(set(deduced_sizes))
    if len(unique_deduced) == 1:
        size = unique_deduced[0]
        print(f"\n  >>> RECOMMENDATION: Register as FIXED size={size}")
        print(f"      PacketDef(opcode=0x{opcode:04x}, name=\"UNKNOWN_0x{opcode:04x}\", "
              f"direction=Direction.S2C, size={size}, confirmed=True)")
        return {"type": "fixed", "size": size}

    elif len(unique_deduced) > 1:
        # Check length field correlation
        print(f"\n  Multiple sizes detected — checking for length field...")
        for lf_offset in [2, 4]:
            matches = 0
            for inst, deduced in zip(instances, deduced_sizes):
                payload = inst["payload"]
                if len(payload) >= lf_offset + 2:
                    val = int.from_bytes(
                        payload[lf_offset:lf_offset + 2], "little")
                    if val == deduced:
                        matches += 1
            ratio = matches / len(instances) if instances else 0
            print(f"    b[{lf_offset}:{lf_offset + 2}] == deduced_size: "
                  f"{matches}/{len(instances)} ({ratio:.0%})")
            if ratio > 0.8:
                print(f"    >>> LENGTH FIELD at offset {lf_offset} (includes header)")
                return {"type": "length_field", "offset": lf_offset}

    return None


def main():
    # Load all raw packets from captures
    all_packets = []
    for capture_file in sorted(CAPTURES_DIR.glob("*.json")):
        data = json.loads(capture_file.read_text())
        packets = data.get("packets", data) if isinstance(data, dict) else data
        for pkt in packets:
            pkt["_file"] = capture_file.name
        all_packets.extend(packets)

    # Find all unknown opcodes
    unknown_counter = Counter()
    unknown_instances: dict[int, list] = defaultdict(list)

    for pkt in all_packets:
        payload_hex = pkt.get("payload_hex", "")
        direction = pkt.get("direction", "S2C")
        if not payload_hex or direction != "S2C":
            continue

        payload = bytes.fromhex(payload_hex)
        if len(payload) < 4:
            continue

        opcode = int.from_bytes(payload[:2], "big")
        if opcode not in KNOWN_PACKETS:
            unknown_counter[opcode] += 1
            unknown_instances[opcode].append({
                "payload": payload,
                "file": pkt.get("_file", "?"),
                "timestamp": pkt.get("timestamp", 0),
            })

    # Also check for unknowns embedded WITHIN segments that start with known opcodes
    # These are opcodes that appear after the known packet boundaries
    print("SCANNING FOR UNKNOWN OPCODES IN RAW CAPTURES")
    print("=" * 70)
    print(f"\nDirect unknown opcodes (first bytes of S2C segments):")
    for opc, count in unknown_counter.most_common(20):
        in_target = " <<<" if opc in UNKNOWN_TARGETS else ""
        print(f"  0x{opc:04x}: {count}x{in_target}")

    # Analyze each target unknown
    results = {}
    for opcode in UNKNOWN_TARGETS:
        instances = unknown_instances.get(opcode, [])
        if not instances:
            # Check if this opcode appears embedded in other segments
            print(f"\n0x{opcode:04x}: Not found as segment start — scanning embeddings...")
            for pkt in all_packets:
                payload_hex = pkt.get("payload_hex", "")
                if not payload_hex:
                    continue
                payload = bytes.fromhex(payload_hex)
                opc_bytes = opcode.to_bytes(2, "big")
                for i in range(2, len(payload) - 1):
                    if payload[i:i + 2] == opc_bytes:
                        instances.append({
                            "payload": payload[i:],  # from the embedded occurrence
                            "file": pkt.get("_file", "?"),
                            "timestamp": pkt.get("timestamp", 0),
                            "embedded_at": i,
                        })

        if instances:
            result = analyze_unknown_opcode(opcode, instances)
            if result:
                results[opcode] = result
        else:
            print(f"\n0x{opcode:04x}: NO INSTANCES FOUND anywhere")

    # Also analyze any other unknown opcodes with 3+ instances
    if SCAN_ALL_UNKNOWNS:
        print(f"\n\n{'='*70}")
        print("OTHER UNKNOWN OPCODES (3+ instances)")
        print("=" * 70)
        for opc, count in unknown_counter.most_common():
            if count < 3 or opc in UNKNOWN_TARGETS:
                continue
            instances = unknown_instances[opc]
            result = analyze_unknown_opcode(opc, instances)
            if result:
                results[opc] = result

    # Final summary
    print(f"\n\n{'='*70}")
    print("REGISTRATION RECOMMENDATIONS")
    print("=" * 70)
    for opc, result in sorted(results.items()):
        if result["type"] == "fixed":
            print(f"  0x{opc:04x}: FIXED size={result['size']}")
        elif result["type"] == "length_field":
            print(f"  0x{opc:04x}: VARIABLE length_field_offset={result['offset']}")


if __name__ == "__main__":
    main()
