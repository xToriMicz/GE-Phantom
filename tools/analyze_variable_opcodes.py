"""Analyze remaining variable-size opcodes for embedded length fields.

Target opcodes:
  0x620c COMBAT_EFFECT  (39x, 24-168b)
  0x5c0c ENTITY_DATA    (17x, 9-1412b)
  0x6b0c ENTITY_MOVE_PATH (size varies: 60, 105b)
  0x6d0c ENTITY_MOVE_DETAIL (size varies: 72, 160b)
  0x660e NAME_LABEL     (25, 73b — contains ASCII names)
  0x380c ZONE_DATA      (395-1412b — large)
  0x2f0c ENTITY_GROUP   (6-130b — embeds child packets)
  0x1b15 INVENTORY_DATA (127-1244b)
  0x0c15 CHARACTER_DATA (44-306b)

Strategy:
  1. Extract all instances from captures
  2. Check bytes[2:4] u16le as candidate length field
  3. Check bytes[4:6] u16le as candidate length field
  4. Look for size correlations: val == size, val == size-2, val == size-4
  5. For packets with embedded known opcodes, deduce true sizes
"""

import json
import sys
from pathlib import Path
from collections import defaultdict, Counter

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.protocol.packet_types import KNOWN_PACKETS, get_packet_size

CAPTURES_DIR = Path(__file__).parent.parent / "captures"

# Target variable opcodes
TARGETS = {
    0x620c: "COMBAT_EFFECT",
    0x5c0c: "ENTITY_DATA",
    0x6b0c: "ENTITY_MOVE_PATH",
    0x6d0c: "ENTITY_MOVE_DETAIL",
    0x660e: "NAME_LABEL",
    0x380c: "ZONE_DATA",
    0x2f0c: "ENTITY_GROUP",
    0x1b15: "INVENTORY_DATA",
    0x0c15: "CHARACTER_DATA",
}

SCAN_EXCLUDE = {0x0000}


def load_all_packets() -> list[dict]:
    all_pkts = []
    for capture_file in sorted(CAPTURES_DIR.glob("*.json")):
        data = json.loads(capture_file.read_text())
        packets = data.get("packets", data) if isinstance(data, dict) else data
        for pkt in packets:
            pkt["_file"] = capture_file.name
        all_pkts.extend(packets)
    return all_pkts


def find_validated_embedded(data: bytes, start: int = 4) -> list[dict]:
    """Find embedded known-framing opcodes with chain validation."""
    results = []
    for offset in range(start, len(data) - 1):
        candidate = int.from_bytes(data[offset:offset + 2], "big")
        if candidate in SCAN_EXCLUDE:
            continue
        pdef = KNOWN_PACKETS.get(candidate)
        if pdef is None:
            continue

        remaining = data[offset:]
        pkt_size = get_packet_size(remaining[:min(len(remaining), 8)])

        validated = False
        if pkt_size is not None:
            end = offset + pkt_size
            if end == len(data):
                validated = True
            elif end < len(data) and end + 2 <= len(data):
                next_opc = int.from_bytes(data[end:end + 2], "big")
                if next_opc in KNOWN_PACKETS and next_opc not in SCAN_EXCLUDE:
                    validated = True

        if validated:
            results.append({
                "offset": offset,
                "opcode_hex": f"0x{candidate:04x}",
                "name": pdef.name,
                "size": pkt_size,
            })

    return results


def check_length_field(packets: list[dict], opcode: int, name: str):
    """Check if a u16le at various offsets correlates with packet size."""
    print(f"\n{'='*70}")
    print(f"{name} (0x{opcode:04x}) -- {len(packets)} packets")
    print(f"{'='*70}")

    sizes = sorted(set(p["size"] for p in packets))
    size_counts = Counter(p["size"] for p in packets)
    print(f"  Sizes: {sizes}")
    print(f"  Counts: {dict(sorted(size_counts.items()))}")

    if len(sizes) == 1:
        print(f"  >>> ACTUALLY FIXED SIZE: {sizes[0]} bytes")
        return {"type": "fixed", "size": sizes[0]}

    # Check candidate length fields at offsets 2, 4, 6
    best_match = None
    best_score = 0

    for lf_offset in [2, 4, 6]:
        for adjustment_name, adjustment in [
            ("==size", 0),
            ("==size-2", -2),
            ("==size-4", -4),
        ]:
            matches = 0
            total = 0
            for p in packets:
                data = p["data"]
                if len(data) < lf_offset + 2:
                    continue
                total += 1
                val = int.from_bytes(data[lf_offset:lf_offset + 2], "little")
                expected = p["size"] + adjustment
                if val == expected:
                    matches += 1

            if total > 0:
                score = matches / total
                marker = " <<<" if score > 0.8 else ""
                print(f"  b[{lf_offset}:{lf_offset+2}] {adjustment_name}: "
                      f"{matches}/{total} ({score:.0%}){marker}")
                if score > best_score and score > 0.5:
                    best_score = score
                    best_match = {
                        "offset": lf_offset,
                        "adjustment": adjustment_name,
                        "score": score,
                        "includes_header": adjustment == 0,
                    }

    # Show per-packet details
    print(f"\n  Per-packet details:")
    for p in packets[:20]:  # limit to 20
        data = p["data"]
        size = p["size"]
        b24 = int.from_bytes(data[2:4], "little") if len(data) >= 4 else -1
        b46 = int.from_bytes(data[4:6], "little") if len(data) >= 6 else -1
        b68 = int.from_bytes(data[6:8], "little") if len(data) >= 8 else -1

        flags = []
        if b24 == size: flags.append("b24==size")
        if b24 == size - 2: flags.append("b24==size-2")
        if b24 == size - 4: flags.append("b24==size-4")
        if b46 == size: flags.append("b46==size")
        if b46 == size - 2: flags.append("b46==size-2")
        if b68 == size: flags.append("b68==size")

        # Embedded opcodes
        embedded = find_validated_embedded(data)
        embed_str = ""
        if embedded:
            embed_str = f"  EMB: [{', '.join(e['name'] + '@' + str(e['offset']) for e in embedded[:3])}]"

        hex_head = " ".join(f"{b:02x}" for b in data[:min(16, len(data))])
        flag_str = f"  [{', '.join(flags)}]" if flags else ""
        print(f"    size={size:4d}  b24={b24:5d} b46={b46:3d} b68={b68:5d}  "
              f"{hex_head}{flag_str}{embed_str}")

    if len(packets) > 20:
        print(f"    ... ({len(packets) - 20} more)")

    # Look for patterns in true sizes from embedded opcodes
    true_sizes = []
    for p in packets:
        embedded = find_validated_embedded(p["data"])
        if embedded:
            true_sizes.append(embedded[0]["offset"])

    if true_sizes:
        ts_counts = Counter(true_sizes)
        print(f"\n  True sizes (from embedded boundaries): {dict(sorted(ts_counts.items()))}")

    if best_match:
        print(f"\n  >>> BEST LENGTH FIELD: b[{best_match['offset']}:{best_match['offset']+2}] "
              f"{best_match['adjustment']} ({best_match['score']:.0%} match)")
        return {"type": "length_field", **best_match}

    return None


def main():
    all_packets = load_all_packets()

    # Extract target opcode packets
    target_packets = defaultdict(list)
    for pkt in all_packets:
        opcode_hex = pkt.get("opcode_hex", "")
        try:
            opcode = int(opcode_hex, 16)
        except ValueError:
            continue
        if opcode in TARGETS:
            payload = bytes.fromhex(pkt.get("payload_hex", ""))
            target_packets[opcode].append({
                "size": len(payload),
                "data": payload,
                "file": pkt.get("_file", "?"),
            })

    print("VARIABLE OPCODE LENGTH FIELD ANALYSIS")
    print("=" * 70)

    results = {}
    for opcode in sorted(TARGETS.keys()):
        name = TARGETS[opcode]
        pkts = target_packets.get(opcode, [])
        if not pkts:
            print(f"\n{name} (0x{opcode:04x}): NO PACKETS FOUND")
            continue
        result = check_length_field(pkts, opcode, name)
        if result:
            results[opcode] = result

    # Summary
    print(f"\n\n{'='*70}")
    print("RECOMMENDATIONS")
    print("=" * 70)
    for opcode, result in sorted(results.items()):
        name = TARGETS[opcode]
        if result["type"] == "fixed":
            print(f"  {name} (0x{opcode:04x}): Register as FIXED size={result['size']}")
        elif result["type"] == "length_field":
            offset = result["offset"]
            inc = "includes_header" if result.get("includes_header") else "payload_only"
            print(f"  {name} (0x{opcode:04x}): Register length_field_offset={offset}, "
                  f"{inc} ({result['score']:.0%})")


if __name__ == "__main__":
    main()
