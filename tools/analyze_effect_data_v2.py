"""EFFECT_DATA (0x330e) Framing Analysis v2 — focused approach.

Instead of scanning binary for HEARTBEAT boundaries (false positives),
this script:
1. Extracts EFFECT_DATA packets from the capture (reassembler output)
2. Analyzes the actual hex dumps for embedded structure patterns
3. Looks for sub-packet boundaries (embedded known opcodes)
4. Correlates candidate length fields with observed sizes
5. Checks if EFFECT_DATA is actually a CONTAINER that embeds other opcodes

Key insight from v1: many "EFFECT_DATA" packets contain embedded opcodes
like 0x530d (ENTITY_STAT), 0x540d (ENTITY_ACTION), 0x5c0c (ENTITY_DATA).
This suggests EFFECT_DATA might be a COMPOUND packet or the boundary
detection was wrong.
"""

import json
import sys
import struct
from pathlib import Path
from collections import defaultdict, Counter

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.protocol.packet_types import KNOWN_PACKETS, get_packet_size, HEADER_SIZE

CAPTURES_DIR = Path(__file__).parent.parent / "captures"

# Exclude from boundary scanning - too many false positives
SCAN_EXCLUDE = {0x0000}  # HEARTBEAT: \x00\x00 everywhere


def load_all_packets() -> list[dict]:
    """Load all packets from all capture files."""
    all_pkts = []
    for capture_file in sorted(CAPTURES_DIR.glob("*.json")):
        data = json.loads(capture_file.read_text())
        packets = data.get("packets", data) if isinstance(data, dict) else data
        for pkt in packets:
            pkt["_file"] = capture_file.name
        all_pkts.extend(packets)
    return all_pkts


def find_embedded_opcodes(data: bytes, start: int = 4) -> list[dict]:
    """Find all known opcodes embedded within data, starting from `start`.
    Validates each by checking if its expected size leads to another known opcode."""
    results = []
    for offset in range(start, len(data) - 1):
        candidate = int.from_bytes(data[offset:offset + 2], "big")
        if candidate in SCAN_EXCLUDE:
            continue
        pdef = KNOWN_PACKETS.get(candidate)
        if pdef is None:
            continue

        # Get expected size
        remaining = data[offset:]
        pkt_size = get_packet_size(remaining[:min(len(remaining), 8)])

        # Validate: does the size make sense?
        validated = False
        if pkt_size is not None:
            end = offset + pkt_size
            if end == len(data):
                validated = True  # Fits exactly to end
            elif end < len(data):
                # Check what follows
                next_opc = int.from_bytes(data[end:end + 2], "big") if end + 2 <= len(data) else None
                if next_opc and next_opc in KNOWN_PACKETS and next_opc not in SCAN_EXCLUDE:
                    validated = True
        elif pdef.size is None:
            # Variable with unknown framing — weaker signal
            pass

        results.append({
            "offset": offset,
            "opcode": candidate,
            "opcode_hex": f"0x{candidate:04x}",
            "name": pdef.name,
            "expected_size": pkt_size,
            "validated": validated,
        })

    return results


def main():
    all_packets = load_all_packets()

    # Extract EFFECT_DATA packets (those that START with 0x330e)
    effect_packets = []
    for i, pkt in enumerate(all_packets):
        opcode_hex = pkt.get("opcode_hex", "")
        if opcode_hex == "0x330e":
            payload = bytes.fromhex(pkt.get("payload_hex", ""))
            effect_packets.append({
                "index": i,
                "size": len(payload),
                "data": payload,
                "file": pkt.get("_file", "?"),
            })

    print("=" * 70)
    print(f"EFFECT_DATA (0x330e) — {len(effect_packets)} packets found")
    print("=" * 70)

    # ---- Size distribution ----
    sizes = [p["size"] for p in effect_packets]
    size_counts = Counter(sizes)
    print(f"\nSize distribution:")
    for sz, cnt in sorted(size_counts.items()):
        print(f"  {sz:4d} bytes: {cnt}x")

    # ---- Per-packet analysis: structure and embedded opcodes ----
    print(f"\n{'=' * 70}")
    print("PER-PACKET STRUCTURE ANALYSIS")
    print("=" * 70)

    # Group by structural pattern
    patterns = defaultdict(list)

    for p in effect_packets:
        data = p["data"]
        size = p["size"]

        # Extract key fields
        entity_id = int.from_bytes(data[2:6], "little") if len(data) >= 6 else None
        b6 = data[6] if len(data) > 6 else None

        # Find embedded opcodes
        embedded = find_embedded_opcodes(data)
        validated_embedded = [e for e in embedded if e["validated"]]

        # Determine pattern
        if validated_embedded:
            # Has embedded opcodes — EFFECT_DATA is likely shorter than total
            first_embed = validated_embedded[0]
            effect_real_size = first_embed["offset"]
            after = " + ".join(f"{e['name']}@{e['offset']}" for e in validated_embedded)
            pattern_key = f"compound(real={effect_real_size})"
            extra = f"REAL_SIZE={effect_real_size}, after=[{after}]"
        else:
            pattern_key = f"simple(size={size})"
            extra = ""

        patterns[pattern_key].append(p)

        # Hex dump (first 30 bytes)
        hex_head = " ".join(f"{b:02x}" for b in data[:min(30, len(data))])
        embed_str = ""
        if validated_embedded:
            embed_str = f"  EMBEDDED: [{after}]"
        elif embedded:
            unval = " + ".join(f"{e['name']}@{e['offset']}(?)" for e in embedded[:3])
            embed_str = f"  maybe: [{unval}]"

        # Length field candidates
        lf_str = ""
        if len(data) >= 8:
            b24 = int.from_bytes(data[2:4], "little")
            b46 = int.from_bytes(data[4:6], "little")
            b68 = int.from_bytes(data[6:8], "little")
            lf_str = f"  b24={b24} b46={b46} b68={b68}"

        print(f"  [{p['index']:4d}] size={size:4d}  {hex_head}{lf_str}{embed_str}")

    # ---- Pattern summary ----
    print(f"\n{'=' * 70}")
    print("PATTERN SUMMARY")
    print("=" * 70)

    for pat, pkts in sorted(patterns.items()):
        print(f"\n  {pat}: {len(pkts)}x")
        sizes = [p["size"] for p in pkts]
        print(f"    total sizes: {sorted(set(sizes))}")

    # ---- Focus: what is the TRUE EFFECT_DATA size? ----
    print(f"\n{'=' * 70}")
    print("DEDUCED TRUE EFFECT_DATA SIZES (from embedded opcode boundaries)")
    print("=" * 70)

    true_sizes = []
    for p in effect_packets:
        data = p["data"]
        embedded = find_embedded_opcodes(data)
        validated = [e for e in embedded if e["validated"]]
        if validated:
            true_sizes.append(validated[0]["offset"])

    if true_sizes:
        size_counts = Counter(true_sizes)
        print(f"\n  Deduced true sizes (before first embedded opcode):")
        for sz, cnt in sorted(size_counts.items()):
            print(f"    {sz:4d} bytes: {cnt}x")

        # Check if there's a dominant size
        most_common = size_counts.most_common(1)[0]
        print(f"\n  Most common: {most_common[0]} bytes ({most_common[1]}x)")
    else:
        print("\n  No validated embedded opcodes found!")

    # ---- Length field correlation for true sizes ----
    print(f"\n{'=' * 70}")
    print("LENGTH FIELD CORRELATION (true sizes from embedding analysis)")
    print("=" * 70)

    for p in effect_packets:
        data = p["data"]
        embedded = find_embedded_opcodes(data)
        validated = [e for e in embedded if e["validated"]]
        if not validated:
            continue

        true_size = validated[0]["offset"]
        effect_data = data[:true_size]

        if len(effect_data) < 8:
            continue

        b24 = int.from_bytes(effect_data[2:4], "little")
        b46 = int.from_bytes(effect_data[4:6], "little")
        b68 = int.from_bytes(effect_data[6:8], "little")

        # Check correlations
        flags = []
        for name, val in [("b24", b24), ("b46", b46), ("b68", b68)]:
            if val == true_size:
                flags.append(f"{name}==size")
            elif val == true_size - 2:
                flags.append(f"{name}==size-2")
            elif val == true_size - 4:
                flags.append(f"{name}==size-4")
            elif val == true_size - 6:
                flags.append(f"{name}==size-6")

        flag_str = f"  MATCH: {', '.join(flags)}" if flags else ""
        hex_head = " ".join(f"{b:02x}" for b in effect_data[:min(20, len(effect_data))])
        print(f"  true_size={true_size:3d}  b24={b24:5d} b46={b46:3d} b68={b68:5d}  {hex_head}{flag_str}")

    # ---- Analyze WHAT FOLLOWS EFFECT_DATA in the packet stream ----
    print(f"\n{'=' * 70}")
    print("SEQUENTIAL CONTEXT: What follows EFFECT_DATA in the packet stream?")
    print("=" * 70)

    for p in effect_packets:
        idx = p["index"]
        if idx + 1 < len(all_packets):
            next_pkt = all_packets[idx + 1]
            next_opc = next_pkt.get("opcode_hex", "?")
            next_size = next_pkt.get("size", "?")
            # Get name
            opc_int = int(next_opc, 16) if next_opc != "?" else 0
            pdef = KNOWN_PACKETS.get(opc_int)
            next_name = pdef.name if pdef else "UNKNOWN"
            print(f"  EFFECT_DATA(size={p['size']}) -> {next_name}({next_opc}, size={next_size})")

    # ---- Sub-type analysis: group by byte[6] pattern ----
    print(f"\n{'=' * 70}")
    print("SUB-TYPE ANALYSIS: grouping by byte patterns")
    print("=" * 70)

    # Look at the structure more carefully
    # bytes[0:2] = opcode (0x330e)
    # bytes[2:6] = entity_id (u32le)
    # bytes[6:?] = payload varies

    type_groups = defaultdict(list)
    for p in effect_packets:
        data = p["data"]
        if len(data) < 7:
            key = f"short({len(data)})"
        else:
            # Use byte[6] as potential sub-type discriminator
            b6 = data[6]
            key = f"b6=0x{b6:02x}"
        type_groups[key].append(p)

    for key, pkts in sorted(type_groups.items()):
        sizes = sorted(set(p["size"] for p in pkts))
        print(f"\n  {key}: {len(pkts)}x, sizes={sizes}")
        # Show hex of first 2 examples
        for p in pkts[:2]:
            hex_str = " ".join(f"{b:02x}" for b in p["data"][:min(20, len(p["data"]))])
            print(f"    size={p['size']:4d}: {hex_str}")


if __name__ == "__main__":
    main()
