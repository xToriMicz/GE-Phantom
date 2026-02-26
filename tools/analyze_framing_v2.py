"""Analyze packet framing by parsing TCP segments with known-size boundaries.

Strategy: for segments containing unknown-framing opcodes, use known-size
packets as anchors to deduce the unknown packet's true size.

For each TCP segment:
1. Parse greedily from front using known sizes
2. When hitting unknown opcode, try parsing from the END backwards
3. The remainder is the unknown packet's size
"""

import json
import sys
import struct
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.protocol.packet_types import KNOWN_PACKETS, get_packet_size, HEADER_SIZE

CAPTURES_DIR = Path(__file__).parent.parent / "captures"

INVESTIGATE = {
    0xa50c: "COMBAT_DATA",
    0x5d0c: "PLAYER_POSITION",
    0x4b0c: "ITEM_EVENT",
    0x330e: "EFFECT_DATA",
}

# Opcodes with CONFIRMED sizes (fixed or length-field)
def has_known_framing(opcode: int) -> bool:
    pdef = KNOWN_PACKETS.get(opcode)
    if pdef is None:
        return False
    return pdef.size is not None or pdef.length_field_offset is not None


def try_parse_from_end(data: bytes) -> list[tuple[int, int, str]]:
    """Try to identify packets from the end of a segment, working backwards.

    Returns list of (offset, size, name) for packets identified at the tail.
    """
    results = []
    remaining = len(data)

    # Try to identify trailing known-size packets
    # Check if the last N bytes form a known packet
    for trial_size in range(2, min(remaining + 1, 400)):
        tail_start = remaining - trial_size
        if tail_start < 0:
            break
        candidate = data[tail_start:tail_start + 2]
        if len(candidate) < 2:
            continue
        opcode = int.from_bytes(candidate, "big")
        pdef = KNOWN_PACKETS.get(opcode)
        if pdef is None:
            continue
        if pdef.size == trial_size:
            results.append((tail_start, trial_size, pdef.name))
            # Try to parse more from the end (before this packet)
            sub_results = try_parse_from_end(data[:tail_start])
            return sub_results + results
        if pdef.length_field_offset is not None and trial_size >= pdef.length_field_offset + 2:
            length = int.from_bytes(
                data[tail_start + pdef.length_field_offset:tail_start + pdef.length_field_offset + 2],
                "little"
            )
            expected = length if pdef.length_field_includes_header else length + HEADER_SIZE
            if expected == trial_size:
                results.append((tail_start, trial_size, pdef.name))
                sub_results = try_parse_from_end(data[:tail_start])
                return sub_results + results

    return results


def parse_segment(data: bytes) -> list[tuple[int, int, str, bool]]:
    """Parse a TCP segment into game packets.

    Returns list of (offset, size, name, known_framing).
    Tries greedy front-to-back parsing, falls back to end-parsing.
    """
    results = []
    offset = 0

    while offset < len(data) - 1:
        remaining = data[offset:]
        if len(remaining) < 2:
            break

        opcode = int.from_bytes(remaining[:2], "big")
        pdef = KNOWN_PACKETS.get(opcode)

        if pdef is None:
            # Unknown opcode entirely — can't parse further
            results.append((offset, len(remaining), f"UNKNOWN(0x{opcode:04x})", False))
            break

        # Try to get size
        pkt_size = get_packet_size(remaining[:min(len(remaining), 8)])

        if pkt_size is not None:
            # Known framing — consume
            actual = min(pkt_size, len(remaining))
            results.append((offset, actual, pdef.name, True))
            offset += actual
            continue

        # Unknown framing — try to figure out size using tail parsing
        tail_results = try_parse_from_end(remaining)
        if tail_results:
            # The first tail result tells us where our unknown packet ends
            unknown_end = tail_results[0][0]
            results.append((offset, unknown_end, pdef.name, False))
            offset += unknown_end
            # Now parse the tail packets
            for t_off_rel, t_size, t_name in tail_results:
                abs_off = offset + (t_off_rel - unknown_end) if t_off_rel > unknown_end else offset
                # These are already parsed from end; just add them sequentially
            # Actually, let the loop continue to parse tail packets normally
            continue

        # Can't determine size — consume everything
        results.append((offset, len(remaining), pdef.name, False))
        break

    return results


def main():
    # Per-opcode size tracking from deduced boundaries
    deduced_sizes: dict[str, list[dict]] = defaultdict(list)
    # Also track raw TCP segment sizes that start with target opcodes
    raw_segment_starts: dict[str, list[int]] = defaultdict(list)

    for capture_file in sorted(CAPTURES_DIR.glob("*.json")):
        print(f"\n{'='*60}")
        print(f"Processing: {capture_file.name}")
        print(f"{'='*60}")

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

            # Track raw TCP segment starts with target opcodes
            if opcode in INVESTIGATE:
                name = INVESTIGATE[opcode]
                raw_segment_starts[name].append(len(payload))

            # Try full segment parsing
            parsed = parse_segment(payload)

            for p_offset, p_size, p_name, p_known in parsed:
                if p_name in INVESTIGATE.values() and not p_known:
                    pkt_bytes = payload[p_offset:p_offset + p_size]
                    b24 = int.from_bytes(pkt_bytes[2:4], "little") if len(pkt_bytes) >= 4 else 0
                    deduced_sizes[p_name].append({
                        "size": p_size,
                        "b24": b24,
                        "hex": pkt_bytes[:30].hex(),
                        "file": capture_file.name,
                        "segment_total": len(payload),
                        "parsed_chain": [(n, s) for _, s, n, _ in parsed],
                    })
                    # Print details
                    chain = " + ".join(f"{n}({s})" for _, s, n, _ in parsed)
                    print(f"  {p_name:20s} deduced_size={p_size:4d}  "
                          f"seg_total={len(payload):4d}  "
                          f"chain=[{chain}]")

    # Summary
    print(f"\n\n{'='*60}")
    print("SUMMARY: Deduced sizes for unknown-framing packets")
    print(f"{'='*60}")

    for name in sorted(INVESTIGATE.values()):
        samples = deduced_sizes.get(name, [])
        raw_starts = raw_segment_starts.get(name, [])

        print(f"\n{name}:")
        print(f"  Raw TCP segment sizes (starts with this opcode): {sorted(set(raw_starts))}")

        if not samples:
            print(f"  Deduced sizes: NO DEDUCED SAMPLES")
            # If we only have raw segment data, analyze that
            if raw_starts:
                unique = sorted(set(raw_starts))
                if len(unique) == 1:
                    print(f"  >>> Could be FIXED at {unique[0]} (only one raw size seen)")
                else:
                    # Check GCD
                    from math import gcd
                    from functools import reduce
                    g = reduce(gcd, unique)
                    print(f"  >>> GCD of raw sizes: {g}")
                    if g > 4:
                        print(f"  >>> Sizes as multiples of {g}: {[s//g for s in unique]}")
            continue

        sizes = sorted(set(s["size"] for s in samples))
        print(f"  Deduced sizes: {sizes} ({len(samples)} samples)")

        if len(sizes) == 1:
            print(f"  >>> CONFIRMED FIXED: {sizes[0]} bytes")
        else:
            print(f"  >>> VARIABLE: {len(sizes)} different sizes")

        for sz in sizes:
            matching = [s for s in samples if s["size"] == sz]
            b24_vals = sorted(set(s["b24"] for s in matching))
            print(f"  size={sz:4d}: count={len(matching)}, b[2:4]={b24_vals[:5]}")
            # Show one example hex
            print(f"    example: {matching[0]['hex']}")
            print(f"    chain: {matching[0]['parsed_chain']}")

    # Direct analysis: for segments starting with unknown opcodes,
    # what known opcodes appear within them and at what offsets?
    print(f"\n\n{'='*60}")
    print("OPCODE BOUNDARY ANALYSIS within target-starting segments")
    print(f"{'='*60}")

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
            if opcode not in INVESTIGATE:
                continue

            name = INVESTIGATE[opcode]

            # Find all known-framing opcodes within this segment
            boundaries = []
            for off in range(0, len(payload) - 1):
                cand = int.from_bytes(payload[off:off+2], "big")
                if cand in KNOWN_PACKETS and has_known_framing(cand):
                    pdef = KNOWN_PACKETS[cand]
                    # Verify: if fixed size, does the next packet boundary also have valid opcode?
                    if pdef.size and off + pdef.size < len(payload):
                        next_opc = int.from_bytes(payload[off+pdef.size:off+pdef.size+2], "big")
                        valid_next = next_opc in KNOWN_PACKETS
                    else:
                        valid_next = (off + (pdef.size or 0)) == len(payload)
                    boundaries.append((off, cand, pdef.name, pdef.size or "var", valid_next))

            if boundaries:
                print(f"\n  {capture_file.name}: {name} segment, {len(payload)} bytes")
                # Only show plausible boundaries (verified)
                verified = [(o, c, n, s) for o, c, n, s, v in boundaries if v or o == 0]
                for off, cand, bname, bsize in verified:
                    print(f"    offset={off:4d}: {bname} (size={bsize}) [verified]")

                # If first verified boundary after offset 0 exists, that's the unknown packet's size
                after_zero = [(o, n, s) for o, c, n, s in verified if o > 0]
                if after_zero:
                    first = after_zero[0]
                    print(f"    >>> Unknown packet size = {first[0]} (gap to first verified boundary)")


if __name__ == "__main__":
    main()
