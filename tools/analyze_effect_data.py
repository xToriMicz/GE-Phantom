"""Analyze EFFECT_DATA (0x330e) framing from live capture data.

Strategies:
1. Extract all TCP segments containing EFFECT_DATA
2. Check bytes[2:4], [4:6], [6:8] as u16le length candidates
3. Backward analysis: if next packet starts with known opcode, infer size
4. Cross-reference with preceding EFFECT (0x4a0e) packets
5. Look for consistent patterns in size distribution
"""

import json
import sys
import struct
from pathlib import Path
from collections import defaultdict, Counter

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.protocol.packet_types import KNOWN_PACKETS, get_packet_size, HEADER_SIZE

CAPTURES_DIR = Path(__file__).parent.parent / "captures"
TARGET_OPCODE = 0x330e  # EFFECT_DATA


def load_capture(name: str) -> list[dict]:
    path = CAPTURES_DIR / name
    data = json.loads(path.read_text())
    return data.get("packets", data) if isinstance(data, dict) else data


def has_known_framing(opcode: int) -> bool:
    pdef = KNOWN_PACKETS.get(opcode)
    if pdef is None:
        return False
    return pdef.size is not None or pdef.length_field_offset is not None


def find_known_opcode_at(data: bytes, offset: int) -> tuple[int, int, str] | None:
    """Check if a known opcode with deterministic framing starts at offset.
    Returns (opcode, expected_size, name) or None."""
    if offset + 2 > len(data):
        return None
    candidate = int.from_bytes(data[offset:offset + 2], "big")
    pdef = KNOWN_PACKETS.get(candidate)
    if pdef is None:
        return None
    if not has_known_framing(candidate):
        return None

    remaining = data[offset:]
    pkt_size = get_packet_size(remaining[:min(len(remaining), 8)])
    if pkt_size is not None:
        return (candidate, pkt_size, pdef.name)
    return None


def validate_chain(data: bytes, offset: int, depth: int = 3) -> list[tuple[int, str, int]]:
    """Validate a packet chain starting at offset, up to `depth` packets.
    Returns list of (offset, name, size) for validated packets."""
    chain = []
    pos = offset
    for _ in range(depth):
        result = find_known_opcode_at(data, pos)
        if result is None:
            break
        opcode, size, name = result
        if pos + size > len(data):
            # Partial packet at end — still valid if it's the segment tail
            chain.append((pos, name, len(data) - pos))
            break
        chain.append((pos, name, size))
        pos += size
    return chain


def analyze_effect_data():
    """Main analysis: extract EFFECT_DATA packets and determine framing."""

    print("=" * 70)
    print("EFFECT_DATA (0x330e) FRAMING ANALYSIS")
    print("=" * 70)

    # Collect all S2C TCP segments
    all_segments = []
    for capture_file in sorted(CAPTURES_DIR.glob("*.json")):
        packets = load_capture(capture_file.name)
        for i, pkt_data in enumerate(packets):
            payload_hex = pkt_data.get("payload_hex", "")
            direction = pkt_data.get("direction", "S2C")
            if not payload_hex or direction != "S2C":
                continue
            payload = bytes.fromhex(payload_hex)
            all_segments.append({
                "file": capture_file.name,
                "index": i,
                "data": payload,
                "size": len(payload),
            })

    print(f"\nTotal S2C segments: {len(all_segments)}")

    # ---- Strategy 1: Find segments containing EFFECT_DATA opcode ----
    effect_data_segments = []
    for seg in all_segments:
        data = seg["data"]
        # Scan for 0x330e in the segment
        for offset in range(0, len(data) - 1):
            if int.from_bytes(data[offset:offset + 2], "big") == TARGET_OPCODE:
                effect_data_segments.append({
                    **seg,
                    "effect_offset": offset,
                })
                break  # one per segment for now

    print(f"Segments containing 0x330e: {len(effect_data_segments)}")

    # ---- Strategy 2: Backward analysis ----
    # For each EFFECT_DATA occurrence, scan forward for the next known opcode
    # The gap = EFFECT_DATA's true size
    print(f"\n{'=' * 70}")
    print("BACKWARD ANALYSIS: scan for next known opcode after EFFECT_DATA")
    print("=" * 70)

    deduced_sizes = []
    length_field_checks = []

    for seg in effect_data_segments:
        data = seg["data"]
        ed_start = seg["effect_offset"]
        ed_data = data[ed_start:]
        seg_remaining = len(ed_data)

        # Scan forward for next known-framing opcode
        best_boundary = None
        best_chain_len = 0

        for probe_offset in range(4, min(seg_remaining, 600)):
            chain = validate_chain(data, ed_start + probe_offset, depth=3)
            if len(chain) >= 2:
                # Strong match: 2+ consecutive known packets
                if len(chain) > best_chain_len:
                    best_boundary = probe_offset
                    best_chain_len = len(chain)
            elif len(chain) == 1:
                name, size = chain[0][1], chain[0][2]
                # Single match: validate it reaches segment end or another known opcode
                end_pos = ed_start + probe_offset + size
                if end_pos == len(data):
                    # Packet ends exactly at segment boundary — good
                    if best_chain_len < 1:
                        best_boundary = probe_offset
                        best_chain_len = 1
                elif end_pos < len(data):
                    next_chain = validate_chain(data, end_pos, depth=1)
                    if next_chain:
                        if best_chain_len < 2:
                            best_boundary = probe_offset
                            best_chain_len = 2

        if best_boundary is not None:
            effect_size = best_boundary
            effect_bytes = data[ed_start:ed_start + effect_size]

            # Extract candidate length fields
            checks = {}
            for name, off in [("b[2:4]", 2), ("b[4:6]", 4), ("b[6:8]", 6)]:
                if len(effect_bytes) >= off + 2:
                    val = int.from_bytes(effect_bytes[off:off + 2], "little")
                    checks[name] = val

            deduced_sizes.append(effect_size)
            length_field_checks.append({
                "size": effect_size,
                "checks": checks,
                "hex_head": effect_bytes[:40].hex() if len(effect_bytes) >= 40 else effect_bytes.hex(),
                "hex_tail": effect_bytes[-10:].hex() if len(effect_bytes) >= 10 else "",
                "chain_depth": best_chain_len,
                "file": seg["file"],
                "seg_total": seg["size"],
                "following": validate_chain(data, ed_start + effect_size, depth=2),
            })

            chain_str = " -> ".join(f"{n}({s})" for _, n, s in
                                     validate_chain(data, ed_start + effect_size, depth=3))
            print(f"  size={effect_size:4d}  chain_after=[{chain_str}]  "
                  f"seg={seg['size']}  checks={checks}")
        else:
            # EFFECT_DATA consumes rest of segment (or can't determine)
            remainder = seg_remaining
            deduced_sizes.append(remainder)
            effect_bytes = ed_data

            checks = {}
            for name, off in [("b[2:4]", 2), ("b[4:6]", 4), ("b[6:8]", 6)]:
                if len(effect_bytes) >= off + 2:
                    val = int.from_bytes(effect_bytes[off:off + 2], "little")
                    checks[name] = val

            length_field_checks.append({
                "size": remainder,
                "checks": checks,
                "hex_head": effect_bytes[:40].hex() if len(effect_bytes) >= 40 else effect_bytes.hex(),
                "hex_tail": effect_bytes[-10:].hex() if len(effect_bytes) >= 10 else "",
                "chain_depth": 0,
                "file": seg["file"],
                "seg_total": seg["size"],
                "following": [],
                "note": "consumed rest of segment",
            })
            print(f"  size={remainder:4d}  [rest of segment]  checks={checks}")

    # ---- Summary ----
    print(f"\n{'=' * 70}")
    print("SIZE DISTRIBUTION")
    print("=" * 70)

    size_counts = Counter(deduced_sizes)
    for size, count in sorted(size_counts.items()):
        print(f"  {size:4d} bytes: {count}x")

    print(f"\nTotal samples: {len(deduced_sizes)}")
    print(f"Unique sizes: {sorted(size_counts.keys())}")

    if len(size_counts) == 1:
        print(f"\n>>> FIXED SIZE CONFIRMED: {deduced_sizes[0]} bytes")
    else:
        print(f"\n>>> VARIABLE SIZE ({len(size_counts)} different sizes)")

    # ---- Length field correlation ----
    print(f"\n{'=' * 70}")
    print("LENGTH FIELD CORRELATION")
    print("=" * 70)

    for field_name in ["b[2:4]", "b[4:6]", "b[6:8]"]:
        print(f"\n  {field_name} as u16le vs packet size:")
        matches_exact = 0
        matches_minus2 = 0
        matches_minus4 = 0
        total = 0
        for entry in length_field_checks:
            val = entry["checks"].get(field_name)
            if val is None:
                continue
            total += 1
            size = entry["size"]
            if val == size:
                matches_exact += 1
            if val == size - 2:
                matches_minus2 += 1
            if val == size - 4:
                matches_minus4 += 1

            # Show each
            rel = ""
            if val == size:
                rel = " == size"
            elif val == size - 2:
                rel = " == size-2"
            elif val == size - 4:
                rel = " == size-4"
            print(f"    size={size:4d}  {field_name}={val:5d} (0x{val:04x}){rel}")

        if total > 0:
            print(f"    --- matches: exact={matches_exact}/{total}, "
                  f"size-2={matches_minus2}/{total}, "
                  f"size-4={matches_minus4}/{total}")

    # ---- Hex dump of first 60 bytes of each EFFECT_DATA ----
    print(f"\n{'=' * 70}")
    print("HEX DUMP (first 60 bytes of each EFFECT_DATA)")
    print("=" * 70)

    for i, entry in enumerate(length_field_checks):
        head = entry["hex_head"]
        # Format as spaced hex
        spaced = " ".join(head[j:j+2] for j in range(0, min(len(head), 120), 2))
        print(f"  [{i:2d}] size={entry['size']:4d}  {spaced}")

    # ---- What precedes EFFECT_DATA? ----
    print(f"\n{'=' * 70}")
    print("CONTEXT: What precedes EFFECT_DATA in the segment?")
    print("=" * 70)

    for seg in effect_data_segments:
        data = seg["data"]
        ed_start = seg["effect_offset"]
        if ed_start == 0:
            print(f"  {seg['file']}: EFFECT_DATA starts at offset 0 (beginning of segment)")
            continue

        # Parse what comes before
        preceding = data[:ed_start]
        pre_opcodes = []
        pos = 0
        while pos < len(preceding) - 1:
            opc = int.from_bytes(preceding[pos:pos + 2], "big")
            pdef = KNOWN_PACKETS.get(opc)
            if pdef is None:
                pre_opcodes.append(f"UNKNOWN(0x{opc:04x})@{pos}")
                break
            pkt_size = get_packet_size(preceding[pos:min(len(preceding), pos + 8)])
            if pkt_size is not None and pos + pkt_size <= len(preceding):
                pre_opcodes.append(f"{pdef.name}({pkt_size})@{pos}")
                pos += pkt_size
            else:
                pre_opcodes.append(f"{pdef.name}(rest={len(preceding)-pos})@{pos}")
                break

        print(f"  {seg['file']}: offset={ed_start}, before=[{' -> '.join(pre_opcodes)}]")


if __name__ == "__main__":
    analyze_effect_data()
