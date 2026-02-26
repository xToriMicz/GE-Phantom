"""Field-level analysis for fixed-size packets.

For each target opcode, extracts all instances from captures (using
reassembler for proper framing), then analyzes byte patterns:
- Constant bytes (same value across all samples)
- Varying bytes (different values across samples)
- Candidate fields: u32le entity IDs, i32le coordinates, f32 floats, strings
- Cross-correlation with ENTITY_POSITION data for coordinate matching
"""

import json
import struct
import sys
from pathlib import Path
from collections import Counter, defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.protocol.packet_types import KNOWN_PACKETS, get_packet_size, HEADER_SIZE

CAPTURES_DIR = Path(__file__).parent.parent / "captures"

# Target opcodes for field decode
TARGETS = {
    0x5c0c: ("ENTITY_DATA", 270),
    0x620c: ("COMBAT_EFFECT", 44),
    0x6b0c: ("ENTITY_MOVE_PATH", 60),
    0x6d0c: ("ENTITY_MOVE_DETAIL", 72),
    0x530d: ("ENTITY_STAT", 22),
    0x330e: ("EFFECT_DATA", 15),
}


def load_reassembled_packets() -> dict[int, list[bytes]]:
    """Load all captures, reassemble via opcode registry, collect per-opcode samples."""
    from src.sniffer.capture import GEPacket
    from src.sniffer.stream import TCPStreamReassembler

    result: dict[int, list[bytes]] = defaultdict(list)

    for capture_file in sorted(CAPTURES_DIR.glob("*.json")):
        data = json.loads(capture_file.read_text())
        raw_packets = data.get("packets", data) if isinstance(data, dict) else data
        if not raw_packets:
            continue

        reassembler = TCPStreamReassembler()
        reassembler.set_framing("opcode_registry")

        def on_packet(direction, pkt_data, _result=result):
            if len(pkt_data) < 2:
                return
            opcode = int.from_bytes(pkt_data[:2], "big")
            if opcode in TARGETS:
                expected_size = TARGETS[opcode][1]
                if len(pkt_data) == expected_size:
                    _result[opcode].append(pkt_data)

        reassembler.on_game_packet(on_packet)

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

    return result


def find_constant_bytes(samples: list[bytes]) -> list[tuple[int, int]]:
    """Find byte offsets that have the same value across all samples."""
    if not samples or len(samples) < 2:
        return []
    pkt_size = len(samples[0])
    constants = []
    for offset in range(pkt_size):
        val = samples[0][offset]
        if all(s[offset] == val for s in samples[1:]):
            constants.append((offset, val))
    return constants


def find_u32le_candidates(samples: list[bytes], offset: int) -> dict:
    """Analyze a u32le field at given offset across samples."""
    vals = []
    for s in samples:
        if offset + 4 <= len(s):
            vals.append(int.from_bytes(s[offset:offset + 4], "little"))
    if not vals:
        return {}
    unique = sorted(set(vals))
    return {
        "min": min(vals),
        "max": max(vals),
        "unique_count": len(unique),
        "values": unique[:10],
        "most_common": Counter(vals).most_common(5),
    }


def find_f32_candidates(samples: list[bytes], offset: int) -> dict:
    """Analyze a float32 field at given offset across samples."""
    vals = []
    for s in samples:
        if offset + 4 <= len(s):
            v = struct.unpack("<f", s[offset:offset + 4])[0]
            vals.append(v)
    if not vals:
        return {}

    # Filter out garbage floats (NaN, Inf, extremely large/small)
    valid = [v for v in vals if not (abs(v) > 1e10 or abs(v) < 1e-10 and v != 0.0)
             and v == v]  # NaN check
    if len(valid) < len(vals) * 0.5:
        return {"valid_ratio": len(valid) / len(vals), "likely_float": False}

    return {
        "min": min(valid),
        "max": max(valid),
        "mean": sum(valid) / len(valid),
        "valid_ratio": len(valid) / len(vals),
        "likely_float": True,
        "sample_values": sorted(set(round(v, 2) for v in valid))[:10],
    }


def find_i32le_candidates(samples: list[bytes], offset: int) -> dict:
    """Analyze a signed int32 field at given offset across samples."""
    vals = []
    for s in samples:
        if offset + 4 <= len(s):
            vals.append(int.from_bytes(s[offset:offset + 4], "little", signed=True))
    if not vals:
        return {}

    unique = sorted(set(vals))
    # Coordinates are typically in range -100000..+100000
    in_coord_range = [v for v in vals if -500000 < v < 500000]
    likely_coord = len(in_coord_range) > len(vals) * 0.8

    return {
        "min": min(vals),
        "max": max(vals),
        "unique_count": len(unique),
        "likely_coordinate": likely_coord,
        "values": unique[:10],
    }


def find_string_regions(samples: list[bytes]) -> list[dict]:
    """Find byte regions that contain ASCII-printable text across samples."""
    if not samples:
        return []
    pkt_size = len(samples[0])
    regions = []

    for start in range(pkt_size):
        # Check if all samples have printable ASCII at this offset
        all_printable = True
        texts = []
        for s in samples:
            if start >= len(s):
                all_printable = False
                break
            # Check for null-terminated string
            end = start
            while end < len(s) and s[end] >= 0x20 and s[end] < 0x7f:
                end += 1
            length = end - start
            if length >= 3:
                texts.append(s[start:end].decode("ascii", errors="replace"))
            else:
                all_printable = False
                break

        if all_printable and texts:
            # Check if at least some samples have different strings
            unique_texts = set(texts)
            regions.append({
                "offset": start,
                "min_len": min(len(t) for t in texts),
                "max_len": max(len(t) for t in texts),
                "unique_count": len(unique_texts),
                "samples": list(unique_texts)[:5],
            })

    # Merge overlapping regions
    merged = []
    for r in regions:
        if merged and r["offset"] <= merged[-1]["offset"] + merged[-1]["max_len"]:
            continue  # skip overlap
        merged.append(r)

    return merged


def analyze_opcode(opcode: int, name: str, expected_size: int, samples: list[bytes]):
    """Full field analysis for one opcode."""
    print(f"\n{'='*70}")
    print(f"{name} (0x{opcode:04x}) — {expected_size} bytes, {len(samples)} samples")
    print(f"{'='*70}")

    if len(samples) < 2:
        print("  Not enough samples for analysis")
        if samples:
            print(f"  Single sample hex: {samples[0].hex()}")
        return

    # 1. Constant bytes
    constants = find_constant_bytes(samples)
    const_offsets = set(c[0] for c in constants)
    print(f"\n  Constant bytes ({len(constants)}/{expected_size}):")
    # Group consecutive constants
    runs = []
    i = 0
    while i < len(constants):
        start = constants[i][0]
        vals = [constants[i][1]]
        while i + 1 < len(constants) and constants[i + 1][0] == constants[i][0] + 1:
            i += 1
            vals.append(constants[i][1])
        runs.append((start, vals))
        i += 1

    for start, vals in runs:
        hex_str = " ".join(f"{v:02x}" for v in vals)
        ascii_str = "".join(chr(v) if 0x20 <= v < 0x7f else "." for v in vals)
        print(f"    [{start:3d}:{start + len(vals):3d}] = {hex_str}  |{ascii_str}|")

    # 2. Field candidates — scan every 4-byte-aligned and 2-byte-aligned offset
    print(f"\n  Field candidates (u32le entity IDs, coordinates, floats):")

    # First, always show opcode and first few fields
    print(f"    [  0:  2] opcode = 0x{opcode:04x}")

    # Check u16le at offset 2 (common: length or sub-type)
    vals_2 = []
    for s in samples:
        if len(s) >= 4:
            vals_2.append(int.from_bytes(s[2:4], "little"))
    u16_2 = Counter(vals_2).most_common(5)
    print(f"    [  2:  4] u16le  = {u16_2}")

    # Scan for entity-like IDs (u32le, values 1-100000)
    entity_fields = []
    coord_fields = []
    float_fields = []

    for offset in range(2, expected_size - 3):
        u32_info = find_u32le_candidates(samples, offset)
        if not u32_info:
            continue

        # Entity ID heuristic: values in range 1..100000, non-zero, varies
        if (u32_info["unique_count"] > 1 and
                1 <= u32_info["min"] <= 100000 and
                u32_info["max"] <= 200000):
            entity_fields.append((offset, u32_info))

        # Coordinate heuristic (i32le)
        i32_info = find_i32le_candidates(samples, offset)
        if i32_info.get("likely_coordinate") and i32_info["unique_count"] > 1:
            coord_fields.append((offset, i32_info))

        # Float heuristic
        if offset % 2 == 0:  # floats are usually aligned
            f32_info = find_f32_candidates(samples, offset)
            if f32_info.get("likely_float"):
                float_fields.append((offset, f32_info))

    if entity_fields:
        print(f"\n  Likely entity IDs (u32le):")
        for offset, info in entity_fields:
            print(f"    [{offset:3d}:{offset + 4:3d}] range={info['min']}-{info['max']}, "
                  f"unique={info['unique_count']}, top={info['most_common'][:3]}")

    if coord_fields:
        print(f"\n  Likely coordinates (i32le):")
        for offset, info in coord_fields:
            print(f"    [{offset:3d}:{offset + 4:3d}] range={info['min']}..{info['max']}, "
                  f"unique={info['unique_count']}")

    if float_fields:
        print(f"\n  Likely floats (f32):")
        for offset, info in float_fields:
            print(f"    [{offset:3d}:{offset + 4:3d}] range={info['min']:.2f}..{info['max']:.2f}, "
                  f"mean={info['mean']:.2f}, samples={info['sample_values'][:5]}")

    # 3. String regions
    strings = find_string_regions(samples)
    if strings:
        print(f"\n  String regions:")
        for s in strings:
            print(f"    [{s['offset']:3d}:+{s['max_len']}] unique={s['unique_count']}, "
                  f"samples={s['samples'][:3]}")

    # 4. Hex dump comparison (first 3 samples)
    print(f"\n  Sample hex dumps (first 3):")
    for idx, sample in enumerate(samples[:3]):
        lines = []
        for row in range(0, expected_size, 16):
            chunk = sample[row:row + 16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
            # Mark varying bytes with [] and constant bytes normally
            marked = []
            for i, b in enumerate(chunk):
                off = row + i
                if off in const_offsets:
                    marked.append(f"{b:02x}")
                else:
                    marked.append(f"\033[1;33m{b:02x}\033[0m")  # yellow for varying
            marked_str = " ".join(marked)
            lines.append(f"    {row:3d}: {marked_str}  |{ascii_str}|")
        for line in lines:
            print(line)
        if idx < 2:
            print()

    # 5. Byte-by-byte variation analysis
    print(f"\n  Byte variation heatmap (. = constant, # = varies):")
    for row in range(0, expected_size, 32):
        chars = []
        for col in range(32):
            off = row + col
            if off >= expected_size:
                break
            if off in const_offsets:
                chars.append(".")
            else:
                # How many unique values?
                unique_vals = len(set(s[off] for s in samples if off < len(s)))
                if unique_vals <= 2:
                    chars.append("o")  # low variation
                elif unique_vals <= 5:
                    chars.append("#")
                else:
                    chars.append("X")  # high variation
        heatmap = "".join(chars)
        print(f"    {row:3d}: {heatmap}")


def main():
    print("FIELD-LEVEL PACKET ANALYSIS")
    print("=" * 70)
    print("Loading and reassembling captures...")

    samples = load_reassembled_packets()

    for opcode in sorted(TARGETS.keys()):
        name, expected_size = TARGETS[opcode]
        opcode_samples = samples.get(opcode, [])
        analyze_opcode(opcode, name, expected_size, opcode_samples)

    # Summary
    print(f"\n\n{'='*70}")
    print("SAMPLE COUNTS")
    print("=" * 70)
    for opcode in sorted(TARGETS.keys()):
        name, expected_size = TARGETS[opcode]
        count = len(samples.get(opcode, []))
        print(f"  {name:25s} (0x{opcode:04x}): {count:3d} samples of {expected_size}b")


if __name__ == "__main__":
    main()
