"""
Phase 1 Analysis — Attack Range + Monster Spawn + Coordinate Validation

Reads all capture files and produces:
1. Attack range per entity (from COMBAT_UPDATE)
2. MONSTER_SPAWN blob deep analysis (find position, type, level fields)
3. Coordinate cross-validation (PLAYER_MOVE vs ENTITY_POSITION vs COMBAT_EFFECT)
"""

import json
import struct
import sys
from pathlib import Path
from collections import defaultdict

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.protocol.packet_types import KNOWN_PACKETS, decode_packet

CAPTURE_DIR = ROOT / "captures"


def load_capture(path: Path) -> list[dict]:
    """Load a capture JSON file and return packet list."""
    with open(path) as f:
        data = json.load(f)
    return data.get("packets", data) if isinstance(data, dict) else data


def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


# ============================================================
# Task 1: Attack Range Analysis
# ============================================================

def analyze_attack_ranges(captures: dict[str, list[dict]]) -> None:
    print("=" * 70)
    print("  TASK 1: ATTACK RANGE ANALYSIS (COMBAT_UPDATE 0x540c)")
    print("=" * 70)

    # Collect all COMBAT_UPDATE packets
    all_ranges: dict[int, list[float]] = defaultdict(list)  # entity_id -> [ranges]
    all_raw: list[tuple[str, bytes]] = []  # (capture_name, raw_bytes)

    for cap_name, packets in captures.items():
        for pkt in packets:
            payload = hex_to_bytes(pkt.get("payload_hex", ""))
            if len(payload) < 2:
                continue
            opcode = struct.unpack(">H", payload[:2])[0]
            if opcode == 0x540c and len(payload) >= 38:
                eid = struct.unpack("<I", payload[2:6])[0]
                attack_range = struct.unpack("<f", payload[30:34])[0]
                all_ranges[eid].append(attack_range)
                all_raw.append((cap_name, payload))

    print(f"\nTotal COMBAT_UPDATE packets: {sum(len(v) for v in all_ranges.values())}")
    print(f"Unique entities with attack_range: {len(all_ranges)}")

    # Per-entity summary
    print(f"\n{'Entity ID':>12} | {'Count':>6} | {'Min Range':>10} | {'Max Range':>10} | {'Avg Range':>10} | {'Unique Values'}")
    print("-" * 80)
    for eid in sorted(all_ranges.keys()):
        ranges = all_ranges[eid]
        unique = sorted(set(ranges))
        print(f"  0x{eid:08x} | {len(ranges):>6} | {min(ranges):>10.1f} | {max(ranges):>10.1f} | "
              f"{sum(ranges)/len(ranges):>10.1f} | {unique[:5]}")

    # Also dump full 38-byte content for analysis of other fields
    print(f"\n--- Raw COMBAT_UPDATE field analysis (first 10 packets) ---")
    print(f"{'Capture':<20} | {'EID':>10} | {'@6-10':>12} | {'@10-14':>12} | {'@14-18':>12} | "
          f"{'@18-22':>12} | {'@22-26 f32':>10} | {'@26-30 f32':>10} | {'@30-34 f32':>10} | {'@34-38':>10}")
    print("-" * 150)
    for cap_name, payload in all_raw[:20]:
        eid = struct.unpack("<I", payload[2:6])[0]
        # Dump all 4-byte chunks as both u32le and f32
        fields = []
        for off in range(6, 34, 4):
            if off + 4 <= len(payload):
                u32 = struct.unpack("<I", payload[off:off+4])[0]
                f32 = struct.unpack("<f", payload[off:off+4])[0]
                fields.append((u32, f32))
        row = f"{cap_name:<20} | 0x{eid:08x}"
        for i, (u32, f32) in enumerate(fields):
            if i >= 5:
                row += f" | {f32:>10.2f}"
            else:
                row += f" | {u32:>12}"
        print(row)


# ============================================================
# Task 2: Monster Spawn Blob Analysis
# ============================================================

def analyze_monster_spawns(captures: dict[str, list[dict]]) -> None:
    print("\n" + "=" * 70)
    print("  TASK 2: MONSTER_SPAWN BLOB ANALYSIS (0x3e0c / 0x3f0c)")
    print("=" * 70)

    spawn_opcodes = {0x3e0c, 0x3f0c, 0x400c, 0x460c}
    all_spawns: list[tuple[str, int, bytes, float]] = []  # (cap, opcode, payload, ts)

    for cap_name, packets in captures.items():
        for pkt in packets:
            payload = hex_to_bytes(pkt.get("payload_hex", ""))
            if len(payload) < 2:
                continue
            opcode = struct.unpack(">H", payload[:2])[0]
            if opcode in spawn_opcodes:
                ts = pkt.get("timestamp", 0)
                all_spawns.append((cap_name, opcode, payload, ts))

    print(f"\nTotal spawn packets: {len(all_spawns)}")
    by_opcode = defaultdict(list)
    for cap, opc, pay, ts in all_spawns:
        by_opcode[opc].append((cap, pay, ts))

    for opc in sorted(by_opcode.keys()):
        items = by_opcode[opc]
        name = KNOWN_PACKETS.get(opc)
        pname = name.name if name else f"0x{opc:04x}"
        print(f"\n--- {pname} (0x{opc:04x}) — {len(items)} packets, size={len(items[0][1])}b ---")

    # Focus on 371-byte spawns (MONSTER_SPAWN / ENTITY_SPAWN_B)
    monster_spawns = [(c, p, t) for c, p, t in by_opcode.get(0x3e0c, []) + by_opcode.get(0x3f0c, [])]
    if not monster_spawns:
        print("No MONSTER_SPAWN packets found!")
        return

    print(f"\n--- Scanning 371-byte blob for position fields ---")
    print(f"Looking for i32 values that match known ENTITY_POSITION coords...\n")

    # Collect ENTITY_POSITION data for cross-reference
    entity_positions: dict[int, list[tuple[int, int, float]]] = defaultdict(list)  # eid -> [(x, y, ts)]
    for cap_name, packets in captures.items():
        for pkt in packets:
            payload = hex_to_bytes(pkt.get("payload_hex", ""))
            if len(payload) < 2:
                continue
            opcode = struct.unpack(">H", payload[:2])[0]
            if opcode == 0x560c and len(payload) >= 26:
                eid = struct.unpack("<I", payload[2:6])[0]
                x = struct.unpack("<i", payload[10:14])[0]
                y = struct.unpack("<i", payload[14:18])[0]
                ts = pkt.get("timestamp", 0)
                entity_positions[eid].append((x, y, ts))

    print(f"Reference: {len(entity_positions)} entities with known positions from ENTITY_POSITION")

    # For each monster spawn, find position fields in the blob
    print(f"\n{'Cap':<15} | {'EID':>10} | {'Offset':>6} | {'x (i32)':>12} | {'y (i32)':>12} | "
          f"{'Match?':>8} | {'Known x':>12} | {'Known y':>12} | {'Dist':>8}")
    print("-" * 120)

    found_offsets: dict[tuple[int, int], int] = defaultdict(int)  # (x_off, y_off) -> match_count

    for cap, payload, ts in monster_spawns:
        eid = struct.unpack("<I", payload[2:6])[0]

        # Get first known position for this entity (closest in time)
        known_pos = entity_positions.get(eid, [])

        # Scan all 4-byte aligned offsets for i32 values that look like coordinates
        for off in range(6, len(payload) - 7, 2):
            try:
                x = struct.unpack("<i", payload[off:off+4])[0]
                y = struct.unpack("<i", payload[off+4:off+8])[0]
            except struct.error:
                continue

            # Filter: coords should be in reasonable range (GE coords are typically 1000-100000)
            if abs(x) < 100 or abs(x) > 500000 or abs(y) < 100 or abs(y) > 500000:
                continue

            # Check against known positions
            matched = False
            match_info = ""
            for kx, ky, kts in known_pos:
                dist = ((x - kx)**2 + (y - ky)**2) ** 0.5
                if dist < 5000:  # within 5000 units = likely same area
                    matched = True
                    match_info = f"{kx:>12} | {ky:>12} | {dist:>8.0f}"
                    found_offsets[(off, off+4)] += 1
                    break

            if matched:
                print(f"{cap:<15} | 0x{eid:08x} | {off:>6} | {x:>12} | {y:>12} | {'YES':>8} | {match_info}")

    if found_offsets:
        print(f"\n--- Most likely position offsets ---")
        for (xoff, yoff), count in sorted(found_offsets.items(), key=lambda x: -x[1]):
            print(f"  x @ offset {xoff}, y @ offset {yoff} — matched {count} times")
    else:
        print("\nNo coordinate matches found in spawn blob. Trying f32 and other formats...")
        # Try f32
        for cap, payload, ts in monster_spawns[:5]:
            eid = struct.unpack("<I", payload[2:6])[0]
            print(f"\n  EID 0x{eid:08x} — f32 scan (values 100-500000):")
            for off in range(6, len(payload) - 3, 2):
                try:
                    val = struct.unpack("<f", payload[off:off+4])[0]
                except struct.error:
                    continue
                if 100 < abs(val) < 500000 and not (val != val):  # not NaN
                    print(f"    offset {off:>3}: {val:>12.2f}")

    # Dump constant vs varying bytes
    print(f"\n--- Byte variance analysis (371-byte spawn) ---")
    if len(monster_spawns) >= 2:
        payloads = [p for _, p, _ in monster_spawns]
        print(f"Analyzing {len(payloads)} spawn packets...\n")

        # Find which bytes are constant vs varying
        constant_bytes = []
        varying_bytes = []
        for off in range(min(len(p) for p in payloads)):
            values = set(p[off] for p in payloads)
            if len(values) == 1:
                constant_bytes.append(off)
            else:
                varying_bytes.append(off)

        print(f"Constant bytes: {len(constant_bytes)} / {len(payloads[0])}")
        print(f"Varying bytes: {len(varying_bytes)} / {len(payloads[0])}")
        print(f"\nVarying byte offsets (likely contain entity-specific data):")
        # Group consecutive varying bytes
        groups = []
        start = None
        for i, off in enumerate(varying_bytes):
            if start is None:
                start = off
                end = off
            elif off == end + 1:
                end = off
            else:
                groups.append((start, end))
                start = off
                end = off
        if start is not None:
            groups.append((start, end))

        for start, end in groups:
            size = end - start + 1
            label = ""
            if start == 2 and size >= 4:
                label = " ← entity_id (known)"
            print(f"  [{start:>3}:{end+1:>3}] ({size:>2} bytes) {label}")
            # Show values at this range for first 5 spawns
            for j, (cap, payload, ts) in enumerate(monster_spawns[:5]):
                chunk = payload[start:end+1]
                hex_str = chunk.hex()
                # Try interpretations
                interp = ""
                if size == 4:
                    u32 = struct.unpack("<I", chunk)[0]
                    i32 = struct.unpack("<i", chunk)[0]
                    f32 = struct.unpack("<f", chunk)[0]
                    interp = f"u32={u32} i32={i32} f32={f32:.2f}"
                elif size == 2:
                    u16 = struct.unpack("<H", chunk)[0]
                    interp = f"u16={u16}"
                elif size == 1:
                    interp = f"u8={chunk[0]}"
                print(f"      #{j}: {hex_str} {interp}")


# ============================================================
# Task 3: Coordinate System Cross-Validation
# ============================================================

def validate_coordinates(captures: dict[str, list[dict]]) -> None:
    print("\n" + "=" * 70)
    print("  TASK 3: COORDINATE SYSTEM CROSS-VALIDATION")
    print("=" * 70)

    # Collect positions from all packet types, keyed by (entity_id, approx_time)
    positions: dict[str, list[tuple[int, int, int, float]]] = defaultdict(list)
    # type -> [(eid, x, y, timestamp)]

    for cap_name, packets in captures.items():
        for pkt in packets:
            payload = hex_to_bytes(pkt.get("payload_hex", ""))
            if len(payload) < 2:
                continue
            opcode = struct.unpack(">H", payload[:2])[0]
            ts = pkt.get("timestamp", 0)

            # ENTITY_POSITION (0x560c) — 26 bytes
            if opcode == 0x560c and len(payload) >= 26:
                eid = struct.unpack("<I", payload[2:6])[0]
                x = struct.unpack("<i", payload[10:14])[0]
                y = struct.unpack("<i", payload[14:18])[0]
                positions["ENTITY_POSITION"].append((eid, x, y, ts))

            # PLAYER_MOVE family (0x7b00, 0xab00, 0xdb00, 0xa000, 0xd000, 0xf500) — 15 bytes
            elif opcode in (0x7b00, 0xab00, 0xdb00, 0xa000, 0xd000, 0xf500) and len(payload) >= 15:
                eid = struct.unpack("<I", payload[2:6])[0]
                x = struct.unpack("<i", payload[6:10])[0]
                y = struct.unpack("<i", payload[10:14])[0]
                pname = KNOWN_PACKETS[opcode].name if opcode in KNOWN_PACKETS else f"0x{opcode:04x}"
                positions[pname].append((eid, x, y, ts))

            # ENTITY_MOVE_PATH (0x6b0c) — 60 bytes — start pos at offset 12,16
            elif opcode == 0x6b0c and len(payload) >= 60:
                eid = struct.unpack("<I", payload[2:6])[0]
                # Start position
                sx = struct.unpack("<i", payload[12:16])[0]
                sy = struct.unpack("<i", payload[16:20])[0]
                # Destination
                dx = struct.unpack("<i", payload[36:40])[0]
                dy = struct.unpack("<i", payload[40:44])[0]
                positions["ENTITY_MOVE_PATH_start"].append((eid, sx, sy, ts))
                positions["ENTITY_MOVE_PATH_dest"].append((eid, dx, dy, ts))

            # ENTITY_MOVE_DETAIL (0x6d0c) — 72 bytes
            elif opcode == 0x6d0c and len(payload) >= 72:
                eid = struct.unpack("<I", payload[2:6])[0]
                sx = struct.unpack("<i", payload[12:16])[0]
                sy = struct.unpack("<i", payload[16:20])[0]
                positions["ENTITY_MOVE_DETAIL_start"].append((eid, sx, sy, ts))

            # COMBAT_EFFECT (0x620c) — 44 bytes — x,y at offset 12,16
            elif opcode == 0x620c and len(payload) >= 44:
                eid = struct.unpack("<I", payload[4:8])[0]
                x = struct.unpack("<i", payload[12:16])[0]
                y = struct.unpack("<i", payload[16:20])[0]
                positions["COMBAT_EFFECT"].append((eid, x, y, ts))

    print(f"\nPositions collected per packet type:")
    for ptype, pos_list in sorted(positions.items()):
        eids = set(eid for eid, _, _, _ in pos_list)
        xs = [x for _, x, _, _ in pos_list]
        ys = [y for _, _, y, _ in pos_list]
        print(f"  {ptype:<30} | {len(pos_list):>6} packets | {len(eids):>4} entities | "
              f"x:[{min(xs):>8}, {max(xs):>8}] | y:[{min(ys):>8}, {max(ys):>8}]")

    # Cross-validate: for same entity, compare positions from different sources within 1 second
    print(f"\n--- Cross-validation: matching positions within 1 second for same entity ---")
    types = list(positions.keys())
    for i, type_a in enumerate(types):
        for type_b in types[i+1:]:
            matches = 0
            total_dist = 0.0
            max_dist = 0.0
            for eid_a, xa, ya, ts_a in positions[type_a]:
                for eid_b, xb, yb, ts_b in positions[type_b]:
                    if eid_a == eid_b and abs(ts_a - ts_b) < 1.0:
                        dist = ((xa - xb)**2 + (ya - yb)**2) ** 0.5
                        matches += 1
                        total_dist += dist
                        max_dist = max(max_dist, dist)
                        if matches >= 500:
                            break
                if matches >= 500:
                    break
            if matches > 0:
                avg_dist = total_dist / matches
                verdict = "SAME SPACE" if avg_dist < 2000 else "DIFFERENT?"
                print(f"  {type_a:>30} vs {type_b:<30} | {matches:>5} matches | "
                      f"avg_dist={avg_dist:>8.1f} | max_dist={max_dist:>8.1f} | {verdict}")


# ============================================================
# Main
# ============================================================

def main():
    captures = {}
    for f in sorted(CAPTURE_DIR.glob("*.json")):
        try:
            captures[f.stem] = load_capture(f)
            print(f"Loaded {f.name}: {len(captures[f.stem])} packets")
        except Exception as e:
            print(f"Error loading {f.name}: {e}")

    analyze_attack_ranges(captures)
    analyze_monster_spawns(captures)
    validate_coordinates(captures)

    print("\n" + "=" * 70)
    print("  Phase 1 Analysis Complete")
    print("=" * 70)


if __name__ == "__main__":
    main()
