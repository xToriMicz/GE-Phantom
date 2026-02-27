"""
Phase 1 Refined — Fix coalescing + correct field offsets

Key fixes:
- Truncate spawn payloads to known size (371 bytes)
- Use correct field offsets from packet_types.py
- Focus on spawn position discovery at offsets 15-22
"""

import json
import struct
import sys
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.protocol.packet_types import KNOWN_PACKETS, decode_packet, get_packet_size

CAPTURE_DIR = ROOT / "captures"


def load_capture(path: Path) -> list[dict]:
    with open(path) as f:
        data = json.load(f)
    return data.get("packets", data) if isinstance(data, dict) else data


def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def extract_game_packets(raw_payload: bytes) -> list[bytes]:
    """Extract individual game packets from a possibly-coalesced TCP payload."""
    packets = []
    pos = 0
    while pos < len(raw_payload) - 1:
        opcode = struct.unpack(">H", raw_payload[pos:pos+2])[0]
        remaining = raw_payload[pos:]
        size = get_packet_size(remaining)
        if size is None or size < 2:
            # Can't determine size, take rest as one packet
            packets.append(remaining)
            break
        packets.append(remaining[:size])
        pos += size
    return packets


def load_all_game_packets(captures: dict[str, list[dict]]) -> list[tuple[str, bytes, float]]:
    """Load all captures and extract properly-framed game packets."""
    all_pkts = []
    for cap_name, raw_packets in captures.items():
        for rpkt in raw_packets:
            payload = hex_to_bytes(rpkt.get("payload_hex", ""))
            ts = rpkt.get("timestamp", 0)
            if len(payload) < 2:
                continue
            for gpkt in extract_game_packets(payload):
                all_pkts.append((cap_name, gpkt, ts))
    return all_pkts


# ============================================================
# Task 1: Attack Range Summary
# ============================================================

def summarize_attack_ranges(game_packets: list[tuple[str, bytes, float]]) -> None:
    print("=" * 70)
    print("  TASK 1: ATTACK RANGE SUMMARY")
    print("=" * 70)

    ranges: dict[float, int] = defaultdict(int)  # range_value -> count
    entity_ranges: dict[int, float] = {}  # eid -> range

    for cap, pkt, ts in game_packets:
        if len(pkt) < 2:
            continue
        opcode = struct.unpack(">H", pkt[:2])[0]
        if opcode == 0x540c and len(pkt) >= 34:
            eid = struct.unpack("<I", pkt[2:6])[0]
            attack_range = struct.unpack("<f", pkt[30:34])[0]
            if 0 < attack_range < 10000:  # sanity check
                ranges[attack_range] += 1
                entity_ranges[eid] = attack_range

    print(f"\nTotal entities with attack_range: {len(entity_ranges)}")
    print(f"\nDistinct attack_range values:")
    print(f"  {'Range':>8} | {'Count':>6} | {'Bar'}")
    print(f"  {'-'*8}-+-{'-'*6}-+-{'-'*40}")
    for r in sorted(ranges.keys()):
        bar = "#" * min(ranges[r], 40)
        print(f"  {r:>8.0f} | {ranges[r]:>6} | {bar}")

    # Group entities by 3s (GE uses 3-char parties)
    print(f"\n--- Party grouping analysis (consecutive entity IDs) ---")
    sorted_eids = sorted(entity_ranges.keys())
    parties: list[list[tuple[int, float]]] = []
    current_party: list[tuple[int, float]] = []

    for eid in sorted_eids:
        r = entity_ranges[eid]
        if not current_party or eid - current_party[-1][0] <= 3:
            current_party.append((eid, r))
        else:
            if len(current_party) >= 2:
                parties.append(current_party)
            current_party = [(eid, r)]
    if len(current_party) >= 2:
        parties.append(current_party)

    print(f"Found {len(parties)} potential parties (2+ consecutive entities):\n")
    for party in parties[:15]:
        members = " | ".join(f"0x{eid:08x}={r:.0f}" for eid, r in party)
        range_set = sorted(set(r for _, r in party))
        print(f"  [{len(party)} chars] {members}")
        print(f"     Ranges: {range_set}")

    # Also dump the remaining 28 bytes of COMBAT_UPDATE to find more fields
    print(f"\n--- COMBAT_UPDATE full field scan (38 bytes) ---")
    print(f"Examining offsets 6-30 for undiscovered fields:\n")

    samples: list[bytes] = []
    for cap, pkt, ts in game_packets:
        if len(pkt) >= 38:
            opcode = struct.unpack(">H", pkt[:2])[0]
            if opcode == 0x540c:
                samples.append(pkt)
                if len(samples) >= 30:
                    break

    # Check each 4-byte offset for patterns
    for off in range(6, 30, 4):
        values_u32 = set()
        values_i32 = set()
        values_f32 = set()
        for s in samples:
            u32 = struct.unpack("<I", s[off:off+4])[0]
            i32 = struct.unpack("<i", s[off:off+4])[0]
            f32 = struct.unpack("<f", s[off:off+4])[0]
            values_u32.add(u32)
            values_i32.add(i32)
            if not (f32 != f32):  # not NaN
                values_f32.add(round(f32, 2))

        # Determine likely type
        if len(values_u32) == 1:
            label = f"CONSTANT u32={list(values_u32)[0]}"
        elif all(v < 100 for v in values_u32):
            label = f"small u32: {sorted(list(values_u32))[:5]}"
        elif any(100 < abs(v) < 50000 for v in values_i32):
            label = f"i32 range: [{min(values_i32)}, {max(values_i32)}]"
        elif any(0.1 < abs(v) < 100000 for v in values_f32):
            label = f"f32 range: [{min(values_f32)}, {max(values_f32)}]"
        else:
            label = f"u32 range: [{min(values_u32)}, {max(values_u32)}]"

        print(f"  offset [{off:>2}:{off+4:>2}] — {len(values_u32):>3} unique — {label}")

    # Check last 4 bytes (34-38)
    off = 34
    values = set()
    for s in samples:
        u32 = struct.unpack("<I", s[off:off+4])[0]
        values.add(u32)
    print(f"  offset [{off:>2}:{off+4:>2}] — {len(values):>3} unique — u32: {sorted(list(values))[:5]}")


# ============================================================
# Task 2: Monster Spawn Position Discovery
# ============================================================

def discover_spawn_positions(game_packets: list[tuple[str, bytes, float]]) -> None:
    print("\n" + "=" * 70)
    print("  TASK 2: SPAWN POSITION DISCOVERY")
    print("=" * 70)

    # Collect spawn packets (properly framed)
    spawn_packets: list[tuple[str, int, bytes, float]] = []  # (cap, opcode, payload, ts)
    entity_positions: dict[int, list[tuple[int, int, float]]] = defaultdict(list)

    for cap, pkt, ts in game_packets:
        if len(pkt) < 2:
            continue
        opcode = struct.unpack(">H", pkt[:2])[0]

        if opcode in (0x3e0c, 0x3f0c, 0x400c, 0x460c):
            spawn_packets.append((cap, opcode, pkt, ts))

        elif opcode == 0x560c and len(pkt) >= 26:
            eid = struct.unpack("<I", pkt[2:6])[0]
            x = struct.unpack("<i", pkt[10:14])[0]
            y = struct.unpack("<i", pkt[14:18])[0]
            entity_positions[eid].append((x, y, ts))

    print(f"\nSpawn packets (properly framed):")
    by_opcode = defaultdict(list)
    for cap, opc, pay, ts in spawn_packets:
        by_opcode[opc].append((cap, pay, ts))

    for opc in sorted(by_opcode.keys()):
        items = by_opcode[opc]
        sizes = set(len(p) for _, p, _ in items)
        name = KNOWN_PACKETS.get(opc)
        pname = name.name if name else f"0x{opc:04x}"
        print(f"  {pname} (0x{opc:04x}): {len(items)} packets, sizes={sorted(sizes)}")

    print(f"\nReference positions: {len(entity_positions)} entities tracked via ENTITY_POSITION")

    # Focus on MONSTER_SPAWN (0x3e0c) — scan for position in 371-byte range
    monster_spawns = by_opcode.get(0x3e0c, []) + by_opcode.get(0x3f0c, [])
    if not monster_spawns:
        print("No MONSTER_SPAWN packets found!")
        return

    # Hypothesis from first analysis: position at offsets 15-22
    print(f"\n--- Testing position hypothesis: x@15(i32le) y@19(i32le) ---")
    print(f"{'Cap':<15} | {'EID':>10} | {'Spawn x':>10} | {'Spawn y':>10} | "
          f"{'Known x':>10} | {'Known y':>10} | {'Dist':>8} | {'TimeDt':>8}")
    print("-" * 105)

    match_count = 0
    total = 0
    for cap, payload, ts in monster_spawns:
        if len(payload) < 23:
            continue
        eid = struct.unpack("<I", payload[2:6])[0]
        sx = struct.unpack("<i", payload[15:19])[0]
        sy = struct.unpack("<i", payload[19:23])[0]
        total += 1

        # Find closest known position
        known = entity_positions.get(eid, [])
        if not known:
            continue

        # Find closest in time
        best = min(known, key=lambda k: abs(k[2] - ts))
        kx, ky, kts = best
        dist = ((sx - kx)**2 + (sy - ky)**2) ** 0.5
        dt = kts - ts

        if dist < 10000:
            match_count += 1
            mark = "CLOSE" if dist < 1000 else "ok"
        else:
            mark = "FAR"

        print(f"{cap:<15} | 0x{eid:08x} | {sx:>10} | {sy:>10} | "
              f"{kx:>10} | {ky:>10} | {dist:>8.0f} | {dt:>+8.1f}s {mark}")

    print(f"\nHypothesis result: {match_count}/{total} matched within 10000 units")

    # Also try other promising offsets from first analysis
    for test_xoff in [6, 10, 15, 23, 27, 31]:
        yoff = test_xoff + 4
        if yoff + 4 > 371:
            continue
        matches = 0
        tested = 0
        for cap, payload, ts in monster_spawns:
            if len(payload) < yoff + 4:
                continue
            eid = struct.unpack("<I", payload[2:6])[0]
            try:
                sx = struct.unpack("<i", payload[test_xoff:test_xoff+4])[0]
                sy = struct.unpack("<i", payload[yoff:yoff+4])[0]
            except struct.error:
                continue

            known = entity_positions.get(eid, [])
            if not known:
                continue
            tested += 1
            best = min(known, key=lambda k: abs(k[2] - ts))
            dist = ((sx - best[0])**2 + (sy - best[1])**2) ** 0.5
            if dist < 5000:
                matches += 1

        if tested > 0:
            pct = matches / tested * 100
            marker = " <<<" if pct > 50 else ""
            print(f"  x@{test_xoff} y@{yoff}: {matches}/{tested} matched ({pct:.0f}%){marker}")

    # Varying bytes analysis on properly framed packets
    print(f"\n--- Varying bytes in MONSTER_SPAWN (properly framed) ---")
    payloads_3e = [p for _, p, _ in by_opcode.get(0x3e0c, [])]
    if len(payloads_3e) >= 3:
        min_len = min(len(p) for p in payloads_3e)
        print(f"Packet count: {len(payloads_3e)}, min size: {min_len}")

        varying = []
        for off in range(min(min_len, 371)):
            values = set(p[off] for p in payloads_3e)
            if len(values) > 1:
                varying.append(off)

        # Group consecutive
        groups = []
        start = end = None
        for off in varying:
            if start is None:
                start = end = off
            elif off == end + 1:
                end = off
            else:
                groups.append((start, end))
                start = end = off
        if start is not None:
            groups.append((start, end))

        print(f"Varying regions ({len(varying)} bytes):")
        for start, end in groups:
            size = end - start + 1
            label = ""
            if start == 2:
                label = "entity_id"
            elif start == 15:
                label = "POSITION CANDIDATE"

            print(f"\n  [{start:>3}:{end+1:>3}] ({size:>2}b) {label}")
            for i, p in enumerate(payloads_3e[:5]):
                chunk = p[start:end+1]
                hex_str = chunk.hex()
                interp = ""
                if size == 4:
                    i32 = struct.unpack("<i", chunk)[0]
                    f32 = struct.unpack("<f", chunk)[0]
                    interp = f"i32={i32:>10}  f32={f32:>10.2f}"
                elif size == 2:
                    u16 = struct.unpack("<H", chunk)[0]
                    i16 = struct.unpack("<h", chunk)[0]
                    interp = f"u16={u16:>6}  i16={i16:>6}"
                elif size >= 8:
                    # Try multiple interpretations
                    parts = []
                    for sub_off in range(0, min(size, 16), 4):
                        if sub_off + 4 <= size:
                            val = struct.unpack("<i", chunk[sub_off:sub_off+4])[0]
                            parts.append(f"@{start+sub_off}={val}")
                    interp = "  ".join(parts)
                print(f"    #{i}: {hex_str[:40]:<40} {interp}")


# ============================================================
# Task 3: Coordinate Cross-Validation (fixed offsets)
# ============================================================

def validate_coords_fixed(game_packets: list[tuple[str, bytes, float]]) -> None:
    print("\n" + "=" * 70)
    print("  TASK 3: COORDINATE CROSS-VALIDATION (corrected offsets)")
    print("=" * 70)

    positions: dict[str, list[tuple[int, int, int, float]]] = defaultdict(list)

    for cap, pkt, ts in game_packets:
        if len(pkt) < 2:
            continue
        opcode = struct.unpack(">H", pkt[:2])[0]

        # ENTITY_POSITION (0x560c) — x@10, y@14
        if opcode == 0x560c and len(pkt) >= 26:
            eid = struct.unpack("<I", pkt[2:6])[0]
            x = struct.unpack("<i", pkt[10:14])[0]
            y = struct.unpack("<i", pkt[14:18])[0]
            positions["ENTITY_POSITION"].append((eid, x, y, ts))

        # PLAYER_MOVE family — x@6, y@10
        elif opcode in (0x7b00, 0xab00, 0xdb00, 0xa000, 0xd000, 0xf500) and len(pkt) >= 15:
            eid = struct.unpack("<I", pkt[2:6])[0]
            x = struct.unpack("<i", pkt[6:10])[0]
            y = struct.unpack("<i", pkt[10:14])[0]
            positions["PLAYER_MOVE"].append((eid, x, y, ts))

        # ENTITY_MOVE_PATH (0x6b0c) — start: x@6, y@10; dest: x@48, y@52
        elif opcode == 0x6b0c and len(pkt) >= 60:
            eid = struct.unpack("<I", pkt[2:6])[0]
            sx = struct.unpack("<i", pkt[6:10])[0]
            sy = struct.unpack("<i", pkt[10:14])[0]
            dx = struct.unpack("<i", pkt[48:52])[0]
            dy = struct.unpack("<i", pkt[52:56])[0]
            positions["MOVE_PATH_start"].append((eid, sx, sy, ts))
            positions["MOVE_PATH_dest"].append((eid, dx, dy, ts))

        # ENTITY_MOVE_DETAIL (0x6d0c) — start: x@6, y@10; dest: x@60, y@64
        elif opcode == 0x6d0c and len(pkt) >= 72:
            eid = struct.unpack("<I", pkt[2:6])[0]
            sx = struct.unpack("<i", pkt[6:10])[0]
            sy = struct.unpack("<i", pkt[10:14])[0]
            dx = struct.unpack("<i", pkt[60:64])[0]
            dy = struct.unpack("<i", pkt[64:68])[0]
            positions["MOVE_DETAIL_start"].append((eid, sx, sy, ts))
            positions["MOVE_DETAIL_dest"].append((eid, dx, dy, ts))

        # COMBAT_EFFECT (0x620c) — x@12, y@16
        elif opcode == 0x620c and len(pkt) >= 44:
            eid = struct.unpack("<I", pkt[4:8])[0]
            x = struct.unpack("<i", pkt[12:16])[0]
            y = struct.unpack("<i", pkt[16:20])[0]
            positions["COMBAT_EFFECT"].append((eid, x, y, ts))

    print(f"\nPositions by packet type:")
    for ptype in sorted(positions.keys()):
        pos_list = positions[ptype]
        eids = set(eid for eid, _, _, _ in pos_list)
        xs = [x for _, x, _, _ in pos_list]
        ys = [y for _, _, y, _ in pos_list]
        print(f"  {ptype:<25} | {len(pos_list):>6} pkts | {len(eids):>4} entities | "
              f"x:[{min(xs):>8}, {max(xs):>8}] | y:[{min(ys):>8}, {max(ys):>8}]")

    # Cross-validate pairs
    print(f"\n--- Temporal cross-validation (same entity, within 2 seconds) ---")
    types = list(positions.keys())
    for i, type_a in enumerate(types):
        for type_b in types[i+1:]:
            # Build index for type_b
            by_eid_b: dict[int, list[tuple[int, int, float]]] = defaultdict(list)
            for eid, x, y, ts in positions[type_b]:
                by_eid_b[eid].append((x, y, ts))

            matches = 0
            total_dist = 0.0
            max_dist = 0.0
            for eid, xa, ya, ts_a in positions[type_a]:
                if eid not in by_eid_b:
                    continue
                for xb, yb, ts_b in by_eid_b[eid]:
                    if abs(ts_a - ts_b) < 2.0:
                        dist = ((xa - xb)**2 + (ya - yb)**2) ** 0.5
                        matches += 1
                        total_dist += dist
                        max_dist = max(max_dist, dist)
                        break  # one match per pair is enough
                if matches >= 1000:
                    break

            if matches > 0:
                avg = total_dist / matches
                verdict = "SAME COORD SPACE" if avg < 3000 else "OFFSET?" if avg < 10000 else "DIFFERENT"
                print(f"  {type_a:>25} vs {type_b:<25} | {matches:>5} pairs | "
                      f"avg={avg:>8.0f} max={max_dist:>8.0f} | {verdict}")


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

    print(f"\nExtracting game packets (with reassembly)...")
    game_packets = load_all_game_packets(captures)
    print(f"Total game packets extracted: {len(game_packets)}")

    # Count by opcode
    opcode_counts = defaultdict(int)
    for _, pkt, _ in game_packets:
        if len(pkt) >= 2:
            opc = struct.unpack(">H", pkt[:2])[0]
            opcode_counts[opc] += 1
    top10 = sorted(opcode_counts.items(), key=lambda x: -x[1])[:10]
    print(f"Top 10 opcodes: {', '.join(f'0x{o:04x}={c}' for o, c in top10)}")

    summarize_attack_ranges(game_packets)
    discover_spawn_positions(game_packets)
    validate_coords_fixed(game_packets)

    print("\n" + "=" * 70)
    print("  Phase 1 Refined Analysis Complete")
    print("=" * 70)


if __name__ == "__main__":
    main()
