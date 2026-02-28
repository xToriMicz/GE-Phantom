# -*- coding: utf-8 -*-
import json
import struct
import sys
from collections import defaultdict

sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)

with open("D:/Project/GE_Phantom/data/autoattack_dummy.json", "r", encoding="utf-8") as f:
    data = json.load(f)

packets = data["packets"]

def hex2bytes(h):
    return bytes.fromhex(h)

known_range_values = {539, 560, 580, 600, 620, 640, 660, 680, 700, 720, 740, 760, 780, 800, 803, 850, 900, 950, 1000}

# Collect by opcode
by_opcode = {}
for i, p in enumerate(packets):
    for parsed in p.get("parsed", []):
        op = parsed.get("opcode", "")
        name = parsed.get("name", op)
        if name not in by_opcode:
            by_opcode[name] = []
        by_opcode[name].append({
            "pkt_idx": i,
            "time_str": p["time_str"],
            "time": p["time"],
            "hex": parsed["hex"],
            "size": parsed.get("size", len(parsed["hex"])//2),
            "opcode": op
        })

# ============================================
# 1. 0x590c
# ============================================
print("=" * 100)
print("1. 0x590c ANALYSIS (34 instances) - COMPLETELY NEW OPCODE")
print("=" * 100)

items_590c = by_opcode.get("0x590c", [])
print(f"Total: {len(items_590c)}")
sizes = {}
for p in items_590c:
    sizes[p["size"]] = sizes.get(p["size"], 0) + 1
print(f"Size distribution: {sizes}")

# Print raw hex for first 5 with ASCII sidebar
for i, pkt in enumerate(items_590c[:5]):
    raw = hex2bytes(pkt["hex"])
    print(f"\n  Instance {i+1} (t={pkt['time_str']}, {len(raw)}B):")
    for row_start in range(0, len(raw), 32):
        chunk = raw[row_start:row_start+32]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    {row_start:4d}: {hex_part:<96s} |{ascii_part}|")

# Structural decode
print("\n--- 0x590c STRUCTURAL DECODE ---")

# Check what varies across size-219 instances
all_219 = [hex2bytes(p["hex"]) for p in items_590c if p["size"] == 219]
all_215 = [hex2bytes(p["hex"]) for p in items_590c if p["size"] == 215]

print(f"\n  Size 219: {len(all_219)} instances, Size 215: {len(all_215)} instances")

if all_219:
    print("\n  VARYING OFFSETS in size-219 group:")
    for off in range(min(len(b) for b in all_219)):
        values = set(b[off] for b in all_219)
        if len(values) > 1:
            vals = [f"0x{b[off]:02x}" for b in all_219[:6]]
            print(f"    offset {off}: {', '.join(vals)} ...")

if all_215:
    print("\n  VARYING OFFSETS in size-215 group:")
    for off in range(min(len(b) for b in all_215)):
        values = set(b[off] for b in all_215)
        if len(values) > 1:
            vals = [f"0x{b[off]:02x}" for b in all_215[:6]]
            print(f"    offset {off}: {', '.join(vals)} ...")

# Extract ALL damage strings and key fields
print("\n  ALL 0x590c INSTANCES - DAMAGE STRINGS AND KEY FIELDS:")
for i, pkt in enumerate(items_590c):
    raw = hex2bytes(pkt["hex"])

    # Extract ASCII text segments
    texts = []
    j = 0
    while j < len(raw):
        if 32 <= raw[j] < 127:
            start = j
            while j < len(raw) and 32 <= raw[j] < 127:
                j += 1
            s = "".join(chr(b) for b in raw[start:j])
            if len(s) >= 3:
                texts.append((start, s))
        else:
            j += 1

    # u16 at important offsets
    vals = {}
    for off in [2, 76, 78, 80, 82]:
        if off + 2 <= len(raw):
            vals[off] = struct.unpack_from("<H", raw, off)[0]

    # f64 at offset 142
    f64_142 = ""
    if len(raw) > 150:
        v = struct.unpack_from("<d", raw, 142)[0]
        if v == v and v != 0:
            f64_142 = f" f64@142={v:.2f}"

    # f64 at offset 148
    f64_148 = ""
    if len(raw) > 156:
        v = struct.unpack_from("<d", raw, 148)[0]
        if v == v and v != 0:
            f64_148 = f" f64@148={v:.2f}"

    text_str = ", ".join(f"@{s}:'{t}'" for s, t in texts)
    print(f"  #{i+1:2d} t={pkt['time_str']} size={len(raw)} u16@76={vals.get(76,'?')} u16@82={vals.get(82,'?')}{f64_142}{f64_148}")
    print(f"       texts: {text_str}")

# Check ALL u16 values for range matches
print("\n  u16@76 VALUES (checking for attack_range):")
for i, pkt in enumerate(items_590c):
    raw = hex2bytes(pkt["hex"])
    if len(raw) > 78:
        v76 = struct.unpack_from("<H", raw, 76)[0]
        flag = ""
        if v76 in known_range_values:
            flag = " *** EXACT RANGE MATCH ***"
        elif 400 <= v76 <= 1100:
            flag = " *** IN RANGE WINDOW ***"
        print(f"    #{i+1:2d}: u16@76 = {v76}{flag}")

# ============================================
# 2. COMBAT_UPDATE
# ============================================
print("\n" + "=" * 100)
print("2. COMBAT_UPDATE (57 instances) - field_30 decode")
print("=" * 100)

cu_items = by_opcode.get("COMBAT_UPDATE", [])
print(f"Total: {len(cu_items)}")

entity_groups = {}
for idx, pkt in enumerate(cu_items):
    raw = hex2bytes(pkt["hex"])
    if len(raw) < 38:
        continue

    seq = struct.unpack_from("<I", raw, 2)[0]
    zeros = struct.unpack_from("<I", raw, 6)[0]
    target = struct.unpack_from("<I", raw, 10)[0]
    b14 = struct.unpack_from("<H", raw, 14)[0]
    b16 = struct.unpack_from("<H", raw, 16)[0]
    b18 = struct.unpack_from("<i", raw, 18)[0]
    b22 = struct.unpack_from("<i", raw, 22)[0]
    b26 = struct.unpack_from("<H", raw, 26)[0]
    b28 = struct.unpack_from("<H", raw, 28)[0]
    f30 = struct.unpack_from("<f", raw, 30)[0]
    u30 = struct.unpack_from("<I", raw, 30)[0]
    b34 = struct.unpack_from("<I", raw, 34)[0]

    key = hex(target)
    if key not in entity_groups:
        entity_groups[key] = []
    entity_groups[key].append({
        "idx": idx, "time": pkt["time_str"],
        "seq": seq, "target": target,
        "b14": b14, "b16": b16,
        "b18": b18, "b22": b22,
        "b26": b26, "b28": b28,
        "f30": f30, "u30": u30, "b34": b34
    })

for ent, entries in entity_groups.items():
    print(f"\n  Entity {ent} ({len(entries)} hits):")
    for e in entries:
        f30_flag = ""
        if 400 <= e["f30"] <= 1100:
            f30_flag = " **RANGE**"
        if e["f30"] == 515.0:
            f30_flag = " (same as prev capture)"
        hex30 = f"0x{e['u30']:08x}"
        print(f"    #{e['idx']:2d} t={e['time']} seq=0x{e['seq']:08x} b14=0x{e['b14']:04x} b16=0x{e['b16']:04x} "
              f"pos=({e['b18']},{e['b22']}) b26={e['b26']} b28={e['b28']} "
              f"f30={e['f30']:.1f}({hex30}) b34={e['b34']}{f30_flag}")

    f30_values = set(e["f30"] for e in entries)
    print(f"  -> field_30 unique values: {sorted(f30_values)}")
    print(f"  -> Previous capture had field_30 = 515.0 constant")

# ============================================
# 3. 0xbd0c (19 instances)
# ============================================
print("\n" + "=" * 100)
print("3. 0xbd0c (19 instances)")
print("=" * 100)

bd0c_items = by_opcode.get("0xbd0c", [])
print(f"Total: {len(bd0c_items)}")

# Check sizes
bd_sizes = {}
for p in bd0c_items:
    bd_sizes[p["size"]] = bd_sizes.get(p["size"], 0) + 1
print(f"Size distribution: {bd_sizes}")

for i, pkt in enumerate(bd0c_items[:5]):
    raw = hex2bytes(pkt["hex"])
    print(f"\n  #{i+1} t={pkt['time_str']} size={len(raw)}B")
    for row_start in range(0, min(len(raw), 64), 32):
        chunk = raw[row_start:row_start+32]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    {row_start:4d}: {hex_part:<96s} |{ascii_part}|")

    if len(raw) >= 6:
        eid = struct.unpack_from("<I", raw, 2)[0]
        print(f"    entity_id @2: 0x{eid:08x} = {eid}")

# Check if all bd0c are the same
unique_bd = set(p["hex"] for p in bd0c_items)
print(f"\n  Unique payloads: {len(unique_bd)}")
if len(unique_bd) <= 5:
    for h in unique_bd:
        count = sum(1 for p in bd0c_items if p["hex"] == h)
        print(f"    {h} (x{count})")

# Check for floats
print("\n  Float scan (all bd0c):")
for i, pkt in enumerate(bd0c_items):
    raw = hex2bytes(pkt["hex"])
    for off in range(0, len(raw)-3, 2):
        if off + 4 <= len(raw):
            vf = struct.unpack_from("<f", raw, off)[0]
            if 100 <= abs(vf) <= 100000 and vf == vf:
                flag = " **RANGE**" if 400 <= vf <= 1100 else ""
                print(f"    #{i+1} f32@{off}={vf:.2f}{flag}")
        if off + 8 <= len(raw):
            vd = struct.unpack_from("<d", raw, off)[0]
            if 100 <= abs(vd) <= 100000 and vd == vd:
                flag = " **RANGE**" if 400 <= vd <= 1100 else ""
                print(f"    #{i+1} f64@{off}={vd:.4f}{flag}")

# ============================================
# 4. 0xc60c (2 instances, NEW)
# ============================================
print("\n" + "=" * 100)
print("4. 0xc60c (2 instances, NEW)")
print("=" * 100)

c60c_items = by_opcode.get("0xc60c", [])
print(f"Total: {len(c60c_items)}")
for i, pkt in enumerate(c60c_items):
    raw = hex2bytes(pkt["hex"])
    print(f"\n  #{i+1} t={pkt['time_str']} size={len(raw)}B")
    for row_start in range(0, len(raw), 32):
        chunk = raw[row_start:row_start+32]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    {row_start:4d}: {hex_part:<96s} |{ascii_part}|")

    texts = []
    j = 0
    while j < len(raw):
        if 32 <= raw[j] < 127:
            start = j
            while j < len(raw) and 32 <= raw[j] < 127:
                j += 1
            s = "".join(chr(b) for b in raw[start:j])
            if len(s) >= 2:
                texts.append((start, s))
        else:
            j += 1
    for off, s in texts:
        print(f"    TEXT @{off}: \"{s}\"")

# ============================================
# 5. 0xac0d (1 instance, NEW)
# ============================================
print("\n" + "=" * 100)
print("5. 0xac0d (1 instance, NEW)")
print("=" * 100)

ac0d_items = by_opcode.get("0xac0d", [])
for pkt in ac0d_items:
    raw = hex2bytes(pkt["hex"])
    print(f"  t={pkt['time_str']} size={len(raw)}B")
    for row_start in range(0, len(raw), 32):
        chunk = raw[row_start:row_start+32]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    {row_start:4d}: {hex_part:<96s} |{ascii_part}|")
    for off in range(0, len(raw), 2):
        parts = []
        if off + 2 <= len(raw):
            parts.append(f"u16={struct.unpack_from('<H', raw, off)[0]}")
        if off + 4 <= len(raw):
            u32 = struct.unpack_from("<I", raw, off)[0]
            f32 = struct.unpack_from("<f", raw, off)[0]
            parts.append(f"u32={u32}")
            if f32 == f32 and abs(f32) > 0.001 and abs(f32) < 1e10:
                parts.append(f"f32={f32:.4f}")
                if 400 <= f32 <= 1100:
                    parts.append("**RANGE**")
        if parts:
            print(f"    @{off}: {' '.join(parts)}")

# ============================================
# 6. 0x8d0c (1 instance, NEW)
# ============================================
print("\n" + "=" * 100)
print("6. 0x8d0c (1 instance, NEW)")
print("=" * 100)

items_8d0c = by_opcode.get("0x8d0c", [])
for pkt in items_8d0c:
    raw = hex2bytes(pkt["hex"])
    print(f"  t={pkt['time_str']} size={len(raw)}B hex={pkt['hex']}")
    for row_start in range(0, len(raw), 32):
        chunk = raw[row_start:row_start+32]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    {row_start:4d}: {hex_part:<96s} |{ascii_part}|")
    for off in range(0, len(raw), 2):
        parts = []
        if off + 4 <= len(raw):
            u32 = struct.unpack_from("<I", raw, off)[0]
            f32 = struct.unpack_from("<f", raw, off)[0]
            i32 = struct.unpack_from("<i", raw, off)[0]
            if u32 > 0 and u32 < 0x01000000:
                extra = " **RANGE**" if 400 <= f32 <= 1100 else ""
                parts.append(f"u32={u32} i32={i32} f32={f32:.4f}{extra}")
        if off + 8 <= len(raw):
            f64 = struct.unpack_from("<d", raw, off)[0]
            if 100 <= abs(f64) <= 100000 and f64 == f64:
                parts.append(f"f64={f64:.4f}")
        if parts:
            print(f"    @{off}: {' | '.join(parts)}")

# ============================================
# 7. 0x510c (5 instances)
# ============================================
print("\n" + "=" * 100)
print("7. 0x510c (5 instances)")
print("=" * 100)

items_510c = by_opcode.get("0x510c", [])
print(f"Total: {len(items_510c)}")
for i, pkt in enumerate(items_510c):
    raw = hex2bytes(pkt["hex"])
    print(f"\n  #{i+1} t={pkt['time_str']} size={len(raw)}B hex={pkt['hex']}")
    if len(raw) >= 2:
        print(f"    opcode: 0x{struct.unpack_from('<H', raw, 0)[0]:04x}")
    if len(raw) >= 6:
        u32_2 = struct.unpack_from("<I", raw, 2)[0]
        print(f"    u32@2: {u32_2} (0x{u32_2:08x})")
    if len(raw) >= 7:
        print(f"    byte@6: {raw[6]} (0x{raw[6]:02x})")

# ============================================
# 8. BATCH_ENTITY_UPDATE
# ============================================
print("\n" + "=" * 100)
print("8. BATCH_ENTITY_UPDATE - f64 values and distance field")
print("=" * 100)

batch_items = by_opcode.get("BATCH_ENTITY_UPDATE", [])
print(f"Total: {len(batch_items)}")
for i, pkt in enumerate(batch_items):
    raw = hex2bytes(pkt["hex"])
    print(f"\n  #{i+1} t={pkt['time_str']} size={len(raw)}B")

    # Find all f64 values
    f64_found = []
    for off in range(0, len(raw)-7, 2):
        f64 = struct.unpack_from("<d", raw, off)[0]
        if f64 == f64 and f64 != 0:
            if 1 < abs(f64) < 1e15:
                flag = ""
                if 400 <= f64 <= 1100:
                    flag = " **RANGE MATCH**"
                f64_found.append((off, f64, flag))
    for off, v, flag in f64_found:
        print(f"    f64@{off}={v:.6f}{flag}")

    # f32 in range
    for off in range(0, len(raw)-3, 2):
        f32 = struct.unpack_from("<f", raw, off)[0]
        if 400 <= f32 <= 1100 and f32 == f32:
            print(f"    f32@{off}={f32:.4f} **RANGE MATCH**")

# ============================================
# 9. 0x410e
# ============================================
print("\n" + "=" * 100)
print("9. 0x410e - named stat block")
print("=" * 100)

items_410e = by_opcode.get("0x410e", [])
print(f"Total: {len(items_410e)}")
for i, pkt in enumerate(items_410e):
    raw = hex2bytes(pkt["hex"])
    print(f"\n  #{i+1} t={pkt['time_str']} size={len(raw)}B")
    for row_start in range(0, len(raw), 32):
        chunk = raw[row_start:row_start+32]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    {row_start:4d}: {hex_part:<96s} |{ascii_part}|")

    texts = []
    j = 0
    while j < len(raw):
        if 32 <= raw[j] < 127:
            start = j
            while j < len(raw) and 32 <= raw[j] < 127:
                j += 1
            s = "".join(chr(b) for b in raw[start:j])
            if len(s) >= 2:
                texts.append((start, s))
        else:
            j += 1
    for off, s in texts:
        flag = ""
        sl = s.lower()
        if any(k in sl for k in ["range", "atk", "shoot", "attack", "dist", "reach"]):
            flag = " *** CONTAINS RANGE/ATK KEYWORD ***"
        print(f"    TEXT @{off}: \"{s}\"{flag}")

    # Decode numeric values after each stat name
    for off in range(0, len(raw)-3, 2):
        if off + 4 <= len(raw):
            f32 = struct.unpack_from("<f", raw, off)[0]
            if 400 <= f32 <= 1100 and f32 == f32:
                print(f"    f32@{off}={f32:.4f} **RANGE MATCH**")
        if off + 8 <= len(raw):
            f64 = struct.unpack_from("<d", raw, off)[0]
            if 400 <= f64 <= 1100 and f64 == f64:
                print(f"    f64@{off}={f64:.4f} **RANGE MATCH**")

# ============================================
# 10. Timeline
# ============================================
print("\n" + "=" * 100)
print("10. TIMELINE")
print("=" * 100)

timeline = []
for i, p in enumerate(packets):
    for parsed in p.get("parsed", []):
        name = parsed.get("name", parsed.get("opcode", "?"))
        timeline.append({
            "time": p["time"],
            "time_str": p["time_str"],
            "name": name,
            "pkt_idx": i
        })

timeline.sort(key=lambda x: x["time"])

by_second = defaultdict(list)
for ev in timeline:
    by_second[ev["time_str"]].append(ev["name"])

print("\nPackets per second:")
for sec in sorted(by_second.keys()):
    events = by_second[sec]
    summary = defaultdict(int)
    for e in events:
        summary[e] += 1
    parts = [f"{k}x{v}" if v > 1 else k for k, v in summary.items()]
    print(f"  {sec}: {', '.join(parts)}")

# 0x590c vs COMBAT_UPDATE timing
print("\n--- 0x590c vs COMBAT_UPDATE timing correlation ---")
cu_times = [e["time"] for e in timeline if e["name"] == "COMBAT_UPDATE"]
s59_times = [e["time"] for e in timeline if e["name"] == "0x590c"]

for st in s59_times[:15]:
    nearest_cu = min(cu_times, key=lambda t: abs(t - st)) if cu_times else None
    if nearest_cu:
        diff = st - nearest_cu
        print(f"  0x590c at t={st:.3f} -> nearest CU delta = {diff:+.3f}s")

# ============================================
# OPCODE FREQUENCY COMPARISON
# ============================================
print("\n" + "=" * 100)
print("OPCODE FREQUENCY COMPARISON: autoattack_dummy vs combat_capture")
print("=" * 100)

prev = {
    "ENTITY_POSITION": 128, "BATCH_ENTITY_UPDATE": 41, "COMBAT_UPDATE": 36,
    "ENTITY_STATE_F64": 12, "0xe10b": 5, "ENTITY_EVENT": 4, "ENTITY_DESPAWN": 3,
    "ITEM_DROP": 2, "0xa60c": 2, "0xdb0c": 2, "0x410e": 2, "0xa80c": 1,
    "0xa20c": 1, "0x420c": 1, "EFFECT": 2, "ACK": 1, "0x0800": 1, "MONSTER_SPAWN": 2
}

curr = data["opcode_summary"]

all_ops = sorted(set(list(prev.keys()) + list(curr.keys())))
print(f"  {'Opcode':<25s} {'combat_capture':>15s} {'autoattack_dummy':>17s} {'Delta':>8s}")
print(f"  {'-'*25} {'-'*15} {'-'*17} {'-'*8}")
for op in all_ops:
    p = prev.get(op, 0)
    c = curr.get(op, 0)
    delta = c - p
    flag = ""
    if c > 0 and p == 0:
        flag = " NEW!"
    elif p > 0 and c == 0:
        flag = " GONE"
    print(f"  {op:<25s} {p:>15d} {c:>17d} {delta:>+8d}{flag}")

# ============================================
# EXTRA: Scan ALL packets for any float in 400-1100 range
# ============================================
print("\n" + "=" * 100)
print("GLOBAL SCAN: Any float (f32/f64) in 400-1100 range across ALL packets")
print("=" * 100)

for i, p in enumerate(packets):
    for parsed in p.get("parsed", []):
        raw = hex2bytes(parsed["hex"])
        name = parsed.get("name", parsed.get("opcode", "?"))
        found = []
        for off in range(0, len(raw)-3, 2):
            if off + 4 <= len(raw):
                f32 = struct.unpack_from("<f", raw, off)[0]
                if 400 <= f32 <= 1100 and f32 == f32:
                    exact = int(f32) in known_range_values
                    found.append(f"f32@{off}={f32:.4f}{'*EXACT*' if exact else ''}")
            if off + 8 <= len(raw):
                f64 = struct.unpack_from("<d", raw, off)[0]
                if 400 <= f64 <= 1100 and f64 == f64:
                    exact = int(f64) in known_range_values
                    found.append(f"f64@{off}={f64:.4f}{'*EXACT*' if exact else ''}")
        if found:
            print(f"  pkt#{i} t={p['time_str']} {name}: {', '.join(found)}")
