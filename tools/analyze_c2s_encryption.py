#!/usr/bin/env python3
"""
C2S Encryption Analysis Tool for GE_Phantom
Analyzes C2S packet payloads for cipher patterns.
"""

import json, glob, math, os, sys
from collections import Counter, defaultdict

CAPTURE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "captures")
KEEPALIVE_OP = "1000"
PLAYER_ACTION_OP = "1800"
SEP = "=" * 80


def load_all_packets():
    all_packets = []
    files = sorted(glob.glob(os.path.join(CAPTURE_DIR, "*.json")))
    if not files:
        print(f"[ERROR] No capture files found in {CAPTURE_DIR}")
        sys.exit(1)
    for fpath in files:
        with open(fpath, "r") as f:
            data = json.load(f)
        packets = data.get("packets", [])
        fname = os.path.basename(fpath)
        for p in packets:
            p["_source_file"] = fname
        all_packets.extend(packets)
    print(f"Loaded {len(all_packets)} total packets from {len(files)} capture files")
    return all_packets, files


def h2b(s): return bytes.fromhex(s)

def xor_bytes(a, b): return bytes(x ^ y for x, y in zip(a, b))


def entropy(bl):
    if not bl: return 0.0
    c = Counter(bl); total = len(bl); ent = 0.0
    for count in c.values():
        p = count / total
        if p > 0: ent -= p * math.log2(p)
    return ent


def fmt_hex(data):
    hp = " ".join(f"{b:02x}" for b in data)
    ap = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"  {hp}  |{ap}|"


def extract_c2s(all_packets, op):
    return [p for p in all_packets if p["direction"] == "C2S" and p["payload_hex"][:4] == op]


def dump_payloads(packets, label):
    print(f"
{SEP}")
    print(f"  {label} -- RAW PAYLOADS ({len(packets)} packets)")
    print(SEP)
    for i, p in enumerate(packets):
        raw = h2b(p["payload_hex"])
        ts = p.get("timestamp", 0)
        src = p.get("_source_file", "?")
        print(f"
  [{i:3d}] size={len(raw):2d}  ts={ts:.3f}  file={src}")
        print(fmt_hex(raw))


def xor_consecutive(packets, label):
    print(f"
{SEP}")
    print(f"  {label} -- XOR CONSECUTIVE PAIRS ({len(packets)-1} pairs)")
    print(SEP)
    if len(packets) < 2:
        print("  Not enough packets."); return []
    xor_results = []
    for i in range(len(packets) - 1):
        a = h2b(packets[i]["payload_hex"])
        b = h2b(packets[i + 1]["payload_hex"])
        xored = xor_bytes(a, b)
        xor_results.append(xored)
        zeros = sum(1 for x in xored if x == 0)
        nonzero = len(xored) - zeros
        dt = packets[i + 1].get("timestamp", 0) - packets[i].get("timestamp", 0)
        print(f"
  [{i:3d}] ^ [{i+1:3d}]  dt={dt:+8.3f}s  same={zeros}/{len(xored)}  changed={nonzero}")
        print(fmt_hex(xored))
    return xor_results


def check_rotation_shift(packets, label):
    print(f"
{SEP}")
    print(f"  {label} -- ROTATION / SHIFT ANALYSIS")
    print(SEP)
    if len(packets) < 2: print("  Not enough packets."); return
    payload_len = len(h2b(packets[0]["payload_hex"]))
    print(f"
  Byte-position delta (b[i+1] - b[i]) mod 256:")
    hdr = "  pair   |"
    for pos in range(payload_len): hdr += f" {pos:4d}"
    print(hdr)
    print("  " + "-" * (9 + 5 * payload_len))
    delta_by_pos = defaultdict(list)
    for i in range(min(len(packets) - 1, 20)):
        a = h2b(packets[i]["payload_hex"])
        b = h2b(packets[i + 1]["payload_hex"])
        deltas = [(b[j] - a[j]) % 256 for j in range(min(len(a), len(b)))]
        for j, d in enumerate(deltas): delta_by_pos[j].append(d)
        row = f"  {i:2d}->{i+1:<2d} |"
        for d in deltas: row += f" {d:4d}"
        print(row)
    print(f"
  Constant-delta check:")
    found = False
    for pos in range(payload_len):
        vals = delta_by_pos[pos]
        if len(vals) >= 3:
            if len(set(vals)) == 1:
                print(f"    pos {pos:2d}: CONSTANT delta = {vals[0]} (counter-mode candidate!)")
                found = True
            elif len(set(vals)) <= 3:
                print(f"    pos {pos:2d}: near-constant deltas = {sorted(set(vals))}")
                found = True
    if not found: print("    No constant-delta positions found.")


def byte_frequency_and_entropy(packets, label):
    print(f"
{SEP}")
    print(f"  {label} -- BYTE FREQUENCY & ENTROPY ({len(packets)} packets)")
    print(SEP)
    if not packets: print("  No packets."); return
    payload_len = len(h2b(packets[0]["payload_hex"]))
    pos_values = defaultdict(list)
    for p in packets:
        raw = h2b(p["payload_hex"])
        for j, b in enumerate(raw): pos_values[j].append(b)
    print(f"
   Pos   Min   Max   Mean  Uniq   Entropy  Assessment")
    print("  " + "-" * 70)
    overall_ent = 0.0
    for pos in range(payload_len):
        vals = pos_values[pos]
        e = entropy(vals)
        overall_ent += e
        mn, mx = min(vals), max(vals)
        mean = sum(vals) / len(vals)
        unique = len(set(vals))
        if unique == 1: assess = "FIXED (constant)"
        elif e < 1.0: assess = "LOW entropy"
        elif e < 3.0: assess = "MODERATE"
        elif e < 5.0: assess = "MEDIUM-HIGH"
        else: assess = "HIGH -- random/encrypted"
        print(f"  {pos:4d}  {mn:4d}  {mx:4d}  {mean:6.1f}  {unique:6d}  {e:8.3f}  {assess}")
    avg = overall_ent / payload_len if payload_len > 0 else 0
    maxp = math.log2(len(packets)) if len(packets) > 1 else 0
    print(f"
  Average entropy: {avg:.3f} bits")
    print(f"  Max possible (log2({len(packets)})): {maxp:.3f} bits")
    if maxp > 0: print(f"  Ratio: {avg/maxp*100:.1f}%")
    print(f"
  Top-3 byte values at each position:")
    for pos in range(payload_len):
        vals = pos_values[pos]
        top3 = Counter(vals).most_common(3)
        dist = ", ".join(f"0x{v:02x}({c})" for v, c in top3)
        print(f"    pos {pos:2d}: {dist}")


def xor_distance_analysis(packets, label):
    print(f"
{SEP}")
    print(f"  {label} -- XOR DISTANCE ANALYSIS")
    print(SEP)
    if len(packets) < 2: print("  Not enough packets."); return
    distances = []
    for i in range(len(packets) - 1):
        a = h2b(packets[i]["payload_hex"])
        b = h2b(packets[i + 1]["payload_hex"])
        xored = xor_bytes(a, b)
        bit_diff = sum(bin(byte).count("1") for byte in xored)
        byte_diff = sum(1 for byte in xored if byte != 0)
        distances.append((bit_diff, byte_diff, len(xored)))
    print(f"
  Pair      BitDiff  ByteDiff  TotalBytes  BitRatio")
    print("  " + "-" * 55)
    for i, (bd, byd, total) in enumerate(distances):
        ratio = bd / (total * 8) * 100
        print(f"  {i:3d}->{i+1:<3d}  {bd:8d}  {byd:8d}  {total:10d}  {ratio:8.1f}%")
    avg_bit = sum(d[0] for d in distances) / len(distances)
    avg_byte = sum(d[1] for d in distances) / len(distances)
    total_bits = distances[0][2] * 8
    exp_byte = distances[0][2] * (1 - 1/256)
    print(f"
  Average bit distance:  {avg_bit:.1f} / {total_bits} ({avg_bit/total_bits*100:.1f}%)")
    print(f"  Average byte distance: {avg_byte:.1f} / {distances[0][2]}")
    print(f"  Expected for random:   ~50% bit, ~{exp_byte:.1f}/{distances[0][2]} byte")


def cipher_signature_analysis(packets, label):
    print(f"
{SEP}")
    print(f"  {label} -- CIPHER SIGNATURE DETECTION")
    print(SEP)
    if len(packets) < 2: print("  Not enough packets."); return
    payloads = [h2b(p["payload_hex"]) for p in packets]
    plen = len(payloads[0])

    # Test 1: XOR fixed key
    print(f"
  [1] XOR Fixed-Key Test")
    print(f"      If payloads XORd with same key, plaintext XOR leaks.")
    xpairs = []
    for i in range(min(len(payloads) - 1, 30)):
        xored = xor_bytes(payloads[i], payloads[i + 1])
        e = entropy(list(xored[2:]))
        xpairs.append(e)
    avg_xe = sum(xpairs) / len(xpairs) if xpairs else 0
    print(f"      Avg entropy of C[i]^C[i+1] (data): {avg_xe:.3f} bits")
    if avg_xe < 3.0: print(f"      >>> LOW -- consistent with XOR cipher")
    elif avg_xe < 5.0: print(f"      >>> MODERATE -- possible XOR with varying plaintext")
    else: print(f"      >>> HIGH -- NOT simple XOR cipher")

    print(f"
      Key recovery (assuming null plaintext after opcode):")
    assumed = bytes([0x10, 0x00]) + bytes(plen - 2)
    keys = []
    for i, pl in enumerate(payloads[:10]):
        key = xor_bytes(pl, assumed)
        keys.append(key)
        print(f"      key[{i:2d}] = {key.hex()}")
    if len(set(k.hex() for k in keys)) == 1:
        print(f"      >>> ALL KEYS IDENTICAL -- static XOR key!")
    else:
        print(f"      >>> Keys differ -- not simple static XOR")

    if len(keys) >= 2:
        print(f"
      Key-to-key deltas:")
        for i in range(min(len(keys) - 1, 5)):
            delta = xor_bytes(keys[i], keys[i + 1])
            print(f"      key[{i}]^key[{i+1}] = {delta.hex()}")

    # Test 2: Rotation cipher
    print(f"
  [2] Rotation Cipher Test")
    for pos in [2, 3, 4, 5]:
        if pos >= plen: break
        vals = [p[pos] for p in payloads]
        diffs = [(vals[i + 1] - vals[i]) % 256 for i in range(len(vals) - 1)]
        udiffs = len(set(diffs))
        mc = Counter(diffs).most_common(1)[0] if diffs else (0, 0)
        print(f"      pos {pos}: {udiffs} unique deltas, most common: delta={mc[0]} (x{mc[1]})")

    # Test 3: Counter mode
    print(f"
  [3] Counter-Mode Test")
    found_ctr = False
    for pos in range(plen):
        vals = [p[pos] for p in payloads]
        diffs = [(vals[i + 1] - vals[i]) % 256 for i in range(len(vals) - 1)]
        if len(diffs) >= 2 and len(set(diffs)) == 1 and diffs[0] != 0:
            print(f"      pos {pos}: CONSTANT +{diffs[0]} -- COUNTER DETECTED")
            found_ctr = True
        elif len(diffs) >= 2 and len(set(diffs)) <= 2 and 0 not in set(diffs):
            print(f"      pos {pos}: near-constant {sorted(set(diffs))} -- possible counter")
            found_ctr = True
    if not found_ctr: print(f"      No single-byte counter patterns.")

    print(f"
      Multi-byte counter (16-bit LE/BE):")
    found_m = False
    for start in range(0, plen - 1):
        vle = [int.from_bytes(p[start:start+2], "little") for p in payloads]
        vbe = [int.from_bytes(p[start:start+2], "big") for p in payloads]
        dle = [(vle[i+1] - vle[i]) % 65536 for i in range(len(vle)-1)]
        dbe = [(vbe[i+1] - vbe[i]) % 65536 for i in range(len(vbe)-1)]
        if len(dle) >= 2 and len(set(dle)) == 1 and dle[0] != 0:
            print(f"      pos {start}..{start+1} LE: constant +{dle[0]}")
            found_m = True
        if len(dbe) >= 2 and len(set(dbe)) == 1 and dbe[0] != 0:
            print(f"      pos {start}..{start+1} BE: constant +{dbe[0]}")
            found_m = True
    if not found_m: print(f"      No multi-byte counter patterns.")

    # Test 4: Block alignment
    print(f"
  [4] Block Alignment")
    print(f"      Payload: {plen} bytes")
    for bs in [4, 8, 16]:
        if plen % bs == 0: print(f"      Aligned to {bs}-byte blocks ({plen // bs} blocks)")
        else: print(f"      NOT aligned to {bs} (remainder {plen % bs})")

    # Test 5: Pairwise XOR entropy
    print(f"
  [5] Pairwise XOR Entropy (first 10x10)")
    n = min(10, len(payloads))
    hdr = "          "
    for j in range(n): hdr += f" {j:5d}"
    print(hdr)
    for i in range(n):
        row = f"      {i:3d}:"
        for j in range(n):
            if i == j: row += "    --"
            else:
                xored = xor_bytes(payloads[i], payloads[j])
                e = entropy(list(xored))
                row += f" {e:5.2f}"
        print(row)


def global_summary(ka_packets, pa_packets):
    print(f"
{SEP}")
    print(f"  GLOBAL SUMMARY & CONCLUSIONS")
    print(SEP)
    print(f"
  Packet counts:")
    print(f"    KEEPALIVE (0x1000, 18B): {len(ka_packets)}")
    print(f"    PLAYER_ACTION (0x1800, 26B): {len(pa_packets)}")
    if ka_packets:
        payloads = [h2b(p["payload_hex"]) for p in ka_packets]
        opcodes = set(p[:2].hex() for p in payloads)
        print(f"
  KEEPALIVE opcodes: {opcodes}")
        if opcodes == {"1000"}:
            print(f"  Opcode 0x1000 ALWAYS plaintext in first 2 bytes")
            print(f"  => Encryption starts AFTER opcode header")
        all_b = []
        for p in payloads: all_b.extend(list(p[2:]))
        oe = entropy(all_b)
        print(f"  Overall data entropy (skip opcode): {oe:.3f} / 8.0 bits")
        unique = len(set(p.hex() for p in payloads))
        print(f"  Unique payloads: {unique}/{len(payloads)}")
        if unique == len(payloads): print(f"  => Every packet unique (no repeats)")
        else: print(f"  => {len(payloads)-unique} duplicates")
    if pa_packets:
        payloads = [h2b(p["payload_hex"]) for p in pa_packets]
        opcodes = set(p[:2].hex() for p in payloads)
        print(f"
  PLAYER_ACTION opcodes: {opcodes}")
        unique = len(set(p.hex() for p in payloads))
        print(f"  Unique payloads: {unique}/{len(payloads)}")


def main():
    print(SEP)
    print("  GE_Phantom -- C2S Encryption Analysis Tool")
    print("  Analyzing KEEPALIVE (0x1000) and PLAYER_ACTION (0x1800)")
    print(SEP)
    all_packets, files = load_all_packets()
    print(f"Capture files: {[os.path.basename(f) for f in files]}")
    ka = extract_c2s(all_packets, KEEPALIVE_OP)
    ka18 = [p for p in ka if len(h2b(p["payload_hex"])) == 18]
    ka_other = [p for p in ka if len(h2b(p["payload_hex"])) != 18]
    pa = extract_c2s(all_packets, PLAYER_ACTION_OP)
    print(f"
KEEPALIVE (18B): {len(ka18)} packets")
    if ka_other:
        sizes = set(len(h2b(p["payload_hex"])) for p in ka_other)
        print(f"KEEPALIVE (other): {len(ka_other)} -- sizes: {sizes}")
    print(f"PLAYER_ACTION: {len(pa)} packets")

    if ka18:
        dump_payloads(ka18, "KEEPALIVE 0x1000 (18B)")
        xor_consecutive(ka18, "KEEPALIVE 0x1000 (18B)")
        check_rotation_shift(ka18, "KEEPALIVE 0x1000 (18B)")
        byte_frequency_and_entropy(ka18, "KEEPALIVE 0x1000 (18B)")
        xor_distance_analysis(ka18, "KEEPALIVE 0x1000 (18B)")
        cipher_signature_analysis(ka18, "KEEPALIVE 0x1000 (18B)")

    if pa:
        dump_payloads(pa, "PLAYER_ACTION 0x1800 (26B)")
        xor_consecutive(pa, "PLAYER_ACTION 0x1800 (26B)")
        check_rotation_shift(pa, "PLAYER_ACTION 0x1800 (26B)")
        byte_frequency_and_entropy(pa, "PLAYER_ACTION 0x1800 (26B)")
        xor_distance_analysis(pa, "PLAYER_ACTION 0x1800 (26B)")
        cipher_signature_analysis(pa, "PLAYER_ACTION 0x1800 (26B)")

    global_summary(ka18, pa)
    print(f"
{SEP}")
    print(f"  Analysis complete.")
    print(SEP)


if __name__ == "__main__":
    main()
