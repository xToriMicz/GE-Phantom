"""Deep analysis of 0x5a0c — variable-size entity packet.

Known from prior analysis:
  13 instances, deduced sizes: 10 (5x), 42 (3x), 74 (3x), 12 (1x), 16 (1x)
  Hypothesis: 10b header + N * 32b entries (N=0,1,2)
  - 10 = 10 + 0*32
  - 42 = 10 + 1*32
  - 74 = 10 + 2*32
  No length field detected. Looking for count byte (u8) in header.
  Always followed by ENTITY_STAT -> likely entity-related batch.
"""

import json
import struct
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.protocol.packet_types import KNOWN_PACKETS, get_packet_size

CAPTURES_DIR = Path(__file__).parent.parent / "captures"
ENTRY_SIZE = 32
HEADER_SIZE = 10


def find_validated_boundary(data: bytes, start: int) -> list[dict]:
    """Find validated known-opcode boundaries after `start` offset."""
    results = []
    for offset in range(start, len(data) - 1):
        candidate = int.from_bytes(data[offset:offset + 2], "big")
        if candidate == 0x0000:
            continue
        pdef = KNOWN_PACKETS.get(candidate)
        if pdef is None:
            continue

        remaining = data[offset:]
        pkt_size = get_packet_size(remaining[:min(len(remaining), 8)])

        if pkt_size is not None:
            end = offset + pkt_size
            if end == len(data):
                results.append({"offset": offset, "opcode": candidate,
                                "name": pdef.name, "size": pkt_size, "chain": 1})
            elif end + 2 <= len(data):
                next_opc = int.from_bytes(data[end:end + 2], "big")
                if next_opc in KNOWN_PACKETS and next_opc != 0x0000:
                    results.append({"offset": offset, "opcode": candidate,
                                    "name": pdef.name, "size": pkt_size, "chain": 2})

    return results


def extract_5a0c_instances():
    """Extract all 0x5a0c instances from captures with full context."""
    instances = []
    opcode_bytes = (0x5a0c).to_bytes(2, "big")

    for capture_file in sorted(CAPTURES_DIR.glob("*.json")):
        data = json.loads(capture_file.read_text())
        packets = data.get("packets", data) if isinstance(data, dict) else data

        for pkt in packets:
            payload_hex = pkt.get("payload_hex", "")
            if not payload_hex:
                continue
            payload = bytes.fromhex(payload_hex)
            direction = pkt.get("direction", "S2C")
            if direction != "S2C":
                continue

            # Check if segment starts with 0x5a0c
            if len(payload) >= 2 and payload[:2] == opcode_bytes:
                boundaries = find_validated_boundary(payload, 4)
                deduced = boundaries[0]["offset"] if boundaries else len(payload)
                instances.append({
                    "data": payload[:deduced],
                    "full_segment": payload,
                    "deduced_size": deduced,
                    "boundary": boundaries[0] if boundaries else None,
                    "file": capture_file.name,
                    "timestamp": pkt.get("timestamp", 0),
                })

            # Also scan for embedded 0x5a0c
            for i in range(2, len(payload) - 1):
                if payload[i:i + 2] == opcode_bytes:
                    remaining = payload[i:]
                    boundaries = find_validated_boundary(remaining, 4)
                    deduced = boundaries[0]["offset"] if boundaries else len(remaining)
                    instances.append({
                        "data": remaining[:deduced],
                        "full_segment": remaining,
                        "deduced_size": deduced,
                        "boundary": boundaries[0] if boundaries else None,
                        "file": capture_file.name,
                        "timestamp": pkt.get("timestamp", 0),
                        "embedded_at": i,
                    })

    return instances


def analyze_count_byte(instances: list[dict]):
    """Check each byte position for correlation with entry count N."""
    print("\n" + "=" * 70)
    print("COUNT BYTE ANALYSIS")
    print("=" * 70)

    # Filter to instances with confirmed sizes (10, 42, 74)
    confirmed = [inst for inst in instances if inst["deduced_size"] in (10, 42, 74)]
    if not confirmed:
        print("  No confirmed instances found!")
        return None

    print(f"  Confirmed instances: {len(confirmed)}")

    # Calculate expected N for each
    for inst in confirmed:
        inst["expected_n"] = (inst["deduced_size"] - HEADER_SIZE) // ENTRY_SIZE

    # Check each byte position in the 10-byte header
    print(f"\n  Checking each header byte for count correlation (N=0,1,2):")
    for byte_pos in range(min(HEADER_SIZE, min(len(inst["data"]) for inst in confirmed))):
        values_by_n = defaultdict(set)
        for inst in confirmed:
            n = inst["expected_n"]
            val = inst["data"][byte_pos]
            values_by_n[n].add(val)

        # Check if byte value == N
        exact_match = all(
            all(v == n for v in vals)
            for n, vals in values_by_n.items()
        )

        # Check if byte value correlates with N (unique value per N)
        unique_per_n = all(len(vals) == 1 for vals in values_by_n.values())
        correlated = unique_per_n and len(set(
            next(iter(vals)) for vals in values_by_n.values()
        )) == len(values_by_n)

        vals_str = {n: sorted(v) for n, v in sorted(values_by_n.items())}
        marker = ""
        if exact_match:
            marker = " <<< EXACT COUNT BYTE!"
        elif correlated:
            marker = " <<< CORRELATED"

        print(f"    byte[{byte_pos}]: N->values = {vals_str}{marker}")

    # Also check u16le fields
    print(f"\n  Checking u16le fields:")
    for offset in range(0, HEADER_SIZE - 1, 2):
        values_by_n = defaultdict(set)
        for inst in confirmed:
            n = inst["expected_n"]
            val = int.from_bytes(inst["data"][offset:offset + 2], "little")
            values_by_n[n].add(val)

        vals_str = {n: sorted(v) for n, v in sorted(values_by_n.items())}
        print(f"    u16le[{offset}:{offset+2}]: N->values = {vals_str}")

    # Check if deduced_size appears anywhere in the header as u16le
    print(f"\n  Checking if deduced_size appears in header:")
    for inst in confirmed:
        data = inst["data"]
        size = inst["deduced_size"]
        found = []
        for off in range(HEADER_SIZE - 1):
            val_le = int.from_bytes(data[off:off + 2], "little")
            val_be = int.from_bytes(data[off:off + 2], "big")
            if val_le == size:
                found.append(f"u16le@{off}")
            if val_be == size:
                found.append(f"u16be@{off}")
        n = inst["expected_n"]
        print(f"    size={size} (N={n}): {found if found else 'NOT FOUND'}")


def analyze_entry_structure(instances: list[dict]):
    """Analyze the 32-byte entry structure."""
    print("\n" + "=" * 70)
    print("ENTRY STRUCTURE ANALYSIS")
    print("=" * 70)

    entries = []
    for inst in instances:
        data = inst["data"]
        n = (inst["deduced_size"] - HEADER_SIZE) // ENTRY_SIZE
        for i in range(n):
            start = HEADER_SIZE + i * ENTRY_SIZE
            end = start + ENTRY_SIZE
            if end <= len(data):
                entries.append({
                    "data": data[start:end],
                    "entry_index": i,
                    "parent_n": n,
                    "file": inst["file"],
                })

    if not entries:
        print("  No entries found (all instances have N=0)")
        return

    print(f"  Total entries extracted: {len(entries)}")

    # Show hex dumps of all entries
    print(f"\n  Entry hex dumps:")
    for entry in entries:
        hex_str = " ".join(f"{b:02x}" for b in entry["data"])
        print(f"    [{entry['entry_index']}/{entry['parent_n']}] {hex_str}")

    # Byte-by-byte analysis
    print(f"\n  Per-byte analysis (constant vs varying):")
    for pos in range(ENTRY_SIZE):
        values = set(e["data"][pos] for e in entries)
        if len(values) == 1:
            val = next(iter(values))
            print(f"    byte[{pos:2d}]: CONSTANT = 0x{val:02x} ({val})")
        else:
            vals_str = ", ".join(f"0x{v:02x}" for v in sorted(values))
            print(f"    byte[{pos:2d}]: VARIES ({len(values)} unique): {vals_str}")

    # Try common field types
    print(f"\n  Field interpretation attempts:")
    for entry in entries:
        d = entry["data"]
        print(f"    Entry [{entry['entry_index']}/{entry['parent_n']}]:")

        # Try u16le at various offsets
        for off in range(0, min(ENTRY_SIZE - 1, 20), 2):
            val = int.from_bytes(d[off:off + 2], "little")
            if val != 0:
                print(f"      u16le[{off}:{off+2}] = {val} (0x{val:04x})")

        # Try u32le at various offsets
        for off in range(0, min(ENTRY_SIZE - 3, 20), 4):
            val = int.from_bytes(d[off:off + 4], "little")
            if val != 0:
                # Try f32 interpretation too
                f_val = struct.unpack("<f", d[off:off + 4])[0]
                f_str = f" / f32={f_val:.4f}" if 0.001 < abs(f_val) < 100000 else ""
                print(f"      u32le[{off}:{off+4}] = {val} (0x{val:08x}){f_str}")


def main():
    instances = extract_5a0c_instances()

    print("0x5a0c DEEP ANALYSIS")
    print("=" * 70)
    print(f"Total instances found: {len(instances)}")

    # Filter to likely real instances (sizes 10, 42, 74)
    for inst in instances:
        size = inst["deduced_size"]
        n = (size - HEADER_SIZE) / ENTRY_SIZE if size >= HEADER_SIZE else -1
        n_int = int(n) if n == int(n) and n >= 0 else None
        boundary_name = inst["boundary"]["name"] if inst["boundary"] else "NONE"
        embedded = f" (embedded@{inst['embedded_at']})" if "embedded_at" in inst else ""

        hex_head = " ".join(f"{b:02x}" for b in inst["data"][:min(20, len(inst["data"]))])
        n_str = f"N={n_int}" if n_int is not None else f"N={n:.1f}(?)"
        fits = "OK" if n_int is not None else "BAD"

        print(f"  size={size:3d}  {n_str:6s} ({fits})  "
              f"->{boundary_name:15s}  {hex_head}{embedded}")

    # Count byte analysis
    analyze_count_byte(instances)

    # Entry structure analysis
    analyze_entry_structure(instances)

    # Summary
    confirmed = [inst for inst in instances if inst["deduced_size"] in (10, 42, 74)]
    print(f"\n{'='*70}")
    print("SUMMARY")
    print("=" * 70)
    print(f"  Confirmed instances: {len(confirmed)}/{ len(instances)}")
    print(f"  Pattern: 10b header + N * 32b entries (N=0,1,2)")
    print(f"  Size formula: size = 10 + N * 32")
    print(f"  Sizes observed: 10 (N=0), 42 (N=1), 74 (N=2)")

    if confirmed:
        # Check if the formula works for ALL confirmed
        all_fit = all(
            (inst["deduced_size"] - HEADER_SIZE) % ENTRY_SIZE == 0
            for inst in confirmed
        )
        print(f"  All confirmed fit formula: {all_fit}")

    # Recommendation
    print(f"\n  RECOMMENDATION:")
    print(f"  If count byte found -> use custom framing")
    print(f"  If no count byte -> boundary scanning (current fallback)")


if __name__ == "__main__":
    main()
