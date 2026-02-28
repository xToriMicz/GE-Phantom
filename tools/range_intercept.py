"""
GE_Phantom — Attack Range Interceptor (Approach A: Packet Interception)

Intercepts COMBAT_UPDATE packets from GE server and modifies attack_range
before the game client reads them. Uses WinDivert (kernel-level packet filter).

Requires:
  pip install pydivert
  Run as Administrator!

Usage:
  python -m tools.range_intercept --range 5000           # Modify all ranges to 5000
  python -m tools.range_intercept --range 5000 --eid 1234  # Only modify entity 1234
  python -m tools.range_intercept --monitor               # Monitor only, don't modify
"""

from __future__ import annotations

import argparse
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.protocol.packet_types import (
    KNOWN_PACKETS,
    get_packet_size,
    decode_packet,
    HEADER_SIZE,
)
from src.sniffer.capture import DEFAULT_SERVER_IPS, DEFAULT_PORTS

# --- Constants from protocol analysis ---
COMBAT_UPDATE_OPCODE = 0x540c
COMBAT_UPDATE_SIZE = 38
SPEED_OFFSET = 30        # movement speed f32le within COMBAT_UPDATE (was mislabeled attack_range)
ENTITY_ID_OFFSET = 2     # entity_id u32le within COMBAT_UPDATE

# 0x4300 — stat array sent during login (30 x u32 values)
# Contains potential attack_range values at indices 0-2,6,16,23,28
STAT_ARRAY_OPCODE = 0x4300
STAT_ARRAY_SIZE = 126     # fixed: 6 header + 30*4 data
STAT_ARRAY_DATA_OFF = 6   # first u32 value starts here
STAT_ARRAY_COUNT = 30     # number of u32 entries


def build_windivert_filter(
    server_ips: list[str] | None = None,
    ports: list[int] | None = None,
    direction: str = "s2c",
) -> str:
    """Build WinDivert filter for GE server traffic with payload.

    direction: "s2c" (server→client), "c2s" (client→server), "both"
    """
    ips = server_ips or DEFAULT_SERVER_IPS

    if direction == "s2c":
        ip_clause = " or ".join(f"ip.SrcAddr == {ip}" for ip in ips)
        if ports:
            port_clause = " or ".join(f"tcp.SrcPort == {p}" for p in ports)
        else:
            port_clause = "tcp.SrcPort >= 7000 and tcp.SrcPort <= 7015"
    elif direction == "c2s":
        ip_clause = " or ".join(f"ip.DstAddr == {ip}" for ip in ips)
        if ports:
            port_clause = " or ".join(f"tcp.DstPort == {p}" for p in ports)
        else:
            port_clause = "tcp.DstPort >= 7000 and tcp.DstPort <= 7015"
    else:  # both
        src_clause = " or ".join(f"ip.SrcAddr == {ip}" for ip in ips)
        dst_clause = " or ".join(f"ip.DstAddr == {ip}" for ip in ips)
        ip_clause = f"({src_clause}) or ({dst_clause})"
        if ports:
            port_clause = (" or ".join(f"tcp.SrcPort == {p}" for p in ports)
                           + " or "
                           + " or ".join(f"tcp.DstPort == {p}" for p in ports))
        else:
            port_clause = ("(tcp.SrcPort >= 7000 and tcp.SrcPort <= 7015)"
                           " or "
                           "(tcp.DstPort >= 7000 and tcp.DstPort <= 7015)")

    return f"({ip_clause}) and ({port_clause}) and tcp.PayloadLength > 0"


def dump_combat_update(data: bytes, off: int) -> None:
    """Dump all fields of a COMBAT_UPDATE packet at offset `off`."""
    raw = data[off:off + COMBAT_UPDATE_SIZE]

    # Parse every 2/4 byte field
    opcode   = (raw[0] << 8) | raw[1]
    eid      = struct.unpack_from('<I', raw, 2)[0]
    unk_06   = struct.unpack_from('<H', raw, 6)[0]
    unk_08   = struct.unpack_from('<H', raw, 8)[0]
    tick     = struct.unpack_from('<I', raw, 10)[0]
    zone     = struct.unpack_from('<I', raw, 14)[0]
    x        = struct.unpack_from('<i', raw, 18)[0]
    y        = struct.unpack_from('<i', raw, 22)[0]
    state    = struct.unpack_from('<I', raw, 26)[0]
    field_30 = struct.unpack_from('<f', raw, 30)[0]
    field_34 = struct.unpack_from('<I', raw, 34)[0]

    # Also try f32 interpretation for all 4-byte aligned offsets
    state_name = {30: "idle", 81: "walk", 119: "run"}.get(state, str(state))

    ts = time.strftime("%H:%M:%S")
    print(f"  [{ts}] === COMBAT_UPDATE (38b) ===")
    print(f"    [ 0] opcode   : 0x{opcode:04x}")
    print(f"    [ 2] entity_id: {eid}  (0x{eid:08X})")
    print(f"    [ 6] unk_06   : {unk_06}  (0x{unk_06:04X})")
    print(f"    [ 8] unk_08   : {unk_08}  (0x{unk_08:04X})")
    print(f"    [10] tick     : {tick}")
    print(f"    [14] zone     : {zone}")
    print(f"    [18] x        : {x}")
    print(f"    [22] y        : {y}")
    print(f"    [26] state    : {state}  ({state_name})")
    print(f"    [30] field_30 : {field_30:.2f}  (f32) / {struct.unpack_from('<I', raw, 30)[0]}  (u32)")
    print(f"    [34] field_34 : {field_34}  (u32) / {struct.unpack_from('<f', raw, 34)[0]:.4f}  (f32)")
    print(f"    hex: {raw.hex(' ')}")
    print()


def scan_payload(
    payload: bytes,
    new_speed: float | None = None,
    new_stat: int | None = None,
    stat_indices: list[int] | None = None,
    target_eid: int | None = None,
    monitor: bool = False,
    debug: bool = False,
    dump: bool = False,
) -> tuple[bytes, int, int]:
    """Walk coalesced TCP payload, find packets, optionally modify values.

    Returns (possibly-modified payload, COMBAT_UPDATE count, stat_array count).
    """
    data = bytearray(payload)
    combat_found = 0
    stat_found = 0
    modified = False

    # --- Scan for 0x4300 stat arrays (byte scan, works even in fragmented payloads) ---
    if new_stat is not None or monitor or debug:
        STAT_OPCODE_BYTES = bytes([STAT_ARRAY_OPCODE >> 8, STAT_ARRAY_OPCODE & 0xFF])
        pos = 0
        while pos + STAT_ARRAY_SIZE <= len(data):
            pos = data.find(STAT_OPCODE_BYTES[0], pos, len(data) - STAT_ARRAY_SIZE + 1)
            if pos == -1:
                break
            if pos + 1 < len(data) and data[pos + 1] == STAT_OPCODE_BYTES[1]:
                # Validate: check size field
                pkt_size = struct.unpack_from('<H', data, pos + 2)[0]
                if pkt_size == STAT_ARRAY_SIZE:
                    stat_found += 1
                    ts = time.strftime("%H:%M:%S")

                    if monitor or debug:
                        vals = []
                        for i in range(STAT_ARRAY_COUNT):
                            v = struct.unpack_from('<I', data, pos + STAT_ARRAY_DATA_OFF + i * 4)[0]
                            vals.append(v)
                        print(f"  [{ts}] STAT_ARRAY 0x4300  vals={vals[:10]}...")

                    if new_stat is not None:
                        indices = stat_indices or list(range(STAT_ARRAY_COUNT))
                        for i in indices:
                            off = pos + STAT_ARRAY_DATA_OFF + i * 4
                            old_val = struct.unpack_from('<I', data, off)[0]
                            struct.pack_into('<I', data, off, new_stat)
                            print(f"  [{ts}] STAT[{i}]: {old_val} -> {new_stat}")
                        modified = True
            pos += 1

    # --- Scan for COMBAT_UPDATE ---
    offset = 0
    combat_offsets: set[int] = set()

    # Strategy 1: Sequential walk
    while offset + HEADER_SIZE <= len(data):
        pkt_size = get_packet_size(bytes(data[offset:]))
        if pkt_size is None:
            break
        if offset + pkt_size > len(data):
            break
        opcode = (data[offset] << 8) | data[offset + 1]
        if opcode == COMBAT_UPDATE_OPCODE and pkt_size == COMBAT_UPDATE_SIZE:
            combat_offsets.add(offset)
        offset += pkt_size

    # Strategy 2: Byte scan fallback
    OPCODE_BYTES = bytes([COMBAT_UPDATE_OPCODE >> 8, COMBAT_UPDATE_OPCODE & 0xFF])
    pos = offset
    while pos + COMBAT_UPDATE_SIZE <= len(data):
        pos = data.find(OPCODE_BYTES[0], pos, len(data) - COMBAT_UPDATE_SIZE + 1)
        if pos == -1:
            break
        if pos + 1 < len(data) and data[pos + 1] == OPCODE_BYTES[1]:
            speed_val = struct.unpack_from('<f', data, pos + SPEED_OFFSET)[0]
            if 10.0 < speed_val < 50000.0 and speed_val == speed_val:
                combat_offsets.add(pos)
        pos += 1

    # Process COMBAT_UPDATEs
    for off in sorted(combat_offsets):
        if off + COMBAT_UPDATE_SIZE > len(data):
            continue
        combat_found += 1

        if dump:
            dump_combat_update(data, off)
            continue

        speed_pos = off + SPEED_OFFSET
        eid_pos = off + ENTITY_ID_OFFSET
        old_speed = struct.unpack_from('<f', data, speed_pos)[0]
        eid = struct.unpack_from('<I', data, eid_pos)[0]

        if monitor or debug:
            ts = time.strftime("%H:%M:%S")
            print(f"  [{ts}] COMBAT_UPDATE  eid={eid:<8d}  speed={old_speed:>7.1f}")
        if not monitor and new_speed is not None:
            if target_eid is not None and eid != target_eid:
                continue
            struct.pack_into('<f', data, speed_pos, new_speed)
            modified = True
            ts = time.strftime("%H:%M:%S")
            print(f"  [{ts}] eid={eid:<8d}  speed: {old_speed:.1f} -> {new_speed:.1f}")

    return (bytes(data) if modified else payload, combat_found, stat_found)


def run_capture(output_path: str, server_ips: list[str] | None = None,
                ports: list[int] | None = None,
                direction: str = "s2c") -> None:
    """Capture packets and save raw payloads to JSON for offline analysis.

    Steps: 1) Start capture  2) Change weapon in-game  3) Ctrl+C  4) Analyze file
    """
    import json
    try:
        import pydivert
    except ImportError:
        print("[!] pydivert not installed.")
        sys.exit(1)

    filt = build_windivert_filter(server_ips, ports, direction=direction)

    dir_label = {"s2c": "Server→Client", "c2s": "Client→Server", "both": "Both Directions"}
    print("=" * 65)
    print(f"  GE_Phantom — Packet Capture [{dir_label.get(direction, direction)}]")
    print("=" * 65)
    print(f"  Output: {output_path}")
    print(f"  Filter: {filt}")
    print()
    print("  1) Let this run")
    print("  2) Perform actions in-game (attack, move, change stance)")
    print("  3) Press Ctrl+C to stop and save")
    print()

    packets = []
    opcode_counts: dict[str, int] = {}

    try:
        with pydivert.WinDivert(filt) as w:
            for packet in w:
                if packet.payload:
                    payload = bytes(packet.payload)
                    ts = time.time()

                    # Parse opcodes in this TCP segment
                    segment_opcodes = []
                    off = 0
                    while off + HEADER_SIZE <= len(payload):
                        opcode = (payload[off] << 8) | payload[off + 1]
                        pkt_size = get_packet_size(payload[off:])

                        pdef = KNOWN_PACKETS.get(opcode)
                        name = pdef.name if pdef else f"0x{opcode:04x}"

                        if pkt_size and off + pkt_size <= len(payload):
                            segment_opcodes.append({
                                "opcode": f"0x{opcode:04x}",
                                "name": name,
                                "offset": off,
                                "size": pkt_size,
                                "hex": payload[off:off + pkt_size].hex(),
                            })
                            opcode_counts[name] = opcode_counts.get(name, 0) + 1
                            off += pkt_size
                        else:
                            # Unknown/variable — save rest as raw
                            segment_opcodes.append({
                                "opcode": f"0x{opcode:04x}",
                                "name": name,
                                "offset": off,
                                "size": len(payload) - off,
                                "hex": payload[off:].hex(),
                                "note": "unknown_size",
                            })
                            opcode_counts[name] = opcode_counts.get(name, 0) + 1
                            break

                    packets.append({
                        "time": ts,
                        "time_str": time.strftime("%H:%M:%S", time.localtime(ts)),
                        "payload_size": len(payload),
                        "raw_hex": payload.hex(),
                        "parsed": segment_opcodes,
                    })

                    count = len(packets)
                    if count <= 5 or count % 50 == 0:
                        names = ", ".join(p["name"] for p in segment_opcodes[:3])
                        print(f"  #{count} [{time.strftime('%H:%M:%S')}] "
                              f"{len(payload)}b: {names}")

                w.send(packet)

    except KeyboardInterrupt:
        pass

    # Save
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "packet_count": len(packets),
        "opcode_summary": dict(sorted(opcode_counts.items(), key=lambda x: -x[1])),
        "packets": packets,
    }, indent=2))

    print(f"\n{'='*65}")
    print(f"  Saved {len(packets)} packets to {output_path}")
    print(f"  Opcode summary:")
    for name, cnt in sorted(opcode_counts.items(), key=lambda x: -x[1]):
        print(f"    {name:<30s} {cnt:>5d}")
    print(f"{'='*65}")
    print(f"\n  Next: analyze with")
    print(f"    python -c \"import json; d=json.load(open('{output_path}')); ...\"")


def run_sniff() -> None:
    """Broad sniff — catch ALL TCP from 103.55.55.* to find actual IPs/ports."""
    try:
        import pydivert
    except ImportError:
        print("[!] pydivert not installed.")
        sys.exit(1)

    # Very broad: any TCP with payload from/to 103.55.55.0/24
    filt = ("(ip.SrcAddr >= 103.55.55.0 and ip.SrcAddr <= 103.55.55.255)"
            " or "
            "(ip.DstAddr >= 103.55.55.0 and ip.DstAddr <= 103.55.55.255)")

    print("=" * 65)
    print("  GE_Phantom — Broad Sniff (finding actual server IPs/ports)")
    print("=" * 65)
    print(f"  Filter: {filt}")
    print(f"  Press Ctrl+C to stop.\n")

    seen: dict[str, int] = {}  # "ip:port" -> count

    try:
        with pydivert.WinDivert(filt) as w:
            for packet in w:
                src = f"{packet.src_addr}:{packet.src_port}"
                dst = f"{packet.dst_addr}:{packet.dst_port}"

                # Track server-side endpoints
                key = None
                direction = None
                if str(packet.src_addr).startswith("103.55.55."):
                    key = src
                    direction = "S2C"
                elif str(packet.dst_addr).startswith("103.55.55."):
                    key = dst
                    direction = "C2S"

                if key:
                    seen[key] = seen.get(key, 0) + 1
                    count = seen[key]
                    if count <= 3 or count % 50 == 0:
                        payload_len = len(packet.payload) if packet.payload else 0
                        ts = time.strftime("%H:%M:%S")
                        print(f"  [{ts}] {direction}  {src} -> {dst}  "
                              f"payload={payload_len}b  (#{count})")

                w.send(packet)  # always re-inject

    except KeyboardInterrupt:
        pass

    if seen:
        print(f"\n{'='*65}")
        print(f"  Server endpoints seen:")
        print(f"{'='*65}")
        for ep, count in sorted(seen.items(), key=lambda x: -x[1]):
            print(f"    {ep}  ({count} packets)")
    else:
        print("\n  [!] No traffic from 103.55.55.* seen at all!")
        print("  Check: Is the game connected? Is this the right subnet?")


def run_intercept(
    new_speed: float | None = None,
    new_stat: int | None = None,
    stat_indices: list[int] | None = None,
    target_eid: int | None = None,
    monitor: bool = False,
    debug: bool = False,
    dump: bool = False,
    server_ips: list[str] | None = None,
    ports: list[int] | None = None,
) -> None:
    """Main intercept loop. Captures packets, modifies, re-injects."""
    try:
        import pydivert
    except ImportError:
        print("[!] pydivert not installed.")
        print("    pip install pydivert")
        sys.exit(1)

    filt = build_windivert_filter(server_ips, ports)

    modes = []
    if dump:
        modes.append("DUMP")
    if debug:
        modes.append("DEBUG")
    if monitor:
        modes.append("MONITOR")
    if new_speed is not None:
        modes.append(f"SPEED -> {new_speed}")
    if new_stat is not None:
        idx_str = f"[{','.join(map(str, stat_indices))}]" if stat_indices else "[ALL]"
        modes.append(f"STAT {idx_str} -> {new_stat}")
    mode_str = " + ".join(modes) if modes else "PASSTHROUGH"

    print("=" * 65)
    print(f"  GE_Phantom — Packet Interceptor (WinDivert)")
    print(f"  Mode: {mode_str}")
    print("=" * 65)
    print(f"  Filter: {filt}")
    if new_stat is not None:
        print(f"  NOTE: 0x4300 stat packets are sent at LOGIN.")
        print(f"        Start this BEFORE logging into the game!")
    print(f"  Press Ctrl+C to stop.\n")

    total_packets = 0
    total_combat = 0
    total_stat = 0
    total_modified = 0

    try:
        with pydivert.WinDivert(filt) as w:
            for packet in w:
                total_packets += 1

                if packet.payload:
                    new_payload, combat_count, stat_count = scan_payload(
                        packet.payload,
                        new_speed=new_speed,
                        new_stat=new_stat,
                        stat_indices=stat_indices,
                        target_eid=target_eid,
                        monitor=monitor,
                        debug=debug,
                        dump=dump,
                    )
                    total_combat += combat_count
                    total_stat += stat_count

                    if new_payload is not packet.payload:
                        packet.payload = new_payload
                        total_modified += combat_count + stat_count

                # Always re-inject
                w.send(packet)

                if total_packets % 500 == 0:
                    print(f"  ... {total_packets} pkts, "
                          f"{total_combat} combat, {total_stat} stat, "
                          f"{total_modified} modified ...")

    except KeyboardInterrupt:
        pass

    print(f"\n{'='*65}")
    print(f"  Summary:")
    print(f"    Total packets:  {total_packets}")
    print(f"    COMBAT_UPDATE:  {total_combat}")
    print(f"    STAT_ARRAY:     {total_stat}")
    print(f"    Modified:       {total_modified}")
    print(f"{'='*65}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GE_Phantom — Packet Interceptor (WinDivert)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s --monitor                          Show all intercepted packets
  %(prog)s --speed 5000                       Modify movement speed (COMBAT_UPDATE)
  %(prog)s --stat 5000                        Modify ALL stat values in 0x4300 (login)
  %(prog)s --stat 5000 --stat-idx 0 1 2       Modify only indices 0,1,2 in 0x4300
  %(prog)s --stat 5000 --stat-idx 1           Modify only index 1 (value=539)
  %(prog)s --capture data/out.json            Capture packets to file
  %(prog)s --sniff                            Find server IPs/ports

NOTE: --stat modifies 0x4300 packets sent during LOGIN.
      Start the interceptor BEFORE logging into the game!
""",
    )
    parser.add_argument("--speed", type=float, dest="new_speed",
                        help="New movement speed (COMBAT_UPDATE field_30)")
    parser.add_argument("--range", type=float, dest="new_range_compat",
                        help="Alias for --speed (backward compat)")
    parser.add_argument("--stat", type=int, dest="new_stat",
                        help="New u32 value for 0x4300 stat array (sent at login)")
    parser.add_argument("--stat-idx", nargs="+", type=int, dest="stat_indices",
                        help="Which indices in 0x4300 to modify (default: ALL 30)")
    parser.add_argument("--eid", type=int, dest="target_eid",
                        help="Only modify this entity ID")
    parser.add_argument("--monitor", action="store_true",
                        help="Monitor mode — show packets without modifying")
    parser.add_argument("--debug", action="store_true",
                        help="Debug mode — verbose output")
    parser.add_argument("--dump", action="store_true",
                        help="Dump all COMBAT_UPDATE fields")
    parser.add_argument("--capture", metavar="FILE",
                        help="Capture all packets to JSON file")
    parser.add_argument("--sniff", action="store_true",
                        help="Broad sniff — find actual server IPs/ports")
    parser.add_argument("--ips", nargs="+",
                        help="Override server IPs")
    parser.add_argument("--ports", nargs="+", type=int,
                        help="Override server ports")
    parser.add_argument("--c2s", action="store_true",
                        help="Capture Client→Server packets (default: Server→Client)")
    parser.add_argument("--both", action="store_true",
                        help="Capture both directions")
    args = parser.parse_args()

    # Determine direction
    if args.both:
        direction = "both"
    elif args.c2s:
        direction = "c2s"
    else:
        direction = "s2c"

    # Backward compat: --range maps to --speed
    new_speed = args.new_speed or args.new_range_compat

    has_action = (args.monitor or args.debug or args.dump or args.sniff
                  or args.capture or new_speed is not None or args.new_stat is not None)
    if not has_action:
        parser.error("Specify --speed, --stat, --monitor, --debug, --dump, --capture, or --sniff")

    # Check admin
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[!] Not running as Administrator!")
            print("[!] WinDivert requires admin privileges.")
            print("[!] Right-click terminal -> Run as Administrator")
            sys.exit(1)
    except AttributeError:
        pass

    if args.sniff:
        run_sniff()
        return

    if args.capture:
        run_capture(args.capture, server_ips=args.ips, ports=args.ports,
                    direction=direction)
        return

    run_intercept(
        new_speed=new_speed,
        new_stat=args.new_stat,
        stat_indices=args.stat_indices,
        target_eid=args.target_eid,
        monitor=args.monitor,
        debug=args.debug,
        dump=args.dump,
        server_ips=args.ips,
        ports=args.ports,
    )


if __name__ == "__main__":
    main()
