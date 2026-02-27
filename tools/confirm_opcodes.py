#!/usr/bin/env python3
"""
Cross-capture opcode confirmation tool.

Replays ALL capture files through the reassembler and checks which
unconfirmed opcodes appear across multiple captures. Opcodes found in
2+ captures with consistent sizes are candidates for auto-confirmation.

Usage:
    python tools/confirm_opcodes.py [--apply]

    --apply   Actually set confirmed=True in packet_types.py for qualifying opcodes
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.protocol.packet_types import KNOWN_PACKETS, get_packet_size, HEADER_SIZE
from src.sniffer.capture import GEPacket
from src.sniffer.stream import TCPStreamReassembler

CAPTURES_DIR = Path(__file__).parent.parent / "captures"


def replay_capture(capture_path: Path) -> dict[int, list[int]]:
    """Replay a capture and return {opcode: [sizes seen]}."""
    data = json.loads(capture_path.read_text())
    raw_packets = data.get("packets", data) if isinstance(data, dict) else data
    if not raw_packets:
        return {}

    reassembler = TCPStreamReassembler()
    reassembler.set_framing("opcode_registry")

    opcode_sizes: dict[int, list[int]] = defaultdict(list)

    def on_packet(direction: str, pkt_data: bytes):
        if len(pkt_data) < 2:
            return
        opcode = int.from_bytes(pkt_data[:2], "big")
        if opcode in KNOWN_PACKETS:
            opcode_sizes[opcode].append(len(pkt_data))

    reassembler.on_game_packet(on_packet)

    for pkt_data in raw_packets:
        payload_hex = pkt_data.get("payload_hex", "")
        if not payload_hex:
            continue
        payload = bytes.fromhex(payload_hex)

        src_parts = pkt_data.get("src", "0.0.0.0:0").rsplit(":", 1)
        dst_parts = pkt_data.get("dst", "0.0.0.0:0").rsplit(":", 1)

        pkt = GEPacket(
            timestamp=pkt_data.get("timestamp", 0.0),
            direction=pkt_data.get("direction", "S2C"),
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

    return dict(opcode_sizes)


def main():
    apply_mode = "--apply" in sys.argv

    # Find unconfirmed opcodes
    unconfirmed = {
        opc: pdef for opc, pdef in KNOWN_PACKETS.items()
        if not pdef.confirmed
    }
    print(f"UNCONFIRMED OPCODES: {len(unconfirmed)}")
    for opc, pdef in sorted(unconfirmed.items()):
        size_str = f"{pdef.size}b" if pdef.size else "variable"
        print(f"  0x{opc:04x} {pdef.name:<25s} {size_str}")

    # Replay all captures
    captures = sorted(CAPTURES_DIR.glob("*.json"))
    print(f"\nREPLAYING {len(captures)} CAPTURES...")

    # {opcode: {capture_name: [sizes]}}
    cross_capture: dict[int, dict[str, list[int]]] = defaultdict(dict)

    for cap in captures:
        print(f"  {cap.name}...", end=" ", flush=True)
        result = replay_capture(cap)
        n_opcodes = len(result)
        n_packets = sum(len(v) for v in result.values())
        print(f"{n_packets} game packets, {n_opcodes} unique opcodes")

        for opc, sizes in result.items():
            if opc in unconfirmed:
                cross_capture[opc][cap.name] = sizes

    # Analyze results
    print(f"\n{'='*70}")
    print(f"CROSS-CAPTURE ANALYSIS FOR UNCONFIRMED OPCODES")
    print(f"{'='*70}")

    can_confirm = []
    needs_more = []

    for opc in sorted(unconfirmed.keys()):
        pdef = unconfirmed[opc]
        appearances = cross_capture.get(opc, {})
        n_captures = len(appearances)
        total_instances = sum(len(v) for v in appearances.items() if isinstance(v, list))
        total_instances = sum(len(sizes) for sizes in appearances.values())

        all_sizes = []
        for sizes in appearances.values():
            all_sizes.extend(sizes)

        unique_sizes = sorted(set(all_sizes)) if all_sizes else []
        size_consistent = len(unique_sizes) == 1 if pdef.size is not None else True

        print(f"\n  0x{opc:04x} {pdef.name}")
        print(f"    Registered size: {pdef.size or 'variable'}")
        print(f"    Captures: {n_captures}/{len(captures)}")
        print(f"    Total instances: {total_instances}")
        if all_sizes:
            print(f"    Sizes seen: {unique_sizes}")
        for cap_name, sizes in sorted(appearances.items()):
            print(f"      {cap_name}: {len(sizes)}x  sizes={sorted(set(sizes))}")

        # Confirmation criteria:
        # - Appears in 2+ captures, OR
        # - Appears 3+ times in a single capture with consistent size
        if n_captures >= 2:
            if pdef.size is not None and not size_consistent:
                print(f"    >> SIZE MISMATCH — needs investigation")
                needs_more.append(opc)
            else:
                print(f"    >> CAN CONFIRM (multi-capture)")
                can_confirm.append(opc)
        elif total_instances >= 3:
            if size_consistent:
                print(f"    >> CAN CONFIRM (3+ instances, consistent)")
                can_confirm.append(opc)
            else:
                print(f"    >> VARIABLE — confirm framing")
                needs_more.append(opc)
        elif total_instances >= 1:
            print(f"    >> SINGLE INSTANCE — needs more captures")
            needs_more.append(opc)
        else:
            print(f"    >> NOT SEEN — may be session-specific")
            needs_more.append(opc)

    # Summary
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  Can confirm: {len(can_confirm)}")
    for opc in can_confirm:
        print(f"    0x{opc:04x} {KNOWN_PACKETS[opc].name}")
    print(f"  Needs more data: {len(needs_more)}")
    for opc in needs_more:
        print(f"    0x{opc:04x} {KNOWN_PACKETS[opc].name}")

    confirmed_before = sum(1 for p in KNOWN_PACKETS.values() if p.confirmed)
    print(f"\n  Confirmed before: {confirmed_before}/{len(KNOWN_PACKETS)}")
    print(f"  Confirmed after:  {confirmed_before + len(can_confirm)}/{len(KNOWN_PACKETS)}")

    if apply_mode and can_confirm:
        print(f"\n  --apply: Updating packet_types.py...")
        apply_confirmations(can_confirm)
        print(f"  Done. {len(can_confirm)} opcodes confirmed.")
    elif can_confirm:
        print(f"\n  Run with --apply to auto-confirm these opcodes.")


def apply_confirmations(opcodes: list[int]) -> None:
    """Update packet_types.py to set confirmed=True for given opcodes."""
    pt_path = Path(__file__).parent.parent / "src" / "protocol" / "packet_types.py"
    content = pt_path.read_text(encoding="utf-8")

    for opc in opcodes:
        pdef = KNOWN_PACKETS[opc]
        # Find the pattern "confirmed=False" within the opcode's definition block
        # Look for the opcode hex in the file and replace confirmed=False nearby
        opc_hex = f"0x{opc:04x}"
        # Find position of opcode in file
        idx = content.find(f"opcode={opc_hex}")
        if idx < 0:
            opc_hex_upper = f"0x{opc:04X}"
            idx = content.find(f"opcode={opc_hex_upper}")
        if idx < 0:
            print(f"    WARNING: Could not find opcode={opc_hex} in file")
            continue

        # Find the confirmed=False within the next 500 chars (within the same PacketDef)
        block_end = content.find("),", idx)
        if block_end < 0:
            block_end = idx + 500
        block = content[idx:block_end]
        old = "confirmed=False"
        new = "confirmed=True"
        if old in block:
            # Replace only within this block
            new_block = block.replace(old, new, 1)
            content = content[:idx] + new_block + content[block_end:]
            print(f"    Confirmed 0x{opc:04x} {pdef.name}")
        else:
            print(f"    0x{opc:04x} already confirmed or not found")

    pt_path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
