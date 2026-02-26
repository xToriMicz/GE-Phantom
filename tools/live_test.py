"""
GE_Phantom Quick Live Test — capture, reassemble, decode, report.

Captures live GE traffic for N seconds, runs through the full pipeline:
  TCP capture → stream reassembly → opcode decode → stats summary

Usage (requires Admin):
  python tools/live_test.py
  python tools/live_test.py --duration 60 --iface "Ethernet"
  python tools/live_test.py --save captures/live_test.json
"""

from __future__ import annotations

import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.sniffer.capture import GESniffer, GEPacket
from src.sniffer.stream import TCPStreamReassembler
from src.protocol.packet_types import KNOWN_PACKETS, decode_packet


def run_live_test(
    duration: int = 30,
    iface: str | None = None,
    save_path: str | None = None,
    verbose: bool = False,
):
    print("=" * 60)
    print("  GE_Phantom — Quick Live Test")
    print("=" * 60)
    print(f"  Duration: {duration}s")
    print(f"  Interface: {iface or 'auto'}")
    print()

    sniffer = GESniffer(iface=iface)
    reassembler = TCPStreamReassembler()
    reassembler.set_framing("opcode_registry")

    # Counters
    tcp_count = Counter()  # direction → count
    tcp_bytes = Counter()  # direction → total bytes
    game_packets: list[tuple[str, bytes]] = []
    opcode_count = Counter()  # (direction, opcode_hex, name) → count
    unknown_count = 0
    decode_errors = 0
    reassembly_issues: list[str] = []

    start_time = time.time()

    def on_game_packet(direction: str, data: bytes) -> None:
        nonlocal unknown_count, decode_errors
        game_packets.append((direction, data))

        if len(data) < 2:
            unknown_count += 1
            return

        opcode = int.from_bytes(data[:2], "big")
        pdef = KNOWN_PACKETS.get(opcode)

        if pdef:
            key = (direction, f"0x{opcode:04x}", pdef.name)
            opcode_count[key] += 1

            # Verify size matches expectation
            if pdef.size is not None and len(data) != pdef.size:
                issue = f"SIZE MISMATCH: {pdef.name} (0x{opcode:04x}) expected {pdef.size}b, got {len(data)}b"
                reassembly_issues.append(issue)
                if verbose:
                    print(f"  [!] {issue}")

            if verbose:
                decoded = decode_packet(data)
                elapsed = time.time() - start_time
                if decoded:
                    fields = {k: v for k, v in decoded.items()
                              if k not in ("opcode", "opcode_hex", "name", "direction", "size")}
                    field_str = " ".join(f"{k}={v}" for k, v in fields.items())
                    print(f"  [{elapsed:6.1f}s] {direction} {decoded['name']:20s} {len(data):>4}b  {field_str}")
                else:
                    print(f"  [{elapsed:6.1f}s] {direction} {pdef.name:20s} {len(data):>4}b")
        else:
            unknown_count += 1
            if verbose:
                elapsed = time.time() - start_time
                print(f"  [{elapsed:6.1f}s] {direction} UNKNOWN(0x{opcode:04x})    {len(data):>4}b")

    reassembler.on_game_packet(on_game_packet)

    def on_tcp_packet(pkt: GEPacket) -> None:
        tcp_count[pkt.direction] += 1
        tcp_bytes[pkt.direction] += pkt.size
        reassembler.feed(pkt)

        # Progress indicator every 50 packets
        total = sum(tcp_count.values())
        if total % 50 == 0 and not verbose:
            elapsed = time.time() - start_time
            game_total = len(game_packets)
            print(f"  [{elapsed:5.1f}s] {total} TCP segments → {game_total} game packets", end="\r")

    sniffer.on_packet(on_tcp_packet)

    print(f"[*] Capturing for {duration}s... (Ctrl+C to stop early)\n")

    try:
        sniffer.start(timeout=duration)
    except KeyboardInterrupt:
        print("\n[*] Stopped early by user")

    elapsed = time.time() - start_time

    # ---- Results ----
    print("\n")
    print("=" * 60)
    print("  RESULTS")
    print("=" * 60)

    total_tcp = sum(tcp_count.values())
    total_game = len(game_packets)

    if total_tcp == 0:
        print("\n  [!] No packets captured!")
        print("  Check:")
        print("    - Is the game running and connected?")
        print("    - Is this terminal running as Administrator?")
        print("    - Server IP: 103.55.55.138, Ports: 7000/7001/7008")
        return

    print(f"\n  Duration: {elapsed:.1f}s")
    print(f"\n  --- TCP Layer ---")
    print(f"  Total TCP segments:  {total_tcp}")
    for d in ["S2C", "C2S"]:
        print(f"    {d}: {tcp_count[d]:>6} segments  ({tcp_bytes[d]:>10,} bytes)")

    print(f"\n  --- Game Layer (after reassembly) ---")
    print(f"  Total game packets:  {total_game}")
    print(f"  Unknown opcodes:     {unknown_count}")

    reassem_stats = reassembler.stats()
    for d in ["S2C", "C2S"]:
        buffered = reassem_stats[d]["buffered"]
        if buffered > 0:
            print(f"  [!] {d} leftover buffer: {buffered} bytes (partial packet at end)")

    if opcode_count:
        print(f"\n  --- Packet Breakdown ---")
        print(f"  {'Dir':>4}  {'Opcode':<8}  {'Name':<24}  {'Count':>6}")
        print(f"  {'─'*4}  {'─'*8}  {'─'*24}  {'─'*6}")
        for (direction, opcode_hex, name), count in sorted(
            opcode_count.items(), key=lambda x: -x[1]
        ):
            print(f"  {direction:>4}  {opcode_hex:<8}  {name:<24}  {count:>6}")

    if reassembly_issues:
        print(f"\n  --- Reassembly Issues ({len(reassembly_issues)}) ---")
        for issue in reassembly_issues[:20]:
            print(f"  [!] {issue}")
        if len(reassembly_issues) > 20:
            print(f"  ... and {len(reassembly_issues) - 20} more")
    else:
        print(f"\n  [OK] No reassembly issues detected!")

    # Save if requested
    if save_path:
        save_data = {
            "duration": elapsed,
            "tcp_segments": total_tcp,
            "game_packets": total_game,
            "unknown_opcodes": unknown_count,
            "reassembly_issues": len(reassembly_issues),
            "breakdown": {
                f"{d}:{opcode}:{name}": count
                for (d, opcode, name), count in opcode_count.items()
            },
            "packets": [
                {
                    "direction": d,
                    "size": len(data),
                    "opcode_hex": f"0x{int.from_bytes(data[:2], 'big'):04x}" if len(data) >= 2 else "??",
                    "payload_hex": data.hex(),
                }
                for d, data in game_packets
            ],
        }
        import json
        out = Path(save_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(save_data, indent=2))
        print(f"\n  [*] Saved {total_game} game packets to {out}")

    print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="GE_Phantom Quick Live Test")
    parser.add_argument("--duration", "-d", type=int, default=30, help="Capture duration in seconds (default: 30)")
    parser.add_argument("--iface", help="Network interface (default: auto)")
    parser.add_argument("--save", "-s", help="Save decoded packets to JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show each packet as it arrives")
    args = parser.parse_args()

    run_live_test(
        duration=args.duration,
        iface=args.iface,
        save_path=args.save,
        verbose=args.verbose,
    )
