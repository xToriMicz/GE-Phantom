"""
GE_Phantom Packet Analyzer — analyze captured sessions.

Usage:
  python tools/analyze.py captures/session.json
  python tools/analyze.py captures/session.json --marker 0
  python tools/analyze.py captures/session.json --diff 0 1
  python tools/analyze.py captures/session.json --direction S2C
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.sniffer.session import CaptureSession
from src.protocol.analyzer import PacketAnalyzer


def cmd_report(session: CaptureSession, direction: str | None = None):
    """Full analysis report."""
    analyzer = PacketAnalyzer(session.packets)
    print(analyzer.report(direction))


def cmd_markers(session: CaptureSession):
    """List all markers with packet counts."""
    print(session.summary())


def cmd_marker_detail(session: CaptureSession, marker_idx: int, context: int = 10):
    """Show packets around a specific marker."""
    if marker_idx >= len(session.markers):
        print(f"[!] Marker {marker_idx} not found (have {len(session.markers)})")
        return

    marker = session.markers[marker_idx]
    packets = session.packets_near_marker(marker_idx, before=context, after=context)

    print(f"=== Marker [{marker_idx}]: {marker.label} ===")
    print(f"    Packet index: {marker.packet_index}")
    print(f"    Showing {context} packets before and after\n")

    for p in packets:
        idx = session.packets.index(p)
        flag = " <<<" if idx == marker.packet_index else ""
        print(f"  [{idx:>4}] {p.direction} {p.size:>5}b  0x{p.payload[:8].hex() if p.size >= 8 else p.hex_dump}{flag}")
        if abs(idx - marker.packet_index) <= 3:
            print(p.pretty_hex)
            print()


def cmd_diff_packets(session: CaptureSession, idx_a: int, idx_b: int):
    """Diff two packets by index."""
    if idx_a >= len(session.packets) or idx_b >= len(session.packets):
        print(f"[!] Invalid packet index (have {len(session.packets)})")
        return

    pkt_a = session.packets[idx_a]
    pkt_b = session.packets[idx_b]
    analyzer = PacketAnalyzer(session.packets)
    diffs = analyzer.diff_packets(pkt_a, pkt_b)

    print(f"=== Diff: packet [{idx_a}] vs [{idx_b}] ===")
    print(f"  A: {pkt_a}")
    print(f"  B: {pkt_b}")
    print()

    if not diffs:
        print("  Identical payloads!")
        return

    for offset, val_a, val_b in diffs:
        if offset == -1:
            print(f"  SIZE: {val_a} vs {val_b} bytes")
        else:
            print(f"  [{offset:04x}] 0x{val_a:02x} → 0x{val_b:02x}  (dec: {val_a} → {val_b})")


def cmd_filter_size(session: CaptureSession, size: int, direction: str | None = None):
    """Show all packets of a specific size."""
    packets = session.packets
    if direction:
        packets = [p for p in packets if p.direction == direction]
    matches = [p for p in packets if p.size == size]

    print(f"=== Packets of size {size} ({direction or 'all'}) — {len(matches)} found ===\n")
    for p in matches[:50]:
        idx = session.packets.index(p)
        print(f"  [{idx:>4}] {p.direction} 0x{p.payload[:8].hex() if p.size >= 8 else p.hex_dump}")

    if len(matches) > 1:
        print()
        analyzer = PacketAnalyzer(matches)
        constants = analyzer.find_constant_bytes(matches)
        varying = analyzer.find_varying_bytes(matches)

        if constants:
            print(f"  Constant bytes ({len(constants)}):")
            for offset, val in constants[:20]:
                print(f"    [{offset:04x}] = 0x{val:02x} (always)")

        if varying:
            print(f"  Varying bytes ({len(varying)}):")
            for offset, unique_count in varying[:20]:
                print(f"    [{offset:04x}] = {unique_count} unique values")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="GE_Phantom Packet Analyzer")
    parser.add_argument("session", help="Path to session JSON file")
    parser.add_argument("--direction", "-d", choices=["C2S", "S2C"], help="Filter by direction")
    parser.add_argument("--marker", "-m", type=int, help="Show packets around marker index")
    parser.add_argument("--diff", nargs=2, type=int, metavar=("A", "B"), help="Diff two packet indices")
    parser.add_argument("--size", "-s", type=int, help="Filter packets by size")
    parser.add_argument("--context", "-c", type=int, default=10, help="Context lines for marker view")
    args = parser.parse_args()

    session = CaptureSession.load(args.session)
    print(f"[*] Loaded: {len(session.packets)} packets, {len(session.markers)} markers\n")

    if args.marker is not None:
        cmd_marker_detail(session, args.marker, args.context)
    elif args.diff:
        cmd_diff_packets(session, args.diff[0], args.diff[1])
    elif args.size:
        cmd_filter_size(session, args.size, args.direction)
    else:
        cmd_report(session, args.direction)
        if session.markers:
            print()
            cmd_markers(session)
