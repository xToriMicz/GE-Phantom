"""
GE_Phantom Live Monitor — capture with interactive markers.

Run while playing GE. Press keys to place markers:
  [Enter]  = place marker (then type label)
  [q]      = quit and save

Usage:
  python tools/monitor.py
  python tools/monitor.py --name "pick_item_test" --iface "Ethernet"
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.sniffer.capture import GESniffer, GEPacket, _print_packet
from src.sniffer.session import CaptureSession


def run_monitor(
    name: str = "",
    iface: str | None = None,
    verbose: bool = False,
    save_dir: str = "captures",
):
    sniffer = GESniffer(iface=iface)
    session = CaptureSession(sniffer, name=name)

    packet_count = 0

    def on_packet(pkt: GEPacket) -> None:
        nonlocal packet_count
        packet_count += 1
        ts = time.strftime("%H:%M:%S", time.localtime(pkt.timestamp))
        ms = int((pkt.timestamp % 1) * 1000)

        if verbose:
            _print_packet(pkt)
        else:
            # Compact view
            print(f"  [{ts}.{ms:03d}] {pkt.direction} {pkt.size:>5}b  first4=0x{pkt.payload[:4].hex() if pkt.size >= 4 else pkt.hex_dump}")

    sniffer.on_packet(on_packet)

    # Capture thread
    def capture_thread():
        session.start()

    t = threading.Thread(target=capture_thread, daemon=True)
    t.start()

    print("=" * 60)
    print("  GE_Phantom Live Monitor")
    print("=" * 60)
    print()
    print("  Commands:")
    print("    [Enter] = place a marker (describe what just happened)")
    print("    q       = quit and save")
    print("    s       = show stats")
    print("    v       = toggle verbose mode")
    print()
    print("  Tip: Place a marker RIGHT AFTER doing an action in-game")
    print("       e.g., right after picking up an item, type: picked item")
    print()

    try:
        while True:
            user_input = input().strip()

            if user_input.lower() == "q":
                break
            elif user_input.lower() == "s":
                print(f"\n  --- Stats: {len(session.packets)} packets, {len(session.markers)} markers ---\n")
            elif user_input.lower() == "v":
                verbose = not verbose
                print(f"\n  --- Verbose: {'ON' if verbose else 'OFF'} ---\n")
            elif user_input:
                session.mark(user_input)
            else:
                label = input("  marker label> ").strip()
                if label:
                    session.mark(label)

    except (KeyboardInterrupt, EOFError):
        pass

    print(f"\n[*] Stopping capture...")
    print(f"[*] Total: {len(session.packets)} packets, {len(session.markers)} markers")

    if session.packets:
        path = session.save(save_dir)
        print(f"[*] Saved to: {path}")
        print()
        print(session.summary())
    else:
        print("[!] No packets captured. Is the game running? Is Npcap installed?")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="GE_Phantom Live Monitor")
    parser.add_argument("--name", default="", help="Session name (default: timestamp)")
    parser.add_argument("--iface", help="Network interface")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full hex dumps")
    parser.add_argument("--save-dir", default="captures", help="Directory for saved sessions")
    args = parser.parse_args()

    run_monitor(
        name=args.name,
        iface=args.iface,
        verbose=args.verbose,
        save_dir=args.save_dir,
    )
