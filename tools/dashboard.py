"""
GE_Phantom — Dashboard CLI

Real-time TUI dashboard for packet monitoring.

Usage:
  python tools/dashboard.py                                               # Live capture
  python tools/dashboard.py --iface "Ethernet"                            # Specific interface
  python tools/dashboard.py --my-chars Kaja,Scoutz                        # Filter my drops
  python tools/dashboard.py --replay captures/session4_combat_full.json   # Replay mode
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.dashboard.app import GEDashboard


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="GE_Phantom Dashboard")
    parser.add_argument("--iface", help="Network interface to sniff on")
    parser.add_argument(
        "--my-chars",
        help="Comma-separated list of your character names (for drop highlighting)",
    )
    parser.add_argument(
        "--replay",
        help="Replay a saved session JSON file instead of live capture",
    )
    args = parser.parse_args()

    my_chars = [c.strip() for c in args.my_chars.split(",")] if args.my_chars else None

    app = GEDashboard(
        iface=args.iface,
        my_chars=my_chars,
        replay_path=args.replay,
    )
    app.run()


if __name__ == "__main__":
    main()
