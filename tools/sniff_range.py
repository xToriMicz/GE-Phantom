"""
Quick sniffer — show attack_range from COMBAT_UPDATE packets.

Uses the existing GESniffer + ClientRouter with TCP reassembly.

Run in Admin terminal:
    python tools/sniff_range.py

Hit a monster or move around to trigger COMBAT_UPDATE packets.
Press Ctrl+C to stop.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.sniffer.capture import GESniffer, GEPacket
from src.data.router import ClientRouter

seen_entities: dict[int, float] = {}
packet_count = 0
combat_count = 0


def on_packet(pkt: GEPacket) -> None:
    global packet_count, combat_count
    packet_count += 1

    key, decoded = router.process_packet(pkt)

    if decoded is None:
        return

    name = decoded.get("name", "")

    # Show COMBAT_UPDATE with attack_range
    if name == "COMBAT_UPDATE":
        combat_count += 1
        eid = decoded.get("entity_id", 0)
        attack_range = decoded.get("attack_range")
        x = decoded.get("x")
        y = decoded.get("y")
        state = decoded.get("state")
        zone = decoded.get("zone")

        if attack_range is None:
            return

        ts = time.strftime("%H:%M:%S")
        is_new = eid not in seen_entities
        prev = seen_entities.get(eid)
        seen_entities[eid] = attack_range

        state_name = {30: "idle", 81: "walk", 119: "run"}.get(state, str(state)) if state else "?"

        marker = " [NEW]" if is_new else ""
        delta = ""
        if prev is not None and abs(prev - attack_range) > 0.1:
            delta = f" (was {prev:.0f})"

        pos = f"({x},{y})" if x is not None and y is not None else ""
        print(f"[{ts}] eid={eid:<8d} range={attack_range:>7.1f}{delta}  "
              f"pos={pos:<20s} state={state_name:<5s} zone={zone}{marker}")

    # Also show any other packet type (just count, for debugging)
    elif packet_count % 50 == 0:
        print(f"  ... {packet_count} packets processed, {combat_count} COMBAT_UPDATE so far ...")


# Global router
router = ClientRouter(reassemble=True)


def main():
    print("=" * 65)
    print("  GE_Phantom — Attack Range Sniffer (with TCP reassembly)")
    print("=" * 65)
    print("  Listening for COMBAT_UPDATE packets...")
    print("  Move around or attack to trigger updates.")
    print("  Press Ctrl+C to stop.\n")

    sniffer = GESniffer()
    sniffer.on_packet(on_packet)

    try:
        sniffer.start()
    except KeyboardInterrupt:
        pass

    if seen_entities:
        print(f"\n{'='*65}")
        print(f"  Summary: {len(seen_entities)} entities, {combat_count} COMBAT_UPDATEs")
        print(f"{'='*65}")

        by_range: dict[float, list[int]] = {}
        for eid, rng in seen_entities.items():
            by_range.setdefault(rng, []).append(eid)

        for rng in sorted(by_range.keys()):
            eids = by_range[rng]
            print(f"  range={rng:>7.1f}: {len(eids)} entities  {eids[:5]}")

        print(f"\n  Use these values for diff-scan:")
        print(f"    python tools/diagnose_range.py diff-scan")
    else:
        print(f"\n  No COMBAT_UPDATE packets seen. ({packet_count} total packets captured)")
        if packet_count == 0:
            print("  Check: Is Npcap installed? Is the game connected?")
        else:
            print("  Try: attack a monster or move closer to one.")


if __name__ == "__main__":
    main()
