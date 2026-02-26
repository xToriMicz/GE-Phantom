"""
GE_Phantom — Item Radar

Real-time monitor that sniffs game traffic and alerts on item drops.
Tracks entities, combat, and item events in a live console view.

Requires: Npcap installed, run as Administrator for best results.

Usage:
  python tools/item_radar.py
  python tools/item_radar.py --iface "Ethernet"
  python tools/item_radar.py --my-chars KajaDesigner,Karjalainen22,Scoutz
"""

from __future__ import annotations

import sys
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.sniffer.capture import GESniffer, GEPacket
from src.protocol.packet_types import decode_packet, KNOWN_PACKETS


# ---- State tracking ----

@dataclass
class Entity:
    """Tracked entity in the game world."""
    entity_id: int
    x: int = 0
    y: int = 0
    last_seen: float = 0.0
    entity_type: str = "unknown"  # "monster", "player", "item", "npc"
    name: str = ""


@dataclass
class ItemDrop:
    """A detected item drop."""
    timestamp: float
    entity_id: int
    item_id: int
    count: int
    x: int
    y: int
    owner_name: str
    owner_eid: int
    picked_up: bool = False


class RadarState:
    """Tracks all game state from decoded packets."""

    def __init__(self, my_chars: list[str] | None = None):
        self.my_chars = set(c.lower() for c in (my_chars or []))
        self.entities: dict[int, Entity] = {}
        self.item_drops: list[ItemDrop] = []
        self.active_drops: dict[int, ItemDrop] = {}  # entity_id → drop
        self.combat_targets: dict[int, int] = {}  # attacker → target
        self.packet_counts: defaultdict[str, int] = defaultdict(int)
        self.total_packets: int = 0
        self.start_time: float = time.time()
        self._lock = threading.Lock()

    def is_mine(self, owner_name: str) -> bool:
        """Check if an item belongs to one of our characters."""
        if not self.my_chars:
            return True  # No filter = show everything
        return owner_name.lower() in self.my_chars

    def process_packet(self, pkt: GEPacket) -> dict | None:
        """Process a captured packet and update state. Returns decoded dict or None."""
        self.total_packets += 1

        if not pkt.payload or len(pkt.payload) < 2:
            return None

        decoded = decode_packet(pkt.payload)
        if not decoded:
            return None

        name = decoded["name"]
        self.packet_counts[name] += 1

        with self._lock:
            match name:
                case "ENTITY_POSITION":
                    self._handle_position(decoded, pkt.timestamp)
                case "ITEM_DROP":
                    self._handle_item_drop(decoded, pkt.timestamp)
                case "ENTITY_DESPAWN":
                    self._handle_despawn(decoded)
                case "TARGET_LINK":
                    self._handle_target(decoded)
                case "MONSTER_SPAWN" | "NPC_SPAWN" | "OBJECT_SPAWN":
                    self._handle_spawn(decoded, name, pkt.timestamp)
                case "COMBAT_UPDATE":
                    pass  # Tracked but no special handling yet

        return decoded

    def _handle_position(self, d: dict, ts: float) -> None:
        eid = d.get("entity_id", 0)
        if not eid:
            return
        ent = self.entities.get(eid)
        if not ent:
            ent = Entity(entity_id=eid, entity_type="unknown")
            self.entities[eid] = ent
        ent.x = d.get("x", ent.x)
        ent.y = d.get("y", ent.y)
        ent.last_seen = ts

    def _handle_item_drop(self, d: dict, ts: float) -> None:
        drop = ItemDrop(
            timestamp=ts,
            entity_id=d.get("entity_id", 0),
            item_id=d.get("item_id", 0),
            count=d.get("count", 1),
            x=d.get("x", 0),
            y=d.get("y", 0),
            owner_name=d.get("owner_name", ""),
            owner_eid=d.get("owner_eid", 0),
        )
        self.item_drops.append(drop)
        self.active_drops[drop.entity_id] = drop

    def _handle_despawn(self, d: dict) -> None:
        eid = d.get("entity_id", 0)
        if eid in self.active_drops:
            self.active_drops[eid].picked_up = True
            del self.active_drops[eid]
        self.entities.pop(eid, None)

    def _handle_target(self, d: dict) -> None:
        attacker = d.get("attacker_id", 0)
        target = d.get("target_id", 0)
        if attacker and target:
            self.combat_targets[attacker] = target

    def _handle_spawn(self, d: dict, spawn_type: str, ts: float) -> None:
        eid = d.get("entity_id", 0)
        if not eid:
            return
        etype = {"MONSTER_SPAWN": "monster", "NPC_SPAWN": "npc", "OBJECT_SPAWN": "object"}.get(spawn_type, "unknown")
        self.entities[eid] = Entity(entity_id=eid, entity_type=etype, last_seen=ts)


# ---- Display ----

def format_time(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def format_elapsed(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h{m:02d}m"
    return f"{m}m{s:02d}s"


def print_drop_alert(drop: ItemDrop, is_mine: bool) -> None:
    """Print a prominent alert for an item drop."""
    ts = format_time(drop.timestamp)
    mine_tag = " [MINE]" if is_mine else ""

    print()
    if is_mine:
        print(f"  {'*' * 56}")
        print(f"  *  ITEM DROP{mine_tag:<42}*")
    else:
        print(f"  {'=' * 56}")
        print(f"  |  ITEM DROP{mine_tag:<42}|")

    border = "*" if is_mine else "|"
    print(f"  {border}  Time:     {ts:<42}{border}")
    print(f"  {border}  Item ID:  {drop.item_id:<42}{border}")
    print(f"  {border}  Count:    {drop.count:<42}{border}")
    print(f"  {border}  Position: ({drop.x}, {drop.y}){'':<30}{border}")
    print(f"  {border}  Owner:    {drop.owner_name:<42}{border}")

    if is_mine:
        print(f"  {'*' * 56}")
    else:
        print(f"  {'=' * 56}")
    print()


def print_status(state: RadarState) -> None:
    """Print current radar status summary."""
    elapsed = time.time() - state.start_time
    with state._lock:
        n_entities = len(state.entities)
        n_active = len(state.active_drops)
        n_total_drops = len(state.item_drops)
        n_mine = sum(1 for d in state.item_drops if state.is_mine(d.owner_name))

    print()
    print(f"  --- Radar Status ({format_elapsed(elapsed)}) ---")
    print(f"  Packets:  {state.total_packets} total")
    print(f"  Entities: {n_entities} tracked")
    print(f"  Drops:    {n_total_drops} seen ({n_active} on ground, {n_mine} mine)")
    if state.packet_counts:
        top = sorted(state.packet_counts.items(), key=lambda x: -x[1])[:8]
        counts = ", ".join(f"{n}={c}" for n, c in top)
        print(f"  Types:    {counts}")
    print()


def print_drops_history(state: RadarState) -> None:
    """Print recent item drops."""
    with state._lock:
        recent = state.item_drops[-10:]

    if not recent:
        print("\n  No item drops detected yet.\n")
        return

    print(f"\n  --- Recent Drops ({len(state.item_drops)} total) ---")
    for d in recent:
        ts = format_time(d.timestamp)
        mine = " *" if state.is_mine(d.owner_name) else ""
        status = "gone" if d.picked_up else "ON GROUND"
        print(f"  [{ts}] item={d.item_id} x{d.count} at ({d.x},{d.y}) "
              f"by {d.owner_name} [{status}]{mine}")
    print()


# ---- Main ----

def run_radar(
    iface: str | None = None,
    my_chars: list[str] | None = None,
    verbose: bool = False,
):
    state = RadarState(my_chars=my_chars)
    sniffer = GESniffer(iface=iface)

    last_drop_count = 0

    def on_packet(pkt: GEPacket) -> None:
        nonlocal last_drop_count
        decoded = state.process_packet(pkt)

        if not decoded:
            if verbose:
                ts = format_time(pkt.timestamp)
                print(f"  [{ts}] {pkt.direction} {pkt.size}b (unknown)")
            return

        name = decoded["name"]

        # Alert on new item drops
        if name == "ITEM_DROP":
            drop = state.item_drops[-1]
            is_mine = state.is_mine(drop.owner_name)
            print_drop_alert(drop, is_mine)
            last_drop_count = len(state.item_drops)

        elif verbose and name not in ("HEARTBEAT", "ACK", "KEEPALIVE"):
            ts = format_time(pkt.timestamp)
            print(f"  [{ts}] {name} ({decoded['size']}b)")

    sniffer.on_packet(on_packet)

    # Capture in background thread
    def capture_thread():
        sniffer.start()

    t = threading.Thread(target=capture_thread, daemon=True)
    t.start()

    print("=" * 60)
    print("  GE_Phantom — Item Radar")
    print("=" * 60)
    print()
    if my_chars:
        print(f"  Tracking characters: {', '.join(my_chars)}")
    else:
        print("  Tracking: ALL drops (use --my-chars to filter)")
    print()
    print("  Commands:")
    print("    s = status        d = drop history")
    print("    v = toggle verbose    q = quit")
    print()
    print("  Listening for item drops...")
    print()

    try:
        while True:
            user_input = input().strip().lower()

            if user_input == "q":
                break
            elif user_input == "s":
                print_status(state)
            elif user_input == "d":
                print_drops_history(state)
            elif user_input == "v":
                verbose = not verbose
                print(f"\n  Verbose: {'ON' if verbose else 'OFF'}\n")

    except (KeyboardInterrupt, EOFError):
        pass

    # Summary on exit
    print(f"\n{'=' * 60}")
    print(f"  Session Summary")
    print(f"{'=' * 60}")
    elapsed = time.time() - state.start_time
    print(f"  Duration:  {format_elapsed(elapsed)}")
    print(f"  Packets:   {state.total_packets}")
    print(f"  Entities:  {len(state.entities)} tracked")
    print(f"  Drops:     {len(state.item_drops)} total")

    if state.item_drops:
        mine = [d for d in state.item_drops if state.is_mine(d.owner_name)]
        print(f"  My drops:  {len(mine)}")
        print()
        print("  All drops:")
        for d in state.item_drops:
            ts = format_time(d.timestamp)
            mine_tag = " *" if state.is_mine(d.owner_name) else ""
            print(f"    [{ts}] item={d.item_id} x{d.count} at ({d.x},{d.y}) "
                  f"by {d.owner_name}{mine_tag}")

    print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="GE_Phantom Item Radar")
    parser.add_argument("--iface", help="Network interface to sniff on")
    parser.add_argument(
        "--my-chars",
        help="Comma-separated list of your character names (for highlighting)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all decoded packets")
    args = parser.parse_args()

    my_chars = [c.strip() for c in args.my_chars.split(",")] if args.my_chars else None

    run_radar(
        iface=args.iface,
        my_chars=my_chars,
        verbose=args.verbose,
    )
