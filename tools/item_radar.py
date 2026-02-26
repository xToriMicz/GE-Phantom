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
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.sniffer.capture import GESniffer, GEPacket
from src.data.state import RadarState, Entity, ItemDrop
from src.data.router import ClientRouter, ClientSession


# ---- Display ----

def format_time(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def format_elapsed(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h{m:02d}m"
    return f"{m}m{s:02d}s"


def print_drop_alert(drop: ItemDrop, is_mine: bool, client_label: str = "") -> None:
    """Print a prominent alert for an item drop."""
    ts = format_time(drop.timestamp)
    mine_tag = " [MINE]" if is_mine else ""
    client_tag = f" [{client_label}]" if client_label else ""

    print()
    if is_mine:
        print(f"  {'*' * 56}")
        print(f"  *  ITEM DROP{mine_tag}{client_tag:<{42 - len(mine_tag)}}*")
    else:
        print(f"  {'=' * 56}")
        print(f"  |  ITEM DROP{mine_tag}{client_tag:<{42 - len(mine_tag)}}|")

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


def print_status(router: ClientRouter) -> None:
    """Print current radar status summary."""
    state = router.global_state
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

    clients = router.get_active_clients()
    if clients:
        print(f"  Clients:  {len(clients)}")
        for i, c in enumerate(clients, 1):
            print(f"    {i}. {c.label} ({c.client_key}) — {c.state.total_packets} pkts")
    print()


def print_drops_history(router: ClientRouter) -> None:
    """Print recent item drops."""
    state = router.global_state
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


def print_clients(router: ClientRouter) -> None:
    """Print connected clients list."""
    clients = router.get_active_clients()
    if not clients:
        print("\n  No clients detected yet.\n")
        return

    print(f"\n  --- Connected Clients ({len(clients)}) ---")
    now = time.time()
    for i, c in enumerate(clients, 1):
        ago = now - c.last_seen if c.last_seen else 0
        stale = " [STALE]" if c.is_stale(300.0, now) else ""
        reconn = f" (reconn x{c.reconnect_count})" if c.reconnect_count else ""
        print(f"  {i}. {c.label} — {c.client_key} — "
              f"{c.state.total_packets} pkts — {ago:.0f}s ago{reconn}{stale}")
    print()


# ---- Main ----

def run_radar(
    iface: str | None = None,
    my_chars: list[str] | None = None,
    verbose: bool = False,
):
    router = ClientRouter(my_chars=my_chars)
    sniffer = GESniffer(iface=iface)

    def on_packet(pkt: GEPacket) -> None:
        key, decoded = router.process_packet(pkt)

        if not decoded:
            if verbose:
                ts = format_time(pkt.timestamp)
                print(f"  [{ts}] {pkt.direction} {pkt.size}b (unknown)")
            return

        name = decoded["name"]

        # Alert on new item drops
        if name == "ITEM_DROP":
            state = router.global_state
            drop = state.item_drops[-1]
            is_mine = state.is_mine(drop.owner_name)
            session = router.clients.get(key)
            client_label = session.label if session else ""
            print_drop_alert(drop, is_mine, client_label)

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
    print("  GE_Phantom — Item Radar (multiclient)")
    print("=" * 60)
    print()
    if my_chars:
        print(f"  Tracking characters: {', '.join(my_chars)}")
    else:
        print("  Tracking: ALL drops (use --my-chars to filter)")
    print()
    print("  Commands:")
    print("    s = status        d = drop history")
    print("    c = client list   v = toggle verbose")
    print("    q = quit")
    print()
    print("  Listening for item drops...")
    print()

    try:
        while True:
            user_input = input().strip().lower()

            if user_input == "q":
                break
            elif user_input == "s":
                print_status(router)
            elif user_input == "d":
                print_drops_history(router)
            elif user_input == "c":
                print_clients(router)
            elif user_input == "v":
                verbose = not verbose
                print(f"\n  Verbose: {'ON' if verbose else 'OFF'}\n")

    except (KeyboardInterrupt, EOFError):
        pass

    # Summary on exit
    state = router.global_state
    print(f"\n{'=' * 60}")
    print(f"  Session Summary")
    print(f"{'=' * 60}")
    elapsed = time.time() - state.start_time
    print(f"  Duration:  {format_elapsed(elapsed)}")
    print(f"  Packets:   {state.total_packets}")
    print(f"  Entities:  {len(state.entities)} tracked")
    print(f"  Drops:     {len(state.item_drops)} total")
    print(f"  Clients:   {len(router.clients)}")

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
