"""Test dashboard replay logic headlessly.

Simulates what the dashboard's _run_replay does, but without TUI.
Validates:
1. All packets are processed without errors
2. Router correctly routes to client sessions
3. State tracking (entities, drops, etc.) works
4. Reassembler splits coalesced packets correctly with new framing
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.data.router import ClientRouter
from src.sniffer.capture import GEPacket
from src.protocol.packet_types import KNOWN_PACKETS


def main():
    capture_path = Path(__file__).parent.parent / "captures" / "live_test_01.json"
    if not capture_path.exists():
        print(f"ERROR: {capture_path} not found")
        return

    data = json.loads(capture_path.read_text())
    packets = data.get("packets", [])
    print(f"Loaded {len(packets)} packets from {capture_path.name}")

    # Create router (same as dashboard does)
    router = ClientRouter(my_chars=None)

    errors = []
    decoded_count = 0
    packet_names = {}

    for i, pkt_data in enumerate(packets):
        payload_hex = pkt_data.get("payload_hex", "")
        if not payload_hex:
            continue

        try:
            payload = bytes.fromhex(payload_hex)
            pkt = GEPacket(
                timestamp=pkt_data.get("timestamp", time.time()),
                direction=pkt_data.get("direction", "S2C"),
                src_ip=pkt_data.get("src", "0.0.0.0:0").rsplit(":", 1)[0] if "src" in pkt_data else "0.0.0.0",
                dst_ip=pkt_data.get("dst", "0.0.0.0:0").rsplit(":", 1)[0] if "dst" in pkt_data else "0.0.0.0",
                src_port=int(pkt_data["src"].rsplit(":", 1)[1]) if "src" in pkt_data else 0,
                dst_port=int(pkt_data["dst"].rsplit(":", 1)[1]) if "dst" in pkt_data else 0,
                payload=payload,
                seq=pkt_data.get("seq", 0),
                ack=pkt_data.get("ack", 0),
                flags=pkt_data.get("flags", ""),
            )

            _key, decoded = router.process_packet(pkt)
            if decoded:
                decoded_count += 1
                name = decoded.get("name", "?")
                packet_names[name] = packet_names.get(name, 0) + 1

        except Exception as e:
            errors.append(f"Packet {i}: {e}")
            if len(errors) <= 5:
                print(f"  ERROR at packet {i}: {e}")

    # Results
    global_state = router.global_state
    clients = router.get_active_clients()

    print(f"\n{'='*60}")
    print("REPLAY TEST RESULTS")
    print(f"{'='*60}")
    print(f"  Packets fed:      {len(packets)}")
    print(f"  Decoded:          {decoded_count}")
    print(f"  Errors:           {len(errors)}")
    print(f"  Clients detected: {len(clients)}")

    for session in clients:
        print(f"    {session.label}: {session.client_key} "
              f"(pkts={session.state.total_packets}, "
              f"ents={len(session.state.entities)}, "
              f"drops={len(session.state.item_drops)})")

    print(f"\n  Global state:")
    print(f"    Total packets: {global_state.total_packets}")
    print(f"    Entities:      {len(global_state.entities)}")
    print(f"    Characters:    {len(global_state.characters)}")
    print(f"    Item drops:    {len(global_state.item_drops)}")
    print(f"    Active drops:  {len(global_state.active_drops)}")
    print(f"    Current zone:  {global_state.current_zone}")
    print(f"    Zone changes:  {len(global_state.zone_transitions)}")

    print(f"\n  Packet type breakdown (top 15):")
    for name, count in sorted(packet_names.items(), key=lambda x: -x[1])[:15]:
        print(f"    {name:<25s} {count:>6d}")

    # Check reassembler stats
    print(f"\n  Reassembler stats:")
    for session in clients:
        if session.reassembler:
            stats = session.reassembler.stats()
            print(f"    {session.label}: {stats}")

    # Validation checks
    print(f"\n{'='*60}")
    print("VALIDATION")
    print(f"{'='*60}")

    issues = []
    if len(errors) > 0:
        issues.append(f"{len(errors)} processing errors")
    if global_state.total_packets == 0:
        issues.append("No packets processed")
    if len(global_state.entities) == 0:
        issues.append("No entities tracked")

    # Check for buffer residue
    for session in clients:
        if session.reassembler:
            stats = session.reassembler.stats()
            for direction, dstats in stats.items():
                if dstats["buffered"] > 0:
                    issues.append(f"{session.label} {direction}: {dstats['buffered']} bytes stuck in buffer")

    if issues:
        print(f"  ISSUES FOUND:")
        for issue in issues:
            print(f"    - {issue}")
    else:
        print(f"  ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
