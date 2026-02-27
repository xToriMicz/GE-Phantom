"""Live multiclient test harness.

Simulates 2+ GE clients with interleaved packets to verify:
- TCP reassembly splits coalesced segments correctly per client
- Per-client state separation (entities, zones, drops)
- Zone tracking per client
- Stale pruning removes inactive clients
- Reconnect detection (same char name on new port)
- Global state aggregates all clients
"""

import struct
import time
import pytest

from src.sniffer.capture import GEPacket
from src.sniffer.stream import TCPStreamReassembler
from src.data.router import ClientRouter
from src.data.state import RadarState


# ---- Packet builders ----

def _s2c_pkt(payload: bytes, client_port: int, ts: float = 1000.0) -> GEPacket:
    """Build an S2C packet targeting a specific client port."""
    return GEPacket(
        timestamp=ts,
        direction="S2C",
        src_ip="103.55.55.138",
        dst_ip="192.168.1.100",
        src_port=7000,
        dst_port=client_port,
        payload=payload,
        seq=0, ack=0, flags="PA",
    )


def _c2s_pkt(payload: bytes, client_port: int, ts: float = 1000.0) -> GEPacket:
    """Build a C2S packet from a specific client port."""
    return GEPacket(
        timestamp=ts,
        direction="C2S",
        src_ip="192.168.1.100",
        dst_ip="103.55.55.138",
        src_port=client_port,
        dst_port=7000,
        payload=payload,
        seq=0, ack=0, flags="PA",
    )


def _entity_position(entity_id: int, zone: int = 3, x: int = 100, y: int = 200) -> bytes:
    buf = bytearray(26)
    buf[0], buf[1] = 0x56, 0x0c
    struct.pack_into("<I", buf, 2, entity_id)
    struct.pack_into("<H", buf, 6, 1)
    struct.pack_into("<H", buf, 8, zone)
    struct.pack_into("<i", buf, 10, x)
    struct.pack_into("<i", buf, 14, y)
    struct.pack_into("<I", buf, 18, 0)
    struct.pack_into("<f", buf, 22, 100.0)
    return bytes(buf)


def _entity_despawn(entity_id: int) -> bytes:
    buf = bytearray(6)
    buf[0], buf[1] = 0x7a, 0x0c
    struct.pack_into("<I", buf, 2, entity_id)
    return bytes(buf)


def _item_drop(entity_id: int, item_id: int, owner_name: str,
               x: int = 100, y: int = 200) -> bytes:
    buf = bytearray(57)
    buf[0], buf[1] = 0x49, 0x0c
    struct.pack_into("<I", buf, 2, entity_id)
    struct.pack_into("<i", buf, 6, x)
    struct.pack_into("<i", buf, 10, y)
    struct.pack_into("<I", buf, 14, 0)
    struct.pack_into("<I", buf, 18, item_id)
    struct.pack_into("<I", buf, 22, 1)
    struct.pack_into("<I", buf, 26, 0)
    name_bytes = owner_name.encode("utf-8")[:20]
    buf[36:36 + len(name_bytes)] = name_bytes
    return bytes(buf)


def _combat_update(entity_id: int, attack_range: float = 850.0) -> bytes:
    buf = bytearray(38)
    buf[0], buf[1] = 0x54, 0x0c
    struct.pack_into("<I", buf, 2, entity_id)
    struct.pack_into("<f", buf, 30, attack_range)
    return bytes(buf)


def _combat_data(entity_id: int, sub_index: int = 0) -> bytes:
    buf = bytearray(23)
    buf[0], buf[1] = 0xa5, 0x0c
    buf[2] = sub_index
    buf[3] = 0x9a
    struct.pack_into("<I", buf, 4, entity_id)
    return bytes(buf)


def _player_position(entity_id: int, x: int = 100, y: int = 200) -> bytes:
    """Build a 15-byte PLAYER_MOVE (0x7b00) packet."""
    buf = bytearray(15)
    buf[0], buf[1] = 0x7b, 0x00
    struct.pack_into("<I", buf, 2, entity_id)
    struct.pack_into("<i", buf, 6, x)
    struct.pack_into("<i", buf, 10, y)
    buf[14] = 0  # state
    return bytes(buf)


def _keepalive() -> bytes:
    buf = bytearray(18)
    buf[0], buf[1] = 0x10, 0x00
    return bytes(buf)


# ---- Test classes ----

class TestTwoClientSimulation:
    """Simulate two GE clients connected simultaneously."""

    CLIENT_A = 54321
    CLIENT_B = 54322

    def test_two_clients_separate_entities(self):
        """Each client tracks its own entities independently."""
        router = ClientRouter()

        # Client A sees monster 100 in zone 5
        router.process_packet(_s2c_pkt(
            _entity_position(entity_id=100, zone=5, x=1000, y=2000),
            self.CLIENT_A, ts=1000.0,
        ))
        # Client B sees monster 200 in zone 7
        router.process_packet(_s2c_pkt(
            _entity_position(entity_id=200, zone=7, x=3000, y=4000),
            self.CLIENT_B, ts=1000.1,
        ))

        clients = router.get_active_clients()
        assert len(clients) == 2

        # Find sessions by port
        a_key = f"192.168.1.100:{self.CLIENT_A}"
        b_key = f"192.168.1.100:{self.CLIENT_B}"
        sa = router.clients[a_key]
        sb = router.clients[b_key]

        # Client A has entity 100 in zone 5
        assert 100 in sa.state.entities
        assert 200 not in sa.state.entities
        assert sa.state.current_zone == 5

        # Client B has entity 200 in zone 7
        assert 200 in sb.state.entities
        assert 100 not in sb.state.entities
        assert sb.state.current_zone == 7

        # Global state has both
        assert 100 in router.global_state.entities
        assert 200 in router.global_state.entities

    def test_two_clients_separate_zone_tracking(self):
        """Zone transitions are tracked independently per client."""
        router = ClientRouter()

        # Client A: zone 3 -> zone 5
        router.process_packet(_s2c_pkt(
            _entity_position(1, zone=3), self.CLIENT_A, ts=1000.0,
        ))
        router.process_packet(_s2c_pkt(
            _entity_position(1, zone=5), self.CLIENT_A, ts=1001.0,
        ))

        # Client B: zone 10 (no transition)
        router.process_packet(_s2c_pkt(
            _entity_position(2, zone=10), self.CLIENT_B, ts=1000.5,
        ))

        a_key = f"192.168.1.100:{self.CLIENT_A}"
        b_key = f"192.168.1.100:{self.CLIENT_B}"
        sa = router.clients[a_key]
        sb = router.clients[b_key]

        assert sa.state.current_zone == 5
        assert len(sa.state.zone_transitions) == 1
        assert sa.state.zone_transitions[0].from_zone == 3
        assert sa.state.zone_transitions[0].to_zone == 5

        assert sb.state.current_zone == 10
        assert len(sb.state.zone_transitions) == 0

    def test_coalesced_segments_per_client(self):
        """TCP coalesced segments are split correctly per client."""
        router = ClientRouter()

        # Client A: 2 ENTITY_POSITION coalesced (52 bytes)
        coalesced_a = (
            _entity_position(entity_id=10, x=100) +
            _entity_position(entity_id=11, x=200)
        )
        router.process_packet(_s2c_pkt(coalesced_a, self.CLIENT_A, ts=1000.0))

        # Client B: 3 COMBAT_DATA coalesced (69 bytes)
        coalesced_b = (
            _combat_data(entity_id=50, sub_index=0) +
            _combat_data(entity_id=50, sub_index=1) +
            _combat_data(entity_id=50, sub_index=2)
        )
        router.process_packet(_s2c_pkt(coalesced_b, self.CLIENT_B, ts=1000.1))

        a_key = f"192.168.1.100:{self.CLIENT_A}"
        b_key = f"192.168.1.100:{self.CLIENT_B}"
        sa = router.clients[a_key]
        sb = router.clients[b_key]

        # Client A: both entities decoded from coalesced segment
        assert 10 in sa.state.entities
        assert 11 in sa.state.entities
        assert sa.state.total_packets == 2  # 2 game packets from 1 TCP segment

        # Client B: 3 COMBAT_DATA packets processed
        assert sb.state.total_packets == 3
        assert sb.state.packet_counts.get("COMBAT_DATA", 0) == 3

    def test_interleaved_packets(self):
        """Packets from two clients interleaved in time order."""
        router = ClientRouter()

        # Interleave A and B packets by timestamp
        packets = [
            (self.CLIENT_A, _entity_position(1, zone=3), 1000.0),
            (self.CLIENT_B, _entity_position(2, zone=7), 1000.1),
            (self.CLIENT_A, _combat_update(1, 850.0), 1000.2),
            (self.CLIENT_B, _entity_position(3, zone=7), 1000.3),
            (self.CLIENT_A, _entity_position(1, zone=3, x=200), 1000.4),
            (self.CLIENT_B, _combat_update(2, 500.0), 1000.5),
        ]

        for port, payload, ts in packets:
            router.process_packet(_s2c_pkt(payload, port, ts))

        a_key = f"192.168.1.100:{self.CLIENT_A}"
        b_key = f"192.168.1.100:{self.CLIENT_B}"
        sa = router.clients[a_key]
        sb = router.clients[b_key]

        # Client A: entity 1, zone 3
        assert sa.state.total_packets == 3
        assert sa.state.current_zone == 3
        assert 1 in sa.state.entities
        assert sa.state.entities[1].x == 200  # latest position

        # Client B: entities 2 and 3, zone 7
        assert sb.state.total_packets == 3
        assert sb.state.current_zone == 7
        assert 2 in sb.state.entities
        assert 3 in sb.state.entities

        # Global has all
        assert router.global_state.total_packets == 6

    def test_item_drop_upgrades_label(self):
        """ITEM_DROP with owner_name upgrades client label to character name."""
        router = ClientRouter()

        # Client A: some position data
        router.process_packet(_s2c_pkt(
            _entity_position(1), self.CLIENT_A, ts=1000.0,
        ))

        a_key = f"192.168.1.100:{self.CLIENT_A}"
        sa = router.clients[a_key]
        assert sa.label.startswith("Client ")

        # Item drop with owner name
        router.process_packet(_s2c_pkt(
            _item_drop(entity_id=500, item_id=42, owner_name="Kaja"),
            self.CLIENT_A, ts=1001.0,
        ))

        assert sa.label == "Kaja"

    def test_c2s_and_s2c_same_client(self):
        """C2S and S2C packets for the same client route to same session."""
        router = ClientRouter()

        # S2C to client A
        router.process_packet(_s2c_pkt(
            _entity_position(1), self.CLIENT_A, ts=1000.0,
        ))
        # C2S from client A
        router.process_packet(_c2s_pkt(
            _keepalive(), self.CLIENT_A, ts=1000.5,
        ))

        a_key = f"192.168.1.100:{self.CLIENT_A}"
        sa = router.clients[a_key]
        # Both directions processed by same client
        assert sa.state.total_packets == 2


class TestStalePruningLive:
    """Test stale client pruning under multiclient conditions."""

    def test_prune_inactive_client(self):
        """Client not seen for >timeout gets pruned."""
        router = ClientRouter()
        PORT_A, PORT_B = 54321, 54322

        # Both clients active
        router.process_packet(_s2c_pkt(_entity_position(1), PORT_A, ts=1000.0))
        router.process_packet(_s2c_pkt(_entity_position(2), PORT_B, ts=1000.0))
        assert len(router.clients) == 2

        # Only client A is active later
        router.process_packet(_s2c_pkt(_entity_position(1, x=200), PORT_A, ts=1100.0))

        # Prune with 60s timeout at time 1100
        pruned = router.prune_stale(timeout=60.0, now=1100.0)
        assert len(pruned) == 1
        assert pruned[0].client_key == f"192.168.1.100:{PORT_B}"
        assert len(router.clients) == 1

    def test_prune_preserves_active_clients(self):
        """Active clients are not pruned."""
        router = ClientRouter()
        PORT_A, PORT_B = 54321, 54322

        router.process_packet(_s2c_pkt(_entity_position(1), PORT_A, ts=1000.0))
        router.process_packet(_s2c_pkt(_entity_position(2), PORT_B, ts=1000.0))

        # Both still active at time 1050 (within 60s timeout)
        pruned = router.prune_stale(timeout=60.0, now=1050.0)
        assert len(pruned) == 0
        assert len(router.clients) == 2

    def test_prune_cleans_char_mapping(self):
        """Pruning a named client also cleans up the char->key mapping."""
        router = ClientRouter()
        PORT_A = 54321

        router.process_packet(_s2c_pkt(_entity_position(1), PORT_A, ts=1000.0))
        router.process_packet(_s2c_pkt(
            _item_drop(500, 42, "TestChar"), PORT_A, ts=1001.0,
        ))

        assert router.find_client_by_char("TestChar") is not None

        # Prune
        pruned = router.prune_stale(timeout=10.0, now=2000.0)
        assert len(pruned) == 1
        assert router.find_client_by_char("TestChar") is None


class TestReconnectDetectionLive:
    """Test reconnect detection: same char name on new port."""

    def test_reconnect_replaces_old_session(self):
        """When a character reconnects on a new port, old session is removed."""
        router = ClientRouter()
        OLD_PORT, NEW_PORT = 54321, 54322

        # First connection: char "Hero" on OLD_PORT
        router.process_packet(_s2c_pkt(_entity_position(1), OLD_PORT, ts=1000.0))
        router.process_packet(_s2c_pkt(
            _item_drop(500, 42, "Hero"), OLD_PORT, ts=1001.0,
        ))

        old_key = f"192.168.1.100:{OLD_PORT}"
        assert router.clients[old_key].label == "Hero"

        # Reconnect: same char "Hero" on NEW_PORT
        router.process_packet(_s2c_pkt(_entity_position(2), NEW_PORT, ts=1100.0))
        router.process_packet(_s2c_pkt(
            _item_drop(501, 43, "Hero"), NEW_PORT, ts=1101.0,
        ))

        # Old session should be removed
        assert old_key not in router.clients
        new_key = f"192.168.1.100:{NEW_PORT}"
        assert new_key in router.clients
        assert router.clients[new_key].label == "Hero"
        assert router.clients[new_key].reconnect_count == 1

    def test_reconnect_count_increments(self):
        """Multiple reconnects increment the counter."""
        router = ClientRouter()

        ports = [54321, 54322, 54323]
        for i, port in enumerate(ports):
            router.process_packet(_s2c_pkt(_entity_position(1), port, ts=1000.0 + i * 100))
            router.process_packet(_s2c_pkt(
                _item_drop(500 + i, 42, "Hero"), port, ts=1001.0 + i * 100,
            ))

        # Only latest session remains
        assert len([s for s in router.clients.values() if s.label == "Hero"]) == 1
        latest = router.find_client_by_char("Hero")
        assert latest is not None
        assert latest.reconnect_count == 2  # reconnected twice

    def test_different_chars_no_reconnect(self):
        """Different character names on different ports are separate clients."""
        router = ClientRouter()

        router.process_packet(_s2c_pkt(_entity_position(1), 54321, ts=1000.0))
        router.process_packet(_s2c_pkt(
            _item_drop(500, 42, "Hero"), 54321, ts=1001.0,
        ))
        router.process_packet(_s2c_pkt(_entity_position(2), 54322, ts=1002.0))
        router.process_packet(_s2c_pkt(
            _item_drop(501, 43, "Mage"), 54322, ts=1003.0,
        ))

        assert len(router.clients) == 2
        assert router.find_client_by_char("Hero") is not None
        assert router.find_client_by_char("Mage") is not None


class TestReassemblyAcrossClients:
    """Test that reassembly buffers are independent per client."""

    def test_fragmented_packet_per_client(self):
        """A fragmented packet on one client doesn't affect the other."""
        router = ClientRouter()
        PORT_A, PORT_B = 54321, 54322

        # Start a fragmented ENTITY_POSITION for client A
        pos_a = _entity_position(entity_id=1, x=100)
        router.process_packet(_s2c_pkt(pos_a[:10], PORT_A, ts=1000.0))

        # Client B gets a complete packet
        pos_b = _entity_position(entity_id=2, x=200)
        router.process_packet(_s2c_pkt(pos_b, PORT_B, ts=1000.1))

        b_key = f"192.168.1.100:{PORT_B}"
        sb = router.clients[b_key]
        assert 2 in sb.state.entities  # Client B decoded successfully

        a_key = f"192.168.1.100:{PORT_A}"
        sa = router.clients[a_key]
        assert 1 not in sa.state.entities  # Client A still buffering

        # Complete the fragment for client A
        router.process_packet(_s2c_pkt(pos_a[10:], PORT_A, ts=1000.2))
        assert 1 in sa.state.entities  # Now decoded

    def test_coalesced_on_one_client_independent(self):
        """Coalesced segments on client A don't leak to client B."""
        router = ClientRouter()
        PORT_A, PORT_B = 54321, 54322

        # Client A: coalesced 2x ENTITY_POSITION
        merged = _entity_position(10, x=100) + _entity_position(11, x=200)
        router.process_packet(_s2c_pkt(merged, PORT_A, ts=1000.0))

        # Client B: single packet
        router.process_packet(_s2c_pkt(
            _entity_position(20, x=300), PORT_B, ts=1000.1,
        ))

        a_key = f"192.168.1.100:{PORT_A}"
        b_key = f"192.168.1.100:{PORT_B}"
        sa = router.clients[a_key]
        sb = router.clients[b_key]

        # Client A has 2 entities
        assert len(sa.state.entities) == 2
        assert 10 in sa.state.entities
        assert 11 in sa.state.entities

        # Client B has 1 entity
        assert len(sb.state.entities) == 1
        assert 20 in sb.state.entities


class TestFullSessionSimulation:
    """Simulate a complete play session with multiple clients."""

    def test_combat_session_two_clients(self):
        """Two clients farming in different zones with full packet variety."""
        router = ClientRouter()
        PORT_A, PORT_B = 54321, 54322
        ts = 1000.0

        # ---- Client A: Zone 3, fighting monsters ----
        # Monster spawns
        spawn_a = bytearray(371)
        spawn_a[0], spawn_a[1] = 0x3e, 0x0c
        struct.pack_into("<I", spawn_a, 2, 1000)
        router.process_packet(_s2c_pkt(bytes(spawn_a), PORT_A, ts)); ts += 0.1

        # Position updates (coalesced)
        pos_batch_a = (
            _entity_position(1000, zone=3, x=500, y=600) +
            _entity_position(1001, zone=3, x=700, y=800)
        )
        router.process_packet(_s2c_pkt(pos_batch_a, PORT_A, ts)); ts += 0.1

        # Combat
        router.process_packet(_s2c_pkt(
            _combat_update(1000, 850.0), PORT_A, ts,
        )); ts += 0.1

        # Combat data batch
        cd_batch = (
            _combat_data(1000, sub_index=0) +
            _combat_data(1000, sub_index=1)
        )
        router.process_packet(_s2c_pkt(cd_batch, PORT_A, ts)); ts += 0.1

        # ---- Client B: Zone 7, picking up items ----
        # Player positions
        pp_batch = (
            _player_position(2000, x=100, y=200) +
            _player_position(2001, x=300, y=400)
        )
        router.process_packet(_s2c_pkt(pp_batch, PORT_B, ts)); ts += 0.1

        # Item drop
        router.process_packet(_s2c_pkt(
            _item_drop(3000, item_id=42, owner_name="Mage", x=150, y=250),
            PORT_B, ts,
        )); ts += 0.1

        # Entity position in zone 7
        router.process_packet(_s2c_pkt(
            _entity_position(3000, zone=7, x=150, y=250),
            PORT_B, ts,
        )); ts += 0.1

        # Item despawn (picked up)
        router.process_packet(_s2c_pkt(
            _entity_despawn(3000), PORT_B, ts,
        )); ts += 0.1

        # ---- Verify final state ----
        a_key = f"192.168.1.100:{PORT_A}"
        b_key = f"192.168.1.100:{PORT_B}"
        sa = router.clients[a_key]
        sb = router.clients[b_key]

        # Client A: zone 3, has monster entity 1000
        assert sa.state.current_zone == 3
        assert 1000 in sa.state.entities
        assert sa.state.entities[1000].entity_type == "monster"
        assert sa.state.packet_counts["COMBAT_DATA"] == 2
        assert sa.state.packet_counts["COMBAT_UPDATE"] == 1

        # Client B: zone 7, named "Mage", item was picked up
        assert sb.state.current_zone == 7
        assert sb.label == "Mage"
        assert len(sb.state.item_drops) == 1
        assert sb.state.item_drops[0].picked_up is True
        assert 3000 not in sb.state.active_drops
        # Player entities tracked
        assert 2000 in sb.state.entities
        assert sb.state.entities[2000].entity_type == "player"

        # Global state
        assert router.global_state.total_packets > 0
        assert router.global_state.packet_counts["ENTITY_POSITION"] >= 3
