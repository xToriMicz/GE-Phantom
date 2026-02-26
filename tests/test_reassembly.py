"""Tests for opcode_registry TCP reassembly and pipeline integration."""

import struct
import pytest

from src.sniffer.capture import GEPacket
from src.sniffer.stream import TCPStreamReassembler
from src.data.router import ClientRouter


def _make_pkt(direction: str, payload: bytes, timestamp: float = 1000.0,
              dst_port: int = 54321) -> GEPacket:
    return GEPacket(
        timestamp=timestamp,
        direction=direction,
        src_ip="192.168.1.100" if direction == "C2S" else "103.55.55.138",
        dst_ip="103.55.55.138" if direction == "C2S" else "192.168.1.100",
        src_port=54321 if direction == "C2S" else 7000,
        dst_port=7000 if direction == "C2S" else dst_port,
        payload=payload,
        seq=0,
        ack=0,
        flags="PA",
    )


def _make_entity_position(entity_id: int = 1, zone: int = 3, x: int = 100, y: int = 200) -> bytes:
    """Build a 26-byte ENTITY_POSITION (0x560c) payload."""
    buf = bytearray(26)
    buf[0] = 0x56
    buf[1] = 0x0c
    struct.pack_into("<I", buf, 2, entity_id)
    struct.pack_into("<H", buf, 6, 1)  # tick
    struct.pack_into("<H", buf, 8, zone)
    struct.pack_into("<i", buf, 10, x)
    struct.pack_into("<i", buf, 14, y)
    struct.pack_into("<I", buf, 18, 0)  # state
    struct.pack_into("<f", buf, 22, 100.0)  # speed
    return bytes(buf)


def _make_heartbeat() -> bytes:
    """Build a 6-byte HEARTBEAT (0x0000)."""
    return b"\x00\x00\x00\x00\x00\x00"


def _make_ack() -> bytes:
    """Build a 6-byte ACK (0xe00c)."""
    return b"\xe0\x0c\x00\x00\x00\x00"


def _make_combat_update(entity_id: int = 1) -> bytes:
    """Build a 38-byte COMBAT_UPDATE (0x540c)."""
    buf = bytearray(38)
    buf[0] = 0x54
    buf[1] = 0x0c
    struct.pack_into("<I", buf, 2, entity_id)
    struct.pack_into("<f", buf, 30, 850.0)  # attack_range
    return bytes(buf)


def _make_entity_despawn(entity_id: int = 1) -> bytes:
    """Build a 6-byte ENTITY_DESPAWN (0x7a0c)."""
    buf = bytearray(6)
    buf[0] = 0x7a
    buf[1] = 0x0c
    struct.pack_into("<I", buf, 2, entity_id)
    return bytes(buf)


def _make_entity_event(entity_id: int = 1, event: int = 0) -> bytes:
    """Build a 7-byte ENTITY_EVENT (0x430c)."""
    buf = bytearray(7)
    buf[0] = 0x43
    buf[1] = 0x0c
    struct.pack_into("<I", buf, 2, entity_id)
    buf[6] = event
    return bytes(buf)


def _make_batch_entity_update(total_size: int = 123) -> bytes:
    """Build a BATCH_ENTITY_UPDATE (0x660c) with length field at [2:4]."""
    buf = bytearray(total_size)
    buf[0] = 0x66
    buf[1] = 0x0c
    struct.pack_into("<H", buf, 2, total_size)  # length includes header
    return bytes(buf)


def _make_effect(total_size: int = 25) -> bytes:
    """Build an EFFECT (0x4a0e) with length field at [2:4]."""
    buf = bytearray(total_size)
    buf[0] = 0x4a
    buf[1] = 0x0e
    struct.pack_into("<H", buf, 2, total_size)  # length includes header
    return bytes(buf)


# ---- Opcode registry reassembly tests ----

class TestOpcodeRegistryReassembly:
    """Test the opcode_registry framing strategy."""

    def _make_reassembler(self) -> tuple[TCPStreamReassembler, list]:
        r = TCPStreamReassembler()
        r.set_framing("opcode_registry")
        results = []
        r.on_game_packet(lambda d, data: results.append((d, data)))
        return r, results

    def test_single_fixed_packet(self):
        """Single ENTITY_POSITION passes through correctly."""
        r, results = self._make_reassembler()
        payload = _make_entity_position()
        r.feed(_make_pkt("S2C", payload))
        assert len(results) == 1
        assert results[0] == ("S2C", payload)

    def test_two_entity_positions_coalesced(self):
        """Two 26-byte ENTITY_POSITION in one TCP segment (52 bytes)."""
        r, results = self._make_reassembler()
        pos1 = _make_entity_position(entity_id=1)
        pos2 = _make_entity_position(entity_id=2)
        merged = pos1 + pos2
        assert len(merged) == 52

        r.feed(_make_pkt("S2C", merged))
        assert len(results) == 2
        assert results[0][1] == pos1
        assert results[1][1] == pos2

    def test_two_combat_updates_coalesced(self):
        """Two 38-byte COMBAT_UPDATE in one segment (76 bytes)."""
        r, results = self._make_reassembler()
        cu1 = _make_combat_update(entity_id=10)
        cu2 = _make_combat_update(entity_id=20)
        merged = cu1 + cu2

        r.feed(_make_pkt("S2C", merged))
        assert len(results) == 2
        assert len(results[0][1]) == 38
        assert len(results[1][1]) == 38

    def test_combat_update_plus_entity_position(self):
        """38-byte COMBAT_UPDATE + 26-byte ENTITY_POSITION (64 bytes total)."""
        r, results = self._make_reassembler()
        cu = _make_combat_update()
        pos = _make_entity_position()
        merged = cu + pos
        assert len(merged) == 64

        r.feed(_make_pkt("S2C", merged))
        assert len(results) == 2
        assert len(results[0][1]) == 38  # COMBAT_UPDATE
        assert len(results[1][1]) == 26  # ENTITY_POSITION

    def test_despawn_plus_entity_position(self):
        """6-byte ENTITY_DESPAWN + 26-byte ENTITY_POSITION (32 bytes)."""
        r, results = self._make_reassembler()
        despawn = _make_entity_despawn(entity_id=5)
        pos = _make_entity_position(entity_id=10)
        merged = despawn + pos

        r.feed(_make_pkt("S2C", merged))
        assert len(results) == 2
        assert len(results[0][1]) == 6
        assert len(results[1][1]) == 26

    def test_entity_event_plus_monster_spawn(self):
        """7-byte ENTITY_EVENT + 371-byte MONSTER_SPAWN (378 bytes)."""
        r, results = self._make_reassembler()
        event = _make_entity_event()
        spawn = bytearray(371)
        spawn[0] = 0x3e
        spawn[1] = 0x0c
        struct.pack_into("<I", spawn, 2, 99)
        merged = event + bytes(spawn)

        r.feed(_make_pkt("S2C", merged))
        assert len(results) == 2
        assert len(results[0][1]) == 7
        assert len(results[1][1]) == 371

    def test_batch_entity_update_variable_length(self):
        """BATCH_ENTITY_UPDATE uses length field at [2:4]."""
        r, results = self._make_reassembler()
        batch = _make_batch_entity_update(total_size=160)
        r.feed(_make_pkt("S2C", batch))
        assert len(results) == 1
        assert len(results[0][1]) == 160

    def test_batch_entity_update_plus_entity_position(self):
        """160-byte BATCH_ENTITY_UPDATE + 26-byte ENTITY_POSITION (186 total)."""
        r, results = self._make_reassembler()
        batch = _make_batch_entity_update(total_size=160)
        pos = _make_entity_position()
        merged = batch + pos

        r.feed(_make_pkt("S2C", merged))
        assert len(results) == 2
        assert len(results[0][1]) == 160
        assert len(results[1][1]) == 26

    def test_effect_variable_length(self):
        """EFFECT uses length field at [2:4]."""
        r, results = self._make_reassembler()
        effect = _make_effect(total_size=23)
        r.feed(_make_pkt("S2C", effect))
        assert len(results) == 1
        assert len(results[0][1]) == 23

    def test_three_heartbeats_coalesced(self):
        """Three 6-byte HEARTBEAT packets in one segment."""
        r, results = self._make_reassembler()
        merged = _make_heartbeat() + _make_heartbeat() + _make_heartbeat()
        r.feed(_make_pkt("S2C", merged))
        assert len(results) == 3

    def test_heartbeat_plus_ack(self):
        """6-byte HEARTBEAT + 6-byte ACK coalesced."""
        r, results = self._make_reassembler()
        merged = _make_heartbeat() + _make_ack()
        r.feed(_make_pkt("S2C", merged))
        assert len(results) == 2

    def test_fragmented_entity_position(self):
        """ENTITY_POSITION split across two TCP segments."""
        r, results = self._make_reassembler()
        pos = _make_entity_position()

        # First half
        r.feed(_make_pkt("S2C", pos[:10]))
        assert len(results) == 0

        # Second half
        r.feed(_make_pkt("S2C", pos[10:]))
        assert len(results) == 1
        assert results[0][1] == pos

    def test_fragmented_then_coalesced(self):
        """First segment is partial, second segment completes it + starts another."""
        r, results = self._make_reassembler()
        pos1 = _make_entity_position(entity_id=1)
        pos2 = _make_entity_position(entity_id=2)

        # First 10 bytes of pos1
        r.feed(_make_pkt("S2C", pos1[:10]))
        assert len(results) == 0

        # Rest of pos1 + all of pos2
        r.feed(_make_pkt("S2C", pos1[10:] + pos2))
        assert len(results) == 2

    def test_c2s_keepalive(self):
        """C2S KEEPALIVE (18 bytes) is correctly sized."""
        r, results = self._make_reassembler()
        keepalive = bytearray(18)
        keepalive[0] = 0x10
        keepalive[1] = 0x00
        r.feed(_make_pkt("C2S", bytes(keepalive)))
        assert len(results) == 1
        assert len(results[0][1]) == 18

    def test_stats_include_game_packets(self):
        """Stats show both TCP segments and game packets emitted."""
        r, _ = self._make_reassembler()
        pos1 = _make_entity_position(entity_id=1)
        pos2 = _make_entity_position(entity_id=2)

        r.feed(_make_pkt("S2C", pos1 + pos2))
        stats = r.stats()
        assert stats["S2C"]["tcp_segments"] == 1
        assert stats["S2C"]["game_packets"] == 2

    def test_mixed_directions_independent(self):
        """C2S and S2C buffers are independent with opcode_registry framing."""
        r, results = self._make_reassembler()

        # Fragment a C2S keepalive
        keepalive = bytearray(18)
        keepalive[0] = 0x10
        keepalive[1] = 0x00
        r.feed(_make_pkt("C2S", bytes(keepalive[:8])))
        assert len(results) == 0

        # Complete S2C entity position
        r.feed(_make_pkt("S2C", _make_entity_position()))
        assert len(results) == 1
        assert results[0][0] == "S2C"

        # Complete the C2S keepalive
        r.feed(_make_pkt("C2S", bytes(keepalive[8:])))
        assert len(results) == 2
        assert results[1][0] == "C2S"


# ---- Router + reassembly integration tests ----

class TestRouterReassembly:
    """Test ClientRouter with reassembly enabled."""

    def test_reassembly_enabled_by_default(self):
        router = ClientRouter()
        pos = _make_entity_position(entity_id=1, zone=5)
        pkt = _make_pkt("S2C", pos)
        key, decoded = router.process_packet(pkt)
        assert decoded is not None
        assert decoded["name"] == "ENTITY_POSITION"

    def test_coalesced_segment_yields_multiple_entities(self):
        """Two ENTITY_POSITION in one TCP segment both update state."""
        router = ClientRouter()
        pos1 = _make_entity_position(entity_id=100, x=500, y=600)
        pos2 = _make_entity_position(entity_id=200, x=700, y=800)
        merged = pos1 + pos2

        pkt = _make_pkt("S2C", merged)
        key, decoded = router.process_packet(pkt)

        # Both entities should be in the state
        session = router.clients[key]
        assert 100 in session.state.entities
        assert 200 in session.state.entities
        assert session.state.entities[100].x == 500
        assert session.state.entities[200].x == 700

        # Global state too
        assert 100 in router.global_state.entities
        assert 200 in router.global_state.entities

    def test_coalesced_despawn_plus_position(self):
        """ENTITY_DESPAWN + ENTITY_POSITION in one segment."""
        router = ClientRouter()

        # First, create entity 5
        pos = _make_entity_position(entity_id=5)
        router.process_packet(_make_pkt("S2C", pos, timestamp=1000.0))
        session = list(router.clients.values())[0]
        assert 5 in session.state.entities

        # Now despawn 5 + new position for 10 in one segment
        despawn = _make_entity_despawn(entity_id=5)
        pos10 = _make_entity_position(entity_id=10, x=999)
        merged = despawn + pos10

        router.process_packet(_make_pkt("S2C", merged, timestamp=1001.0))
        assert 5 not in session.state.entities
        assert 10 in session.state.entities

    def test_reassembly_disabled(self):
        """With reassemble=False, coalesced segment passes through as-is."""
        router = ClientRouter(reassemble=False)
        pos1 = _make_entity_position(entity_id=100)
        pos2 = _make_entity_position(entity_id=200)
        merged = pos1 + pos2

        pkt = _make_pkt("S2C", merged)
        key, decoded = router.process_packet(pkt)

        # Without reassembly, the 52-byte payload is decoded as one packet
        # (decode_packet reads first opcode only)
        session = router.clients[key]
        # Only entity 100 would be decoded (first 26 bytes)
        assert decoded is not None
        assert decoded["name"] == "ENTITY_POSITION"

    def test_reassembly_per_client(self):
        """Each client has its own reassembler."""
        router = ClientRouter()
        pos = _make_entity_position()

        # Client 1
        router.process_packet(_make_pkt("S2C", pos, dst_port=54321))
        # Client 2
        router.process_packet(_make_pkt("S2C", pos, dst_port=54322))

        assert len(router.clients) == 2
        for session in router.clients.values():
            assert session.reassembler is not None

    def test_stats_after_coalesced(self):
        """Per-client state should count each game packet, not each TCP segment."""
        router = ClientRouter()
        pos1 = _make_entity_position(entity_id=1)
        pos2 = _make_entity_position(entity_id=2)
        merged = pos1 + pos2

        pkt = _make_pkt("S2C", merged)
        router.process_packet(pkt)

        session = list(router.clients.values())[0]
        # Each game packet is processed separately
        assert session.state.total_packets == 2
        assert router.global_state.total_packets == 2
