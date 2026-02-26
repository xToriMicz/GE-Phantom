"""Tests for zone tracking in RadarState."""

import struct
import pytest

from src.sniffer.capture import GEPacket
from src.data.state import RadarState, ZoneTransition


def _make_entity_position_pkt(
    entity_id: int = 1,
    zone: int = 3,
    x: int = 100,
    y: int = 200,
    timestamp: float = 1000.0,
) -> GEPacket:
    """Build a GEPacket containing ENTITY_POSITION (0x560c)."""
    buf = bytearray(26)
    buf[0] = 0x56
    buf[1] = 0x0c
    struct.pack_into("<I", buf, 2, entity_id)
    struct.pack_into("<H", buf, 6, 1)  # tick
    struct.pack_into("<H", buf, 8, zone)
    struct.pack_into("<i", buf, 10, x)
    struct.pack_into("<i", buf, 14, y)
    struct.pack_into("<I", buf, 18, 0)
    struct.pack_into("<f", buf, 22, 100.0)
    return GEPacket(
        timestamp=timestamp,
        direction="S2C",
        src_ip="103.55.55.138",
        dst_ip="192.168.1.100",
        src_port=7000,
        dst_port=54321,
        payload=bytes(buf),
        seq=0,
        ack=0,
        flags="PA",
    )


class TestZoneTracking:
    """Test zone tracking in RadarState."""

    def test_initial_zone_is_zero(self):
        state = RadarState()
        assert state.current_zone == 0

    def test_zone_set_from_entity_position(self):
        state = RadarState()
        pkt = _make_entity_position_pkt(entity_id=1, zone=5)
        state.process_packet(pkt)
        assert state.current_zone == 5

    def test_zone_change_recorded(self):
        """Zone transition is recorded when zone changes."""
        state = RadarState()

        # First zone (no transition — coming from 0)
        pkt1 = _make_entity_position_pkt(entity_id=1, zone=3, timestamp=1000.0)
        state.process_packet(pkt1)
        assert state.current_zone == 3
        assert len(state.zone_transitions) == 0  # first zone, no prior

        # Same zone — no transition
        pkt2 = _make_entity_position_pkt(entity_id=2, zone=3, timestamp=1001.0)
        state.process_packet(pkt2)
        assert len(state.zone_transitions) == 0

        # Zone change!
        pkt3 = _make_entity_position_pkt(entity_id=1, zone=7, timestamp=1002.0)
        state.process_packet(pkt3)
        assert state.current_zone == 7
        assert len(state.zone_transitions) == 1

        tr = state.zone_transitions[0]
        assert tr.from_zone == 3
        assert tr.to_zone == 7
        assert tr.timestamp == 1002.0

    def test_multiple_zone_transitions(self):
        state = RadarState()

        # Zone 1
        state.process_packet(_make_entity_position_pkt(zone=1, timestamp=1000.0))
        # Zone 2
        state.process_packet(_make_entity_position_pkt(zone=2, timestamp=1001.0))
        # Zone 5
        state.process_packet(_make_entity_position_pkt(zone=5, timestamp=1002.0))

        assert state.current_zone == 5
        assert len(state.zone_transitions) == 2
        assert state.zone_transitions[0].from_zone == 1
        assert state.zone_transitions[0].to_zone == 2
        assert state.zone_transitions[1].from_zone == 2
        assert state.zone_transitions[1].to_zone == 5

    def test_zone_zero_ignored(self):
        """Zone 0 should not trigger a transition."""
        state = RadarState()
        state.process_packet(_make_entity_position_pkt(zone=3, timestamp=1000.0))
        state.process_packet(_make_entity_position_pkt(zone=0, timestamp=1001.0))
        assert state.current_zone == 3
        assert len(state.zone_transitions) == 0

    def test_zone_stored_in_character_info(self):
        """CharacterInfo should also track zone per entity."""
        state = RadarState()
        pkt = _make_entity_position_pkt(entity_id=42, zone=8)
        state.process_packet(pkt)

        assert 42 in state.characters
        assert state.characters[42].zone == 8

    def test_zone_change_callback(self):
        """The zone_change event is emitted via callbacks."""
        state = RadarState()
        events = []
        state.on_update(lambda event_type, data: events.append((event_type, data)))

        state.process_packet(_make_entity_position_pkt(zone=3, timestamp=1000.0))
        state.process_packet(_make_entity_position_pkt(zone=7, timestamp=1001.0))

        zone_events = [(t, d) for t, d in events if t == "zone_change"]
        assert len(zone_events) == 1
        assert zone_events[0][1]["from_zone"] == 3
        assert zone_events[0][1]["to_zone"] == 7
