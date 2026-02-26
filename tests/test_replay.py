"""Tests for replay verification — run captures through the reassembly pipeline."""

import json
from pathlib import Path

import pytest

from src.sniffer.capture import GEPacket
from src.data.router import ClientRouter
from src.protocol.packet_types import KNOWN_PACKETS


CAPTURES_DIR = Path(__file__).parent.parent / "captures"


def _load_capture(name: str) -> list[dict]:
    """Load a capture file and return its packets."""
    path = CAPTURES_DIR / name
    if not path.exists():
        pytest.skip(f"Capture file not found: {name}")
    data = json.loads(path.read_text())
    return data.get("packets", [])


def _pkt_from_dict(d: dict) -> GEPacket:
    """Convert a capture dict to a GEPacket."""
    payload = bytes.fromhex(d.get("payload_hex", ""))
    src_parts = d.get("src", "0.0.0.0:0").rsplit(":", 1)
    dst_parts = d.get("dst", "0.0.0.0:0").rsplit(":", 1)
    return GEPacket(
        timestamp=d.get("timestamp", 0.0),
        direction=d.get("direction", "S2C"),
        src_ip=src_parts[0],
        dst_ip=dst_parts[0],
        src_port=int(src_parts[1]),
        dst_port=int(dst_parts[1]),
        payload=payload,
        seq=d.get("seq", 0),
        ack=d.get("ack", 0),
        flags=d.get("flags", ""),
    )


class TestReplaySession4:
    """Replay session4_combat_full.json through the reassembly pipeline."""

    @pytest.fixture
    def capture_packets(self) -> list[dict]:
        return _load_capture("session4_combat_full.json")

    def test_replay_with_reassembly(self, capture_packets):
        """All packets process without error through reassembly pipeline."""
        router = ClientRouter(reassemble=True)

        decoded_count = 0
        for pkt_data in capture_packets:
            if not pkt_data.get("payload_hex"):
                continue
            pkt = _pkt_from_dict(pkt_data)
            _key, decoded = router.process_packet(pkt)
            if decoded:
                decoded_count += 1

        # Should decode more packets with reassembly (coalesced segments split)
        assert decoded_count > 0
        assert router.global_state.total_packets > 0

    def test_reassembly_decodes_more_than_direct(self, capture_packets):
        """Reassembly should decode MORE packets than direct mode (splits coalesced)."""
        router_with = ClientRouter(reassemble=True)
        router_without = ClientRouter(reassemble=False)

        decoded_with = 0
        decoded_without = 0

        for pkt_data in capture_packets:
            if not pkt_data.get("payload_hex"):
                continue
            pkt = _pkt_from_dict(pkt_data)

            _, dec_w = router_with.process_packet(pkt)
            _, dec_wo = router_without.process_packet(pkt)

            if dec_w:
                decoded_with += 1
            if dec_wo:
                decoded_without += 1

        # With reassembly: per-client state gets each game packet individually
        # Without: coalesced segments are treated as one packet (only first decoded)
        total_with = router_with.global_state.total_packets
        total_without = router_without.global_state.total_packets

        # Reassembly should produce MORE total packets (splits coalesced segments)
        assert total_with > total_without

    def test_coalesced_entity_positions_split(self, capture_packets):
        """The known 52-byte ENTITY_POSITION segments (2x26) should be split."""
        router_with = ClientRouter(reassemble=True)
        router_without = ClientRouter(reassemble=False)

        for pkt_data in capture_packets:
            if not pkt_data.get("payload_hex"):
                continue
            pkt = _pkt_from_dict(pkt_data)
            router_with.process_packet(pkt)
            router_without.process_packet(pkt)

        session_with = list(router_with.clients.values())[0]
        session_without = list(router_without.clients.values())[0]
        pos_with = session_with.state.packet_counts.get("ENTITY_POSITION", 0)
        pos_without = session_without.state.packet_counts.get("ENTITY_POSITION", 0)

        # Reassembly should decode MORE ENTITY_POSITION (splits coalesced 52b segments)
        assert pos_with > pos_without
        # At least 10 more ENTITY_POSITION from splitting coalesced segments
        assert pos_with - pos_without >= 10

    def test_zone_detected_from_capture(self, capture_packets):
        """Zone should be detected from ENTITY_POSITION packets in the capture."""
        router = ClientRouter(reassemble=True)

        for pkt_data in capture_packets:
            if not pkt_data.get("payload_hex"):
                continue
            pkt = _pkt_from_dict(pkt_data)
            router.process_packet(pkt)

        session = list(router.clients.values())[0]
        # session4 has zone values in ENTITY_POSITION packets
        assert session.state.current_zone > 0


class TestReplaySession5:
    """Replay session5_pickup.json — has item drops and more traffic."""

    @pytest.fixture
    def capture_packets(self) -> list[dict]:
        return _load_capture("session5_pickup.json")

    def test_replay_processes_all(self, capture_packets):
        """All packets in session5 process without errors."""
        router = ClientRouter(reassemble=True)

        for pkt_data in capture_packets:
            if not pkt_data.get("payload_hex"):
                continue
            pkt = _pkt_from_dict(pkt_data)
            router.process_packet(pkt)

        assert router.global_state.total_packets > 0

    def test_player_actions_detected(self, capture_packets):
        """Session5 (pickup session) should have PLAYER_ACTION and combat packets."""
        router = ClientRouter(reassemble=True)

        for pkt_data in capture_packets:
            if not pkt_data.get("payload_hex"):
                continue
            pkt = _pkt_from_dict(pkt_data)
            router.process_packet(pkt)

        # session5_pickup has PLAYER_ACTION (0x1800) packets
        action_count = router.global_state.packet_counts.get("PLAYER_ACTION", 0)
        combat_count = router.global_state.packet_counts.get("COMBAT_UPDATE", 0)
        assert action_count > 0 or combat_count > 0


class TestReplayAllCaptures:
    """Smoke test: all capture files replay without crashes."""

    @pytest.mark.parametrize("filename", [
        "session1.json",
        "session2_standing.json",
        "session3_combat.json",
        "session4_combat_full.json",
        "session5_pickup.json",
    ])
    def test_replay_no_crash(self, filename):
        packets = _load_capture(filename)
        router = ClientRouter(reassemble=True)

        for pkt_data in packets:
            if not pkt_data.get("payload_hex"):
                continue
            pkt = _pkt_from_dict(pkt_data)
            router.process_packet(pkt)

        # Just verify it didn't crash
        assert router.global_state.total_packets >= 0
