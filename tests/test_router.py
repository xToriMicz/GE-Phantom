"""Tests for ClientRouter — multiclient packet routing."""

import struct
import time
import pytest

from src.sniffer.capture import GEPacket
from src.data.router import ClientRouter, ClientSession


def _make_packet(
    direction: str = "S2C",
    src_ip: str = "103.55.55.138",
    dst_ip: str = "192.168.1.100",
    src_port: int = 7000,
    dst_port: int = 54321,
    payload: bytes = b"\x00\x00",
    timestamp: float = 1000.0,
) -> GEPacket:
    """Helper to build a GEPacket."""
    return GEPacket(
        timestamp=timestamp,
        direction=direction,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        payload=payload,
        seq=0,
        ack=0,
        flags="PA",
    )


def _make_entity_position_payload(entity_id: int = 1, x: int = 100, y: int = 200) -> bytes:
    """Build a minimal ENTITY_POSITION (0x560c) payload, 26 bytes."""
    buf = bytearray(26)
    # opcode: 0x560c big-endian
    buf[0] = 0x56
    buf[1] = 0x0c
    # entity_id at offset 2, u32le
    struct.pack_into("<I", buf, 2, entity_id)
    # tick at 6, u16le
    struct.pack_into("<H", buf, 6, 1)
    # zone at 8, u16le
    struct.pack_into("<H", buf, 8, 1)
    # x at 10, i32le
    struct.pack_into("<i", buf, 10, x)
    # y at 14, i32le
    struct.pack_into("<i", buf, 14, y)
    # state at 18, u32le
    struct.pack_into("<I", buf, 18, 0)
    # speed at 22, f32
    struct.pack_into("<f", buf, 22, 100.0)
    return bytes(buf)


def _make_item_drop_payload(
    entity_id: int = 9001,
    item_id: int = 42,
    owner_name: str = "Kaja",
) -> bytes:
    """Build an ITEM_DROP (0x490c) payload, 57 bytes."""
    buf = bytearray(57)
    # opcode: 0x490c big-endian
    buf[0] = 0x49
    buf[1] = 0x0c
    # entity_id at 2, u32le
    struct.pack_into("<I", buf, 2, entity_id)
    # x at 6, i32le
    struct.pack_into("<i", buf, 6, 500)
    # y at 10, i32le
    struct.pack_into("<i", buf, 10, 600)
    # state at 14, u32le
    struct.pack_into("<I", buf, 14, 0)
    # item_id at 18, u32le
    struct.pack_into("<I", buf, 18, item_id)
    # count at 22, u32le
    struct.pack_into("<I", buf, 22, 1)
    # owner_eid at 26, u32le
    struct.pack_into("<I", buf, 26, 1001)
    # zeros at 30, 6 bytes (already zero)
    # owner_name at 36, 21 bytes null-terminated
    name_bytes = owner_name.encode("ascii")[:20]
    buf[36:36 + len(name_bytes)] = name_bytes
    return bytes(buf)


class TestClientIdentification:
    """Test that _identify correctly extracts client keys."""

    def test_c2s_uses_src(self):
        router = ClientRouter()
        pkt = _make_packet(direction="C2S", src_ip="192.168.1.100", src_port=54321)
        assert router._identify(pkt) == "192.168.1.100:54321"

    def test_s2c_uses_dst(self):
        router = ClientRouter()
        pkt = _make_packet(direction="S2C", dst_ip="192.168.1.100", dst_port=54321)
        assert router._identify(pkt) == "192.168.1.100:54321"

    def test_same_client_c2s_and_s2c(self):
        """C2S and S2C from the same connection should have the same key."""
        router = ClientRouter()
        c2s = _make_packet(
            direction="C2S",
            src_ip="192.168.1.100", src_port=54321,
            dst_ip="103.55.55.138", dst_port=7000,
        )
        s2c = _make_packet(
            direction="S2C",
            src_ip="103.55.55.138", src_port=7000,
            dst_ip="192.168.1.100", dst_port=54321,
        )
        assert router._identify(c2s) == router._identify(s2c)


class TestMulticlientRouting:
    """Test that packets from different clients are routed to separate states."""

    def test_two_clients_separate_states(self):
        router = ClientRouter()
        payload = _make_entity_position_payload(entity_id=1)

        # Client 1: port 54321
        pkt1 = _make_packet(dst_port=54321, payload=payload, timestamp=1000.0)
        key1, dec1 = router.process_packet(pkt1)

        # Client 2: port 54322
        pkt2 = _make_packet(dst_port=54322, payload=payload, timestamp=1001.0)
        key2, dec2 = router.process_packet(pkt2)

        assert key1 != key2
        assert len(router.clients) == 2

        # Each client's state should have 1 packet
        s1 = router.clients[key1]
        s2 = router.clients[key2]
        assert s1.state.total_packets == 1
        assert s2.state.total_packets == 1

        # Global should have both
        assert router.global_state.total_packets == 2

    def test_single_client_one_session(self):
        """All packets from the same endpoint go to one session."""
        router = ClientRouter()
        payload = _make_entity_position_payload()

        for i in range(5):
            pkt = _make_packet(dst_port=54321, payload=payload, timestamp=1000.0 + i)
            router.process_packet(pkt)

        assert len(router.clients) == 1
        session = list(router.clients.values())[0]
        assert session.state.total_packets == 5
        assert router.global_state.total_packets == 5

    def test_three_clients(self):
        router = ClientRouter()
        payload = _make_entity_position_payload()

        for port in [54321, 54322, 54323]:
            pkt = _make_packet(dst_port=port, payload=payload, timestamp=1000.0)
            router.process_packet(pkt)

        assert len(router.clients) == 3

    def test_global_state_aggregates_all(self):
        """Global state should contain data from all clients."""
        router = ClientRouter()

        # Client 1 sees entity 1
        pkt1 = _make_packet(
            dst_port=54321,
            payload=_make_entity_position_payload(entity_id=1, x=100),
            timestamp=1000.0,
        )
        router.process_packet(pkt1)

        # Client 2 sees entity 2
        pkt2 = _make_packet(
            dst_port=54322,
            payload=_make_entity_position_payload(entity_id=2, x=200),
            timestamp=1001.0,
        )
        router.process_packet(pkt2)

        # Global state has both entities
        assert 1 in router.global_state.entities
        assert 2 in router.global_state.entities

        # Each client only has their entity
        clients = list(router.clients.values())
        c1 = [c for c in clients if c.client_key.endswith(":54321")][0]
        c2 = [c for c in clients if c.client_key.endswith(":54322")][0]
        assert 1 in c1.state.entities
        assert 2 not in c1.state.entities
        assert 2 in c2.state.entities
        assert 1 not in c2.state.entities


class TestClientLabels:
    """Test auto-labeling and label upgrade from ITEM_DROP."""

    def test_default_labels(self):
        router = ClientRouter()
        payload = _make_entity_position_payload()

        pkt1 = _make_packet(dst_port=54321, payload=payload, timestamp=1000.0)
        pkt2 = _make_packet(dst_port=54322, payload=payload, timestamp=1001.0)
        router.process_packet(pkt1)
        router.process_packet(pkt2)

        labels = sorted(s.label for s in router.clients.values())
        assert labels == ["Client 1", "Client 2"]

    def test_label_upgrade_from_item_drop(self):
        router = ClientRouter()

        # First, send a generic packet to create the session
        pos_payload = _make_entity_position_payload()
        pkt1 = _make_packet(dst_port=54321, payload=pos_payload, timestamp=1000.0)
        router.process_packet(pkt1)

        session = list(router.clients.values())[0]
        assert session.label == "Client 1"

        # Now send an ITEM_DROP with owner_name "Kaja"
        drop_payload = _make_item_drop_payload(owner_name="Kaja")
        pkt2 = _make_packet(dst_port=54321, payload=drop_payload, timestamp=1001.0)
        router.process_packet(pkt2)

        assert session.label == "Kaja"

    def test_label_no_double_upgrade(self):
        """Once upgraded, label should not change again."""
        router = ClientRouter()

        drop1 = _make_item_drop_payload(owner_name="Kaja")
        pkt1 = _make_packet(dst_port=54321, payload=drop1, timestamp=1000.0)
        router.process_packet(pkt1)

        session = list(router.clients.values())[0]
        assert session.label == "Kaja"

        # Another drop with different owner should NOT change label
        drop2 = _make_item_drop_payload(owner_name="Scoutz")
        pkt2 = _make_packet(dst_port=54321, payload=drop2, timestamp=1001.0)
        router.process_packet(pkt2)

        assert session.label == "Kaja"


class TestClientCallbacks:
    """Test client discovery callbacks."""

    def test_on_client_discovered(self):
        router = ClientRouter()
        discovered = []
        router.on_client_discovered(lambda s: discovered.append(s.client_key))

        payload = _make_entity_position_payload()
        pkt1 = _make_packet(dst_port=54321, payload=payload, timestamp=1000.0)
        pkt2 = _make_packet(dst_port=54322, payload=payload, timestamp=1001.0)
        pkt3 = _make_packet(dst_port=54321, payload=payload, timestamp=1002.0)  # same client

        router.process_packet(pkt1)
        router.process_packet(pkt2)
        router.process_packet(pkt3)

        assert len(discovered) == 2  # only 2 unique clients


class TestGetActiveClients:
    """Test client listing and index lookup."""

    def test_sorted_by_last_seen(self):
        router = ClientRouter()
        payload = _make_entity_position_payload()

        # Client A seen at t=1000, Client B at t=1001
        pkt_a = _make_packet(dst_port=54321, payload=payload, timestamp=1000.0)
        pkt_b = _make_packet(dst_port=54322, payload=payload, timestamp=1001.0)
        router.process_packet(pkt_a)
        router.process_packet(pkt_b)

        clients = router.get_active_clients()
        assert clients[0].client_key.endswith(":54322")  # most recent first

    def test_get_client_by_index(self):
        router = ClientRouter()
        payload = _make_entity_position_payload()

        pkt1 = _make_packet(dst_port=54321, payload=payload, timestamp=1000.0)
        pkt2 = _make_packet(dst_port=54322, payload=payload, timestamp=1001.0)
        router.process_packet(pkt1)
        router.process_packet(pkt2)

        assert router.get_client_by_index(1) is not None
        assert router.get_client_by_index(2) is not None
        assert router.get_client_by_index(3) is None
        assert router.get_client_by_index(0) is None

    def test_my_chars_passed_to_states(self):
        router = ClientRouter(my_chars=["Kaja", "Scoutz"])
        payload = _make_entity_position_payload()

        pkt = _make_packet(dst_port=54321, payload=payload, timestamp=1000.0)
        router.process_packet(pkt)

        session = list(router.clients.values())[0]
        assert session.state.my_chars == {"kaja", "scoutz"}
        assert router.global_state.my_chars == {"kaja", "scoutz"}
