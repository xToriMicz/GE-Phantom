"""Shared fixtures for GE_Phantom tests."""

import pytest
from src.sniffer.capture import GEPacket


@pytest.fixture
def sample_c2s_packet() -> GEPacket:
    """A sample client→server packet."""
    return GEPacket(
        timestamp=1000.0,
        direction="C2S",
        src_ip="192.168.1.100",
        dst_ip="103.55.55.138",
        src_port=54321,
        dst_port=7000,
        payload=b"\x01\x00\x0c\x00\x48\x65\x6c\x6c\x6f\x00\x00\x00",
        seq=1000,
        ack=2000,
        flags="PA",
    )


@pytest.fixture
def sample_s2c_packet() -> GEPacket:
    """A sample server→client packet."""
    return GEPacket(
        timestamp=1000.5,
        direction="S2C",
        src_ip="103.55.55.138",
        dst_ip="192.168.1.100",
        src_port=7000,
        dst_port=54321,
        payload=b"\x02\x00\x10\x00\xaa\xbb\xcc\xdd\x01\x02\x03\x04\x05\x06\x07\x08",
        seq=2000,
        ack=1012,
        flags="PA",
    )


@pytest.fixture
def item_drop_packets() -> list[GEPacket]:
    """Simulated S2C packets that might be item drops (same size, different data)."""
    base_payload = bytearray(b"\x05\x00\x18\x00")  # hypothetical opcode + length
    packets = []
    for i in range(5):
        payload = bytearray(base_payload)
        # item_id varies
        payload.extend(i.to_bytes(4, "little"))
        # x, y coordinates vary
        payload.extend((100 + i * 10).to_bytes(4, "little"))
        payload.extend((200 + i * 5).to_bytes(4, "little"))
        # instance_id varies
        payload.extend((9000 + i).to_bytes(4, "little"))
        # padding
        payload.extend(b"\x00" * 4)

        packets.append(GEPacket(
            timestamp=1000.0 + i * 0.5,
            direction="S2C",
            src_ip="103.55.55.138",
            dst_ip="192.168.1.100",
            src_port=7000,
            dst_port=54321,
            payload=bytes(payload),
            seq=2000 + i * 24,
            ack=1000,
            flags="PA",
        ))
    return packets


@pytest.fixture
def pick_item_packets() -> list[GEPacket]:
    """Simulated C2S packets that might be pick-up requests (similar structure)."""
    packets = []
    for i in range(5):
        payload = bytearray(b"\x06\x00\x08\x00")  # hypothetical opcode + length
        payload.extend((9000 + i).to_bytes(4, "little"))  # instance_id to pick up

        packets.append(GEPacket(
            timestamp=1001.0 + i * 0.5,
            direction="C2S",
            src_ip="192.168.1.100",
            dst_ip="103.55.55.138",
            src_port=54321,
            dst_port=7000,
            payload=bytes(payload),
            seq=1000 + i * 8,
            ack=2000,
            flags="PA",
        ))
    return packets
