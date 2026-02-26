"""Tests for TCP stream reassembler."""

from src.sniffer.capture import GEPacket
from src.sniffer.stream import TCPStreamReassembler


def _make_pkt(direction: str, payload: bytes) -> GEPacket:
    return GEPacket(
        timestamp=1000.0,
        direction=direction,
        src_ip="192.168.1.100" if direction == "C2S" else "103.55.55.138",
        dst_ip="103.55.55.138" if direction == "C2S" else "192.168.1.100",
        src_port=54321 if direction == "C2S" else 7000,
        dst_port=7000 if direction == "C2S" else 54321,
        payload=payload,
        seq=0,
        ack=0,
        flags="PA",
    )


def test_passthrough_no_framing():
    """Without framing, raw TCP segments pass through as-is."""
    reassembler = TCPStreamReassembler()
    results = []
    reassembler.on_game_packet(lambda d, data: results.append((d, data)))

    reassembler.feed(_make_pkt("S2C", b"\x01\x02\x03\x04"))
    assert len(results) == 1
    assert results[0] == ("S2C", b"\x01\x02\x03\x04")


def test_length_prefix_le16():
    """Test little-endian u16 length prefix framing."""
    reassembler = TCPStreamReassembler()
    reassembler.set_framing(
        "length_prefix_le16",
        length_offset=2,
        length_size=2,
        endian="little",
        includes_header=True,
        header_size=4,
    )

    results = []
    reassembler.on_game_packet(lambda d, data: results.append((d, data)))

    # Complete packet: [opcode:2][length:2][payload]
    # length includes header: total = 8 bytes
    packet = b"\x05\x00\x08\x00\xaa\xbb\xcc\xdd"
    reassembler.feed(_make_pkt("S2C", packet))

    assert len(results) == 1
    assert results[0][1] == packet


def test_fragmented_packet():
    """Test packet split across two TCP segments."""
    reassembler = TCPStreamReassembler()
    reassembler.set_framing(
        "length_prefix_le16",
        length_offset=2,
        length_size=2,
        endian="little",
        includes_header=True,
        header_size=4,
    )

    results = []
    reassembler.on_game_packet(lambda d, data: results.append((d, data)))

    # Full packet is 8 bytes, split into 2 TCP segments
    reassembler.feed(_make_pkt("S2C", b"\x05\x00\x08\x00\xaa"))
    assert len(results) == 0  # Not complete yet

    reassembler.feed(_make_pkt("S2C", b"\xbb\xcc\xdd"))
    assert len(results) == 1  # Now complete


def test_multiple_packets_in_one_segment():
    """Test two game packets merged in one TCP segment."""
    reassembler = TCPStreamReassembler()
    reassembler.set_framing(
        "length_prefix_le16",
        length_offset=2,
        length_size=2,
        endian="little",
        includes_header=True,
        header_size=4,
    )

    results = []
    reassembler.on_game_packet(lambda d, data: results.append((d, data)))

    # Two 8-byte packets merged
    merged = b"\x05\x00\x08\x00\xaa\xbb\xcc\xdd" + b"\x06\x00\x08\x00\x11\x22\x33\x44"
    reassembler.feed(_make_pkt("S2C", merged))

    assert len(results) == 2


def test_separate_directions():
    """Test that C2S and S2C have independent buffers."""
    reassembler = TCPStreamReassembler()
    reassembler.set_framing(
        "length_prefix_le16",
        length_offset=2,
        length_size=2,
        endian="little",
        includes_header=True,
        header_size=4,
    )

    results = []
    reassembler.on_game_packet(lambda d, data: results.append((d, data)))

    # Fragment C2S
    reassembler.feed(_make_pkt("C2S", b"\x01\x00\x08\x00"))

    # Complete S2C (should not be affected by C2S buffer)
    reassembler.feed(_make_pkt("S2C", b"\x02\x00\x08\x00\xaa\xbb\xcc\xdd"))
    assert len(results) == 1
    assert results[0][0] == "S2C"

    # Complete C2S
    reassembler.feed(_make_pkt("C2S", b"\xee\xff\x00\x11"))
    assert len(results) == 2
    assert results[1][0] == "C2S"


def test_stats():
    reassembler = TCPStreamReassembler()
    reassembler.feed(_make_pkt("S2C", b"\x01\x02\x03"))
    stats = reassembler.stats()
    assert stats["S2C"]["tcp_segments"] == 1
    assert stats["C2S"]["tcp_segments"] == 0
