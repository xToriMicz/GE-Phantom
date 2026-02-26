"""Tests for protocol packet type registry."""

from src.protocol.packet_types import (
    PacketDef, FieldDef, Direction,
    decode_field, decode_packet, register_packet, KNOWN_PACKETS,
)


def test_decode_field_u8():
    f = FieldDef("test", 0, 1, "u8")
    assert decode_field(b"\xff", f) == 255


def test_decode_field_u16le():
    f = FieldDef("test", 0, 2, "u16le")
    assert decode_field(b"\x01\x00", f) == 1
    assert decode_field(b"\x00\x01", f) == 256


def test_decode_field_u32le():
    f = FieldDef("test", 0, 4, "u32le")
    assert decode_field(b"\x01\x00\x00\x00", f) == 1


def test_decode_field_i32le():
    f = FieldDef("test", 0, 4, "i32le")
    assert decode_field(b"\xff\xff\xff\xff", f) == -1


def test_decode_field_str():
    f = FieldDef("test", 0, 10, "str")
    assert decode_field(b"hello\x00\x00\x00\x00\x00", f) == "hello"


def test_decode_field_with_offset():
    f = FieldDef("test", 4, 2, "u16le")
    data = b"\x00\x00\x00\x00\x42\x00"
    assert decode_field(data, f) == 0x42


def test_register_and_decode():
    # Register a test packet
    pdef = PacketDef(
        opcode=0x9999,
        name="TEST_PKT",
        direction=Direction.S2C,
        fields=[
            FieldDef("value_a", 4, 2, "u16le"),
            FieldDef("value_b", 6, 2, "u16le"),
        ],
    )
    register_packet(pdef)

    # Decode it
    data = b"\x99\x99\x08\x00\x0a\x00\x14\x00"  # opcode=0x9999, then values
    result = decode_packet(data)

    assert result is not None
    assert result["name"] == "TEST_PKT"
    assert result["value_a"] == 10
    assert result["value_b"] == 20

    # Cleanup
    del KNOWN_PACKETS[0x9999]


def test_decode_unknown_packet():
    result = decode_packet(b"\xff\xfe\x04\x00")
    assert result is None


def test_decode_too_short():
    result = decode_packet(b"\x01")
    assert result is None
