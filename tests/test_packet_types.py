"""Tests for protocol packet type registry."""

import struct

from src.protocol.packet_types import (
    PacketDef, FieldDef, Direction,
    decode_field, decode_packet, register_packet, get_packet_size, KNOWN_PACKETS,
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


# ---- get_packet_size tests ----

def test_get_packet_size_fixed():
    """Fixed-size packets return their known size."""
    # HEARTBEAT (0x0000) = 6 bytes
    assert get_packet_size(b"\x00\x00\x00\x00") == 6
    # ENTITY_POSITION (0x560c) = 26 bytes
    assert get_packet_size(b"\x56\x0c\x00\x00") == 26
    # COMBAT_UPDATE (0x540c) = 38 bytes
    assert get_packet_size(b"\x54\x0c\x00\x00") == 38
    # MONSTER_SPAWN (0x3e0c) = 371 bytes
    assert get_packet_size(b"\x3e\x0c\x00\x00") == 371
    # ENTITY_EVENT (0x430c) = 7 bytes
    assert get_packet_size(b"\x43\x0c\x00\x00") == 7
    # ENTITY_DESPAWN (0x7a0c) = 6 bytes
    assert get_packet_size(b"\x7a\x0c\x00\x00") == 6
    # TARGET_LINK (0x680c) = 15 bytes
    assert get_packet_size(b"\x68\x0c\x00\x00") == 15


def test_get_packet_size_length_field():
    """Packets with length field read size from bytes [2:4] LE."""
    # BATCH_ENTITY_UPDATE (0x660c) with length=123
    header = bytearray(4)
    header[0] = 0x66
    header[1] = 0x0c
    struct.pack_into("<H", header, 2, 123)
    assert get_packet_size(bytes(header)) == 123

    # EFFECT (0x4a0e) with length=25
    header = bytearray(4)
    header[0] = 0x4a
    header[1] = 0x0e
    struct.pack_into("<H", header, 2, 25)
    assert get_packet_size(bytes(header)) == 25


def test_get_packet_size_unknown_opcode():
    """Unknown opcodes return None."""
    assert get_packet_size(b"\xff\xff\x00\x00") is None


def test_get_packet_size_too_short():
    """Less than HEADER_SIZE bytes returns None."""
    assert get_packet_size(b"\x56") is None
    assert get_packet_size(b"\x56\x0c") is None


def test_get_packet_size_variable_no_length_field():
    """Variable-size packet without length field returns None."""
    # NAME_LABEL (0x660e) has no length field
    assert get_packet_size(b"\x66\x0e\x00\x00") is None


def test_get_packet_size_combat_data_fixed():
    """COMBAT_DATA (0xa50c) is now confirmed fixed at 23 bytes."""
    assert get_packet_size(b"\xa5\x0c\x00\x9a") == 23


def test_get_packet_size_combat_footer_fixed():
    """COMBAT_FOOTER (0x000c) is fixed at 25 bytes."""
    assert get_packet_size(b"\x00\x0c\x19\x00") == 25


def test_get_packet_size_player_position_fixed():
    """PLAYER_POSITION (0x5d0c) is now confirmed fixed at 23 bytes."""
    assert get_packet_size(b"\x5d\x0c\x00\x00") == 23


def test_get_packet_size_item_event_fixed():
    """ITEM_EVENT (0x4b0c) is now confirmed fixed at 6 bytes."""
    assert get_packet_size(b"\x4b\x0c\x00\x00") == 6
