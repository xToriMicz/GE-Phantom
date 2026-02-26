"""
Protocol Packet Types — registry of discovered packet structures.

This file grows as we reverse-engineer the protocol. Start empty,
fill in as patterns are confirmed from captures.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum


# ---- Packet Header (hypothesis — to be confirmed from captures) ----
# Most MMO protocols use: [length:2][opcode:2][payload:N]
# GE might use: [opcode:2][length:2][payload:N] or similar
# We'll fill this in after first capture analysis.

HEADER_SIZE = 4  # placeholder — update after analysis


class Direction:
    C2S = "C2S"  # client → server
    S2C = "S2C"  # server → client


@dataclass
class PacketDef:
    """Definition of a known packet type."""
    opcode: int
    name: str
    direction: str
    description: str = ""
    size: int | None = None  # Expected size in bytes (None = variable)
    fields: list[FieldDef] = field(default_factory=list)
    confirmed: bool = False  # True once verified from multiple captures
    # Length field info for variable-size packets with embedded length
    length_field_offset: int | None = None  # offset of length u16 in packet
    length_field_includes_header: bool = True  # length value includes header bytes


@dataclass
class FieldDef:
    """A field within a packet."""
    name: str
    offset: int
    size: int
    type: str  # "u8", "u16le", "u16be", "u32le", "i32le", "f32", "str", "bytes"
    description: str = ""


# ---- Registry of discovered packets ----
# Opcodes use wire format (big-endian read of first 2 bytes).
# e.g. raw bytes [56 0c] → opcode 0x560c

KNOWN_PACKETS: dict[int, PacketDef] = {

    # ---- S2C: Server → Client (readable, not encrypted) ----

    0x0000: PacketDef(
        opcode=0x0000,
        name="HEARTBEAT",
        direction=Direction.S2C,
        size=6,
        description="Server heartbeat / keepalive",
        confirmed=True,
    ),

    0xe00c: PacketDef(
        opcode=0xe00c,
        name="ACK",
        direction=Direction.S2C,
        size=6,
        description="Server acknowledgement",
        confirmed=True,
    ),

    0x560c: PacketDef(
        opcode=0x560c,
        name="ENTITY_POSITION",
        direction=Direction.S2C,
        size=26,  # confirmed fixed — 52/346 were TCP-coalesced multi-packet segments
        description="Entity (monster/NPC) position update",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("tick", 6, 2, "u16le", "Server tick"),
            FieldDef("zone", 8, 2, "u16le", "Zone/map ID"),
            FieldDef("x", 10, 4, "i32le", "X coordinate (signed)"),
            FieldDef("y", 14, 4, "i32le", "Y coordinate (signed)"),
            FieldDef("state", 18, 4, "u32le", "Entity state flags"),
            FieldDef("speed", 22, 4, "f32", "Movement speed"),
        ],
        confirmed=True,
    ),

    0x490c: PacketDef(
        opcode=0x490c,
        name="ITEM_DROP",
        direction=Direction.S2C,
        size=57,
        description="Item dropped on ground — has item_id, position, owner name",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Drop entity ID"),
            FieldDef("x", 6, 4, "i32le", "X coordinate"),
            FieldDef("y", 10, 4, "i32le", "Y coordinate"),
            FieldDef("state", 14, 4, "u32le", "State flags"),
            FieldDef("item_id", 18, 4, "u32le", "Item type ID"),
            FieldDef("count", 22, 4, "u32le", "Stack count"),
            FieldDef("owner_eid", 26, 4, "u32le", "Owner entity ID"),
            FieldDef("zeros", 30, 6, "bytes", "Padding / unknown"),
            FieldDef("owner_name", 36, 21, "str", "Owner character name (null-terminated)"),
        ],
        confirmed=True,
    ),

    0x540c: PacketDef(
        opcode=0x540c,
        name="COMBAT_UPDATE",
        direction=Direction.S2C,
        size=38,  # confirmed fixed — 76=2x38, 63=38+25(EFFECT), 64=38+26(ENTITY_POS)
        description="Combat update — contains attack range as float32",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("attack_range", 30, 4, "f32", "Attack range (e.g. 850.0, 803.0)"),
        ],
        confirmed=True,
    ),

    0x3e0c: PacketDef(
        opcode=0x3e0c,
        name="MONSTER_SPAWN",
        direction=Direction.S2C,
        size=371,  # confirmed fixed — 742=2x371 coalesced
        description="Monster spawn with full data (type, level, position, stats)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
        ],
        confirmed=True,
    ),

    0x3f0c: PacketDef(
        opcode=0x3f0c,
        name="NPC_SPAWN",
        direction=Direction.S2C,
        size=371,
        description="NPC spawn (similar structure to monster spawn)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
        ],
        confirmed=False,
    ),

    0x400c: PacketDef(
        opcode=0x400c,
        name="OBJECT_SPAWN",
        direction=Direction.S2C,
        size=371,  # confirmed — 742=2x371 coalesced
        description="Object/structure spawn (similar to monster spawn)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
        ],
        confirmed=False,
    ),

    0x7a0c: PacketDef(
        opcode=0x7a0c,
        name="ENTITY_DESPAWN",
        direction=Direction.S2C,
        size=6,  # confirmed fixed — 32=6+26(ENTITY_POS) coalesced
        description="Entity despawn or death",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
        ],
        confirmed=True,
    ),

    0x680c: PacketDef(
        opcode=0x680c,
        name="TARGET_LINK",
        direction=Direction.S2C,
        size=15,
        description="Entity targeting — who attacks who",
        fields=[
            FieldDef("attacker_id", 2, 4, "u32le", "Attacker entity ID"),
            FieldDef("target_id", 6, 4, "u32le", "Target entity ID"),
        ],
        confirmed=True,
    ),

    0x660c: PacketDef(
        opcode=0x660c,
        name="BATCH_ENTITY_UPDATE",
        direction=Direction.S2C,
        size=None,  # variable: 123, 160, etc.
        description="Multi-entity position batch update",
        confirmed=True,
        length_field_offset=2,
        length_field_includes_header=True,
    ),

    0x5d0c: PacketDef(
        opcode=0x5d0c,
        name="PLAYER_POSITION",
        direction=Direction.S2C,
        size=None,  # variable: 46/69/192/195 — may batch multiple entries
        description="Player character positions using f64 coordinates",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Player entity ID"),
            FieldDef("x", 6, 8, "f64", "X coordinate (double)"),
            FieldDef("y", 14, 8, "f64", "Y coordinate (double)"),
        ],
        confirmed=True,
    ),

    0x430c: PacketDef(
        opcode=0x430c,
        name="ENTITY_EVENT",
        direction=Direction.S2C,
        size=7,  # confirmed fixed — 14=2x7, 378=7+371(MONSTER_SPAWN) coalesced
        description="Entity event trigger (animation, state change)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("event", 6, 1, "u8", "Event type"),
        ],
        confirmed=True,
    ),

    0xa50c: PacketDef(
        opcode=0xa50c,
        name="COMBAT_DATA",
        direction=Direction.S2C,
        size=None,  # variable: 23, 71, 94, etc. — framing unknown
        description="Combat data — appears during fights, details unknown",
        confirmed=False,
    ),

    0x4a0e: PacketDef(
        opcode=0x4a0e,
        name="EFFECT",
        direction=Direction.S2C,
        size=None,  # variable: 23, 25 — has length field
        description="Effects/animations — contains readable ASCII strings",
        confirmed=True,
        length_field_offset=2,
        length_field_includes_header=True,
    ),

    0x4b0c: PacketDef(
        opcode=0x4b0c,
        name="ITEM_EVENT",
        direction=Direction.S2C,
        size=None,  # variable: 6 or 84 — framing unknown
        description="Item-related event (pickup confirmation?)",
        confirmed=False,
    ),

    0x330e: PacketDef(
        opcode=0x330e,
        name="EFFECT_DATA",
        direction=Direction.S2C,
        size=None,  # variable: 357, 370, 371, 395 — follows EFFECT packets
        description="Effect data payload — often follows EFFECT (0x4a0e)",
        confirmed=False,
    ),

    # ---- C2S: Client → Server (encrypted — opcode readable, payload not) ----

    0x1000: PacketDef(
        opcode=0x1000,
        name="KEEPALIVE",
        direction=Direction.C2S,
        size=18,
        description="Client keepalive (~1/sec), encrypted payload",
        confirmed=True,
    ),

    0x1800: PacketDef(
        opcode=0x1800,
        name="PLAYER_ACTION",
        direction=Direction.C2S,
        size=26,
        description="Player action (attack/skill/pickup), encrypted payload",
        confirmed=True,
    ),
}


def decode_field(data: bytes, field_def: FieldDef) -> int | str | bytes:
    """Decode a single field from packet data."""
    raw = data[field_def.offset:field_def.offset + field_def.size]
    match field_def.type:
        case "u8":
            return raw[0]
        case "u16le":
            return int.from_bytes(raw, "little", signed=False)
        case "u16be":
            return int.from_bytes(raw, "big", signed=False)
        case "u32le":
            return int.from_bytes(raw, "little", signed=False)
        case "u32be":
            return int.from_bytes(raw, "big", signed=False)
        case "i32le":
            return int.from_bytes(raw, "little", signed=True)
        case "i32be":
            return int.from_bytes(raw, "big", signed=True)
        case "f32":
            return struct.unpack("<f", raw)[0]
        case "f64":
            return struct.unpack("<d", raw)[0]
        case "str":
            return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        case "bytes":
            return raw
        case _:
            return raw


def decode_packet(data: bytes) -> dict | None:
    """Decode a packet using the known packet registry.

    Opcodes are read as big-endian (wire format): raw [56 0c] → 0x560c.
    """
    if len(data) < HEADER_SIZE:
        return None

    opcode = int.from_bytes(data[:2], "big")
    if opcode not in KNOWN_PACKETS:
        return None

    pdef = KNOWN_PACKETS[opcode]
    result = {
        "opcode": opcode,
        "opcode_hex": f"0x{opcode:04x}",
        "name": pdef.name,
        "direction": pdef.direction,
        "size": len(data),
    }
    for f in pdef.fields:
        if f.offset + f.size <= len(data):
            result[f.name] = decode_field(data, f)
    return result


def register_packet(pdef: PacketDef) -> None:
    """Register a newly discovered packet type."""
    KNOWN_PACKETS[pdef.opcode] = pdef


def get_packet_size(data: bytes) -> int | None:
    """Determine the size of a game packet from its header bytes.

    Returns the total packet size (including header), or None if unknown.
    Requires at least 4 bytes in `data` (HEADER_SIZE).
    """
    if len(data) < HEADER_SIZE:
        return None

    opcode = int.from_bytes(data[:2], "big")
    pdef = KNOWN_PACKETS.get(opcode)
    if pdef is None:
        return None

    # Fixed-size packet
    if pdef.size is not None:
        return pdef.size

    # Variable-size with embedded length field
    if pdef.length_field_offset is not None:
        lf_end = pdef.length_field_offset + 2  # u16le length field
        if len(data) < lf_end:
            return None  # need more data to read length
        length = int.from_bytes(
            data[pdef.length_field_offset:lf_end], "little"
        )
        if pdef.length_field_includes_header:
            return length
        else:
            return length + HEADER_SIZE

    # Unknown framing
    return None
