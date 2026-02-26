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
        size=None,  # 26b base, also seen 52, 149, 346
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
        size=None,  # 38b base, also seen 63, 64, 76, 116
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
        size=None,  # 371b typical, also 396, 738, 742
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
        size=None,  # 371 or 742
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
        size=None,  # 6, 32, or 58 bytes
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
        size=None,  # 123, 160, 175, 186, 217
        description="Multi-entity position batch update",
        confirmed=True,
    ),

    0x5d0c: PacketDef(
        opcode=0x5d0c,
        name="PLAYER_POSITION",
        direction=Direction.S2C,
        size=None,  # variable
        description="Player character positions (contains floats/doubles)",
        confirmed=True,
    ),

    0x430c: PacketDef(
        opcode=0x430c,
        name="ENTITY_EVENT",
        direction=Direction.S2C,
        size=None,  # 7b base, also 14, 33, 39, 59, 378
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
        size=None,  # 23, 71, 94, 97, 112, 120, 132, 283, 287, 535
        description="Combat data — appears during fights, details unknown",
        confirmed=False,
    ),

    0x4a0e: PacketDef(
        opcode=0x4a0e,
        name="EFFECT",
        direction=Direction.S2C,
        size=None,  # 25, 50, 368-496
        description="Effects/animations — contains readable ASCII strings",
        confirmed=True,
    ),

    0x4b0c: PacketDef(
        opcode=0x4b0c,
        name="ITEM_EVENT",
        direction=Direction.S2C,
        size=None,  # 6 or 84 bytes
        description="Item-related event (pickup confirmation?)",
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
