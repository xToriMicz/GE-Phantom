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
        size=23,  # confirmed fixed — 46=2x23, 69=3x23 were TCP-coalesced
        description="Player character position using f64 coordinates",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Player entity ID"),
            FieldDef("x", 6, 8, "f64", "X coordinate (double)"),
            FieldDef("y", 14, 8, "f64", "Y coordinate (double)"),
            FieldDef("flags", 22, 1, "u8", "Movement/state flags"),
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
        size=23,  # confirmed fixed — 71=2x23+25(COMBAT_FOOTER), 94=3x23+25 were TCP-coalesced
        description="Combat data entry — multiple may be coalesced, followed by COMBAT_FOOTER",
        fields=[
            FieldDef("sub_index", 2, 1, "u8", "Entry index within batch (0, 1, 2)"),
            FieldDef("entity_id", 4, 4, "u32le", "Entity ID"),
        ],
        confirmed=True,
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
        size=6,  # confirmed fixed — 84=6+3x26(ENTITY_POSITION) were TCP-coalesced
        description="Item-related event (pickup confirmation?)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Item entity ID"),
        ],
        confirmed=True,
    ),

    0x330e: PacketDef(
        opcode=0x330e,
        name="EFFECT_DATA",
        direction=Direction.S2C,
        size=15,  # confirmed fixed — backward analysis: 18/24 validated boundaries at offset 15
        description="Effect data — entity effect trigger with param and type",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("effect_param", 6, 4, "u32le", "Effect parameter/value"),
            FieldDef("effect_type", 10, 1, "u8", "Effect type"),
            FieldDef("effect_data", 11, 4, "bytes", "Effect data (often zeros)"),
        ],
        confirmed=True,
    ),

    0x000c: PacketDef(
        opcode=0x000c,
        name="COMBAT_FOOTER",
        direction=Direction.S2C,
        size=25,  # confirmed fixed — appears after COMBAT_DATA batches (2+ entries)
        description="Combat batch summary/footer — follows sequence of COMBAT_DATA entries",
        confirmed=True,
    ),

    # ---- Discovered from live capture (2026-02-26) ----

    0x3d0c: PacketDef(
        opcode=0x3d0c,
        name="ENTITY_FLAG",
        direction=Direction.S2C,
        size=7,  # confirmed — 21=3x7 coalesced, gap analysis 8 occurrences
        description="Entity flag/status change",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("flag", 6, 1, "u8", "Flag value"),
        ],
        confirmed=True,
    ),

    0x460c: PacketDef(
        opcode=0x460c,
        name="PLAYER_SPAWN",
        direction=Direction.S2C,
        size=334,  # confirmed — all 4 occurrences = 334b
        description="Player character spawn (similar size to MONSTER_SPAWN 371b)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
        ],
        confirmed=True,
    ),

    0x530d: PacketDef(
        opcode=0x530d,
        name="ENTITY_STAT",
        direction=Direction.S2C,
        size=22,  # confirmed — gap=22 (31 occurrences), 66=3x22, 88=4x22
        description="Entity stat update (HP/MP/status)",
        fields=[
            FieldDef("entity_id", 2, 2, "u16le", "Entity ID"),
            FieldDef("stat_value", 10, 4, "u32le", "Stat value (HP/damage, 0-16679)"),
            FieldDef("speed_or_range", 18, 4, "f32", "Speed or range value (6.4-10.5)"),
        ],
        confirmed=True,
    ),

    0x540d: PacketDef(
        opcode=0x540d,
        name="ENTITY_ACTION",
        direction=Direction.S2C,
        size=8,  # confirmed — 80b = 8b + 72b(0x6d0c) coalesced
        description="Entity action trigger",
        confirmed=True,
    ),

    0x5c0c: PacketDef(
        opcode=0x5c0c,
        name="ENTITY_DATA",
        direction=Direction.S2C,
        size=270,  # confirmed fixed — 12/17 validated embeddings at offset 270
        description="Entity detailed data block (270 bytes, mostly zeros — sparse template)",
        fields=[
            FieldDef("data_id", 2, 4, "u32le", "Data/sequence ID (sequential)"),
            FieldDef("entity_ref", 10, 2, "u16le", "Referenced entity ID"),
            FieldDef("flags1", 19, 1, "u8", "Flags byte 1"),
            FieldDef("slot_a", 32, 1, "u8", "Slot/sub-type A (0 or 1)"),
            FieldDef("config_a", 37, 1, "u8", "Config byte A (0x80 flag)"),
            FieldDef("sub_count", 55, 1, "u8", "Sub-entry count (typically 6)"),
            FieldDef("type_flag", 76, 4, "u32le", "Type/category flag"),
            FieldDef("stat_a", 89, 4, "u32le", "Stat block A"),
            FieldDef("stat_b", 124, 1, "u8", "Stat block B (variant)"),
            FieldDef("config_b", 128, 4, "u32le", "Config block B (sparse)"),
            FieldDef("slot_b", 162, 1, "u8", "Slot/sub-type B (0 or 4)"),
            FieldDef("slot_c", 172, 1, "u8", "Slot/sub-type C (0 or 4)"),
            FieldDef("variant", 219, 1, "u8", "Variant byte (0 or 2)"),
            FieldDef("level_or_tier", 241, 2, "u16le", "Level/tier value (sparse, 0-992)"),
        ],
        confirmed=True,
    ),

    0x620c: PacketDef(
        opcode=0x620c,
        name="COMBAT_EFFECT",
        direction=Direction.S2C,
        size=44,  # confirmed fixed — 31/39 validated embeddings at offset 44
        description="Combat effect / damage display — contains source/target coords and damage",
        fields=[
            FieldDef("magic", 2, 2, "u16le", "Constant marker (0x545a)"),
            FieldDef("entity_id", 4, 4, "u32le", "Source entity ID"),
            FieldDef("x", 12, 4, "i32le", "Source X coordinate"),
            FieldDef("y", 16, 4, "i32le", "Source Y coordinate"),
            FieldDef("effect_type", 20, 1, "u8", "Effect sub-type (72=ranged, 119=melee)"),
            FieldDef("effect_value", 24, 4, "u32le", "Damage/effect magnitude"),
            FieldDef("target_entity_id", 30, 4, "u32le", "Target entity ID"),
            FieldDef("target_value", 36, 4, "u32le", "Target effect value"),
            FieldDef("sequence_id", 40, 4, "u32le", "Sequence counter"),
        ],
        confirmed=True,
    ),

    0x660e: PacketDef(
        opcode=0x660e,
        name="NAME_LABEL",
        direction=Direction.S2C,
        size=None,  # variable: 25, 73b — contains ASCII character names
        description="Name label for entity (contains readable character/NPC names)",
        confirmed=False,
    ),

    0x6b0c: PacketDef(
        opcode=0x6b0c,
        name="ENTITY_MOVE_PATH",
        direction=Direction.S2C,
        size=60,  # confirmed fixed — 7/8 = 60b, 105=60+45(coalesced); validated at offset 60
        description="Entity movement path — 3 waypoints: start, waypoint1, destination",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("start_x", 6, 4, "i32le", "Start X coordinate"),
            FieldDef("start_y", 10, 4, "i32le", "Start Y coordinate"),
            FieldDef("start_state", 14, 1, "u8", "Start state (30=idle, 81=walk, 119=run)"),
            FieldDef("wp1_x", 18, 4, "i32le", "Waypoint 1 X coordinate"),
            FieldDef("wp1_y", 22, 4, "i32le", "Waypoint 1 Y coordinate"),
            FieldDef("wp1_state", 26, 1, "u8", "Waypoint 1 state"),
            FieldDef("path_ref", 30, 2, "u16le", "Path reference/entity tag"),
            FieldDef("path_magic", 32, 4, "u32le", "Path constant (0x331ff130)"),
            FieldDef("speed1", 36, 4, "u32le", "Speed/distance value 1"),
            FieldDef("speed2", 40, 4, "u32le", "Speed/distance value 2"),
            FieldDef("delta", 44, 4, "u32le", "Time delta or segment length"),
            FieldDef("dest_x", 48, 4, "i32le", "Destination X coordinate"),
            FieldDef("dest_y", 52, 4, "i32le", "Destination Y coordinate"),
            FieldDef("dest_state", 56, 1, "u8", "Destination state"),
        ],
        confirmed=True,
    ),

    0x6c0c: PacketDef(
        opcode=0x6c0c,
        name="ENTITY_TICK",
        direction=Direction.S2C,
        size=11,  # confirmed — 33=3x11 coalesced (11b 6c0c + 11b 530d + noise)
        description="Entity tick/heartbeat update",
        confirmed=True,
    ),

    0x6d0c: PacketDef(
        opcode=0x6d0c,
        name="ENTITY_MOVE_DETAIL",
        direction=Direction.S2C,
        size=72,  # confirmed fixed — 4/5 = 72b, 160=72+88(coalesced); validated at offset 72
        description="Detailed entity movement — start/waypoint/dest coords + speed + heading",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("start_x", 6, 4, "i32le", "Start X coordinate"),
            FieldDef("start_y", 10, 4, "i32le", "Start Y coordinate"),
            FieldDef("start_state", 14, 1, "u8", "Start state (30=idle, 81=walk, 119=run)"),
            FieldDef("wp1_x", 18, 4, "i32le", "Waypoint 1 X coordinate"),
            FieldDef("wp1_y", 22, 4, "i32le", "Waypoint 1 Y coordinate"),
            FieldDef("wp1_state", 26, 1, "u8", "Waypoint 1 state"),
            FieldDef("distance", 30, 4, "u32le", "Distance or path cost"),
            FieldDef("chase_entity", 36, 4, "u32le", "Chase/follow entity ID"),
            FieldDef("speed", 44, 4, "f32", "Movement speed (0.0-7.0)"),
            FieldDef("heading", 56, 4, "f32", "Heading angle (8.8-10.4)"),
            FieldDef("dest_x", 60, 4, "i32le", "Destination X coordinate"),
            FieldDef("dest_y", 64, 4, "i32le", "Destination Y coordinate"),
            FieldDef("dest_state", 68, 1, "u8", "Destination state"),
        ],
        confirmed=True,
    ),

    0x750c: PacketDef(
        opcode=0x750c,
        name="ENTITY_BATCH_MOVE",
        direction=Direction.S2C,
        size=52,  # confirmed — offset2 always=52, byte[52]=0x330e(EFFECT_DATA follows)
        description="Entity batch movement update, often followed by EFFECT_DATA",
        fields=[
            FieldDef("length", 2, 2, "u16le", "Packet length (always 52)"),
        ],
        confirmed=True,
    ),

    0xd00e: PacketDef(
        opcode=0xd00e,
        name="SKILL_EFFECT",
        direction=Direction.S2C,
        size=50,  # confirmed — all 6 occurrences = 50b
        description="Skill visual effect data",
        confirmed=True,
    ),

    0x301e: PacketDef(
        opcode=0x301e,
        name="COMBAT_RESULT",
        direction=Direction.S2C,
        size=33,  # confirmed — all 2 occurrences = 33b
        description="Combat result / damage summary",
        confirmed=True,
    ),

    0x380c: PacketDef(
        opcode=0x380c,
        name="ZONE_DATA",
        direction=Direction.S2C,
        size=None,  # variable: uses embedded length field
        description="Zone or map data payload (large, variable with length field)",
        confirmed=True,
        length_field_offset=2,  # b[2:4] u16le = total packet size (verified: b24=757 matches embedding@757)
        length_field_includes_header=True,
    ),

    0x2f0c: PacketDef(
        opcode=0x2f0c,
        name="ENTITY_GROUP",
        direction=Direction.S2C,
        size=6,  # confirmed fixed — 5/7 = 6b; 66=6+60(MOVE_PATH), 130=6+72(MOVE_DETAIL)+52(BATCH)
        description="Entity group header — followed by child movement packets",
        fields=[
            FieldDef("group_id", 2, 4, "u32le", "Group/batch ID (always 4 observed)"),
        ],
        confirmed=True,
    ),

    0x1b15: PacketDef(
        opcode=0x1b15,
        name="INVENTORY_DATA",
        direction=Direction.S2C,
        size=None,  # variable: 127-1244b
        description="Inventory or item data payload",
        confirmed=False,
    ),

    0x0c15: PacketDef(
        opcode=0x0c15,
        name="CHARACTER_DATA",
        direction=Direction.S2C,
        size=None,  # variable: 44-306b
        description="Character data payload",
        confirmed=False,
    ),

    # ---- Discovered from unknown opcode analysis (2026-02-26) ----

    0x0064: PacketDef(
        opcode=0x0064,
        name="SYSTEM_PING",
        direction=Direction.S2C,
        size=8,  # confirmed — 6/6 identical segments, all 8 bytes
        description="System/server ping — all instances identical payload",
        fields=[
            FieldDef("param1", 2, 4, "u32le", "System parameter 1"),
            FieldDef("param2", 6, 2, "u16le", "System parameter 2"),
        ],
        confirmed=True,
    ),

    0x7b0c: PacketDef(
        opcode=0x7b0c,
        name="ENTITY_SPEED",
        direction=Direction.S2C,
        size=25,  # confirmed — 3/3 deduced from embedded boundaries
        description="Entity speed/parameter update — contains f32 speed values",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("speed1", 10, 4, "f32", "Speed value 1 (~7.5-8.0)"),
            FieldDef("speed2", 18, 4, "f32", "Speed value 2 (same as speed1)"),
        ],
        confirmed=True,
    ),

    0x5a0c: PacketDef(
        opcode=0x5a0c,
        name="ENTITY_STAT_HEADER",
        direction=Direction.S2C,
        size=10,  # confirmed — 11 instances: always 10b, followed by ENTITY_STAT
        description="Entity stat update prefix — always pairs with ENTITY_STAT (0x530d)",
        fields=[
            FieldDef("entity_ref", 2, 2, "u16le", "Entity reference ID"),
            FieldDef("zeros1", 4, 2, "bytes", "Always 0x0000"),
            FieldDef("param", 6, 2, "u16le", "Parameter value"),
            FieldDef("zeros2", 8, 2, "bytes", "Always 0x0000"),
        ],
        confirmed=True,
    ),

    0x5411: PacketDef(
        opcode=0x5411,
        name="ENTITY_PROFILE",
        direction=Direction.S2C,
        size=77,  # confirmed — 3/3 identical size, no boundary variation
        description="Entity profile/detail data (77 bytes)",
        fields=[
            FieldDef("entity_ref", 4, 4, "u32le", "Referenced entity ID"),
            FieldDef("profile_id", 13, 2, "u16le", "Profile/badge ID"),
        ],
        confirmed=True,
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
