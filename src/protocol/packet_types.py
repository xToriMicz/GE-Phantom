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
        description="Combat update — attack range + entity position + movement state",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("tick", 10, 4, "u32le", "Tick/sequence (range 5228-5392)"),
            FieldDef("zone", 14, 4, "u32le", "Zone ID (range 215437-215440)"),
            FieldDef("x", 18, 4, "i32le", "Entity X coordinate"),
            FieldDef("y", 22, 4, "i32le", "Entity Y coordinate"),
            FieldDef("state", 26, 4, "u32le", "Movement state (30=idle, 81=walk, 119=run)"),
            FieldDef("attack_range", 30, 4, "f32", "Attack range (539-1000, per character class)"),
            FieldDef("combat_flags", 34, 4, "u32le", "Combat flags (0, 2, or 4)"),
        ],
        confirmed=True,
    ),

    0x3e0c: PacketDef(
        opcode=0x3e0c,
        name="MONSTER_SPAWN",
        direction=Direction.S2C,
        size=371,  # confirmed fixed — 742=2x371 coalesced
        description="Monster spawn with position at offsets 15-22 (i32le x,y)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("x", 15, 4, "i32le", "Spawn X coordinate (confirmed 100% match)"),
            FieldDef("y", 19, 4, "i32le", "Spawn Y coordinate (confirmed 100% match)"),
            FieldDef("spawn_state", 23, 2, "u16le", "Spawn state/flags"),
        ],
        confirmed=True,
    ),

    0x3f0c: PacketDef(
        opcode=0x3f0c,
        name="ENTITY_SPAWN_B",
        direction=Direction.S2C,
        size=371,  # confirmed — all instances 371b
        description="Entity spawn group B (same position layout as MONSTER_SPAWN)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("x", 15, 4, "i32le", "Spawn X coordinate"),
            FieldDef("y", 19, 4, "i32le", "Spawn Y coordinate"),
            FieldDef("spawn_state", 23, 2, "u16le", "Spawn state/flags"),
        ],
        confirmed=True,
    ),

    0x400c: PacketDef(
        opcode=0x400c,
        name="OBJECT_SPAWN",
        direction=Direction.S2C,
        size=371,  # confirmed — 742=2x371 coalesced
        description="Object/structure spawn (same position layout as MONSTER_SPAWN)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("x", 15, 4, "i32le", "Spawn X coordinate"),
            FieldDef("y", 19, 4, "i32le", "Spawn Y coordinate"),
            FieldDef("spawn_state", 23, 2, "u16le", "Spawn state/flags"),
        ],
        confirmed=True,
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
        name="ENTITY_STATE_F64",
        direction=Direction.S2C,
        size=23,  # confirmed fixed — 46=2x23, 69=3x23 were TCP-coalesced
        description="Entity state data (f64 values, NOT position). Flag 0x00=player, 0x01=other",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("value_a", 6, 8, "f64", "State value A (unknown purpose)"),
            FieldDef("value_b", 14, 8, "f64", "State value B (unknown purpose)"),
            FieldDef("entity_flag", 22, 1, "u8", "Entity type flag (0=player, 1=other)"),
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

    0x5f0c: PacketDef(
        opcode=0x5f0c,
        name="ENTITY_LINK",
        direction=Direction.S2C,
        size=24,  # confirmed — boundary deduced: chain=[ENTITY_BATCH_MOVE@24]
        description="Entity link/association (entity family, 24 bytes)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
        ],
        confirmed=True,
    ),

    0x630c: PacketDef(
        opcode=0x630c,
        name="ENTITY_SYNC",
        direction=Direction.S2C,
        size=14,  # confirmed — solo segment exactly 14 bytes
        description="Entity sync/update (entity family, 14 bytes)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
        ],
        confirmed=True,
    ),

    0x580c: PacketDef(
        opcode=0x580c,
        name="ENTITY_LABEL",
        direction=Direction.S2C,
        size=None,  # variable — contains null-terminated character names
        description="Entity name/label (contains character name string, possibly Thai)",
        confirmed=True,
        length_field_offset=2,  # b[2:4] u16le = total packet size (verified: 26=26)
        length_field_includes_header=True,
    ),

    0xca0c: PacketDef(
        opcode=0xca0c,
        name="SKILL_CAST",
        direction=Direction.S2C,
        size=None,  # variable — contains null-terminated skill names
        description="Skill cast with position and skill name (e.g. SKl_Resuscitation)",
        fields=[
            FieldDef("x", 4, 4, "i32le", "X coordinate"),
            FieldDef("y", 8, 4, "i32le", "Y coordinate"),
            FieldDef("param", 12, 4, "u32le", "Skill parameter"),
            FieldDef("skill_name", 16, 18, "str", "Skill name (null-terminated)"),
        ],
        confirmed=True,
        length_field_offset=2,  # b[2:4] u16le = total packet size (verified: 34=34, 3x coalesced)
        length_field_includes_header=True,
    ),

    # ---- Discovered from remaining unknowns analysis (2026-02-27) ----

    0x520c: PacketDef(
        opcode=0x520c,
        name="PLAYER_NAME",
        direction=Direction.S2C,
        size=26,  # 1 instance, follows PLAYER_SPAWN — contains "CrusaderDaria"
        description="Player name label — character name string after PLAYER_SPAWN",
        fields=[
            FieldDef("param", 2, 2, "u16le", "Parameter (0x019b)"),
            FieldDef("ref_opcode", 4, 2, "u16be", "Embedded ref (0x0c15 CHARACTER_DATA)"),
            FieldDef("zeros", 6, 2, "bytes", "Padding"),
            FieldDef("name", 8, 13, "str", "Character name (null-terminated)"),
            FieldDef("flags", 22, 1, "u8", "Name flags"),
            FieldDef("suffix", 23, 3, "bytes", "Suffix data"),
        ],
        confirmed=False,
    ),

    0x1215: PacketDef(
        opcode=0x1215,
        name="SESSION_PARAM",
        direction=Direction.S2C,
        size=9,  # 1 instance — all zeros payload
        description="Session/zone parameter (9 bytes, mostly zeros)",
        confirmed=False,
    ),

    0xfbee: PacketDef(
        opcode=0xfbee,
        name="SYSTEM_BLOCK_A",
        direction=Direction.S2C,
        size=268,  # 1 instance — large static data, follows HEARTBEAT
        description="System data block (268 bytes, sparse — similar structure to 0x6cf1)",
        confirmed=False,
    ),

    0xbe14: PacketDef(
        opcode=0xbe14,
        name="ENTITY_DETAIL_B",
        direction=Direction.S2C,
        size=108,  # 1 instance — 3×36-byte sub-entries with sequential sub-opcodes (bf14, c014)
        description="Entity detail batch — 36-byte entries with coords/speed, follows ENTITY_BATCH_MOVE",
        fields=[
            FieldDef("count_marker", 12, 2, "u16le", "Entry count marker (0x02)"),
            FieldDef("speed", 20, 4, "f32", "Speed/range value (~9.08)"),
            FieldDef("x", 24, 4, "i32le", "X coordinate"),
            FieldDef("y", 28, 4, "i32le", "Y coordinate"),
            FieldDef("state", 32, 4, "u32le", "Movement state"),
        ],
        confirmed=False,
    ),

    0x5a54: PacketDef(
        opcode=0x5a54,
        name="COMBAT_TRIGGER",
        direction=Direction.S2C,
        size=42,  # 1 instance — has coords, entity refs, state byte 0x77 (run)
        description="Combat trigger with entity positions and action references",
        fields=[
            FieldDef("entity_ref", 2, 2, "u16le", "Entity reference"),
            FieldDef("x", 10, 4, "i32le", "X coordinate (signed)"),
            FieldDef("y", 14, 4, "i32le", "Y coordinate (signed)"),
            FieldDef("state", 18, 1, "u8", "Movement state (0x77=run)"),
            FieldDef("entity_id", 22, 4, "u32le", "Entity ID"),
        ],
        confirmed=False,
    ),

    0xba14: PacketDef(
        opcode=0xba14,
        name="ENTITY_NOTIFY",
        direction=Direction.S2C,
        size=21,  # 1 instance — 0xxx14 entity family, follows HEARTBEAT
        description="Entity notification — small entity update (21 bytes)",
        fields=[
            FieldDef("zeros", 2, 6, "bytes", "Padding (6 zero bytes)"),
            FieldDef("value", 8, 4, "u32le", "Notification value"),
        ],
        confirmed=False,
    ),

    0xf0b7: PacketDef(
        opcode=0xf0b7,
        name="SYSTEM_ECHO",
        direction=Direction.S2C,
        size=13,  # 1 instance — b[0:4] == b[8:12] repeating pattern
        description="System echo — 4-byte header pattern repeats at offset 8",
        confirmed=False,
    ),

    0x8114: PacketDef(
        opcode=0x8114,
        name="ENTITY_MARKER",
        direction=Direction.S2C,
        size=13,  # 3 instances in live_test_01, consistent 13b — 0xxx14 entity family
        description="Entity marker/config (13 bytes, 0xxx14 family)",
        fields=[
            FieldDef("zeros", 2, 6, "bytes", "Padding"),
            FieldDef("value", 8, 4, "u32le", "Marker value"),
        ],
        confirmed=True,
    ),

    0x005b: PacketDef(
        opcode=0x005b,
        name="PLAYER_FULL_DATA",
        direction=Direction.S2C,
        size=708,  # 1 instance — massive player data, follows PLAYER_ACTION
        description="Full player data payload (708 bytes — stats, inventory, etc.)",
        confirmed=True,
    ),

    0x6cf1: PacketDef(
        opcode=0x6cf1,
        name="SYSTEM_BLOCK_B",
        direction=Direction.S2C,
        size=268,  # 1 instance — same size as SYSTEM_BLOCK_A (0xfbee), similar structure
        description="System data block B (268 bytes, sparse — 0xxxf1 family)",
        confirmed=False,
    ),

    0xaef1: PacketDef(
        opcode=0xaef1,
        name="ENTITY_EFFECT_EX",
        direction=Direction.S2C,
        size=36,  # 1 instance — has coords, entity refs, 0xxxf1 family
        description="Extended entity effect — coordinates and entity references",
        fields=[
            FieldDef("zeros", 2, 6, "bytes", "Padding"),
            FieldDef("entity_ref", 8, 4, "u32le", "Entity reference"),
            FieldDef("param", 12, 4, "u32le", "Effect parameter"),
            FieldDef("x", 16, 4, "i32le", "X coordinate"),
            FieldDef("y", 20, 4, "i32le", "Y coordinate"),
            FieldDef("state", 24, 4, "u32le", "State/flags"),
            FieldDef("magnitude", 28, 4, "f32", "Effect magnitude"),
        ],
        confirmed=False,
    ),

    # NOTE: 0x0054 and 0x0018 appear as 17b residuals after ENTITY_DETAIL
    # sub-entries are split by 0x8114 boundary. NOT registered because `00 xx`
    # opcodes cause false positive boundary matches in the scanner (00 is too
    # common in binary data). These are sub-entry tails, not independent opcodes.

    0x010a: PacketDef(
        opcode=0x010a,
        name="PLAYER_IDENTITY",
        direction=Direction.S2C,
        size=406,  # confirmed — 2 instances across 2 captures, consistent 406b
        description="Player identity — char name, clan, active skill ('Lady Rachel', 'Good Night', 'ExCeLlence')",
        fields=[
            FieldDef("header", 2, 3, "bytes", "Header params"),
            FieldDef("char_name", 5, 11, "str", "Character name (null-term, may contain 0xa0)"),
            FieldDef("clan_name", 37, 10, "str", "Clan/family name (null-term)"),
            FieldDef("skill_delim_start", 48, 2, "bytes", "Skill name start delimiter (0x2d 0xf0)"),
            FieldDef("skill_name", 50, 10, "str", "Active skill name ('ExCeLlence')"),
            FieldDef("skill_delim_end", 60, 2, "bytes", "Skill name end delimiter (0xf0 0x2d)"),
        ],
        confirmed=True,
    ),

    # ---- Variable-size unknowns (boundary-scanned framing) ----

    0x1900: PacketDef(
        opcode=0x1900,
        name="SERVER_RESPONSE",
        direction=Direction.S2C,
        size=None,  # variable: 11b, 22b — always follows ACK
        description="Server response/confirmation after ACK (variable, 2 instances in session5)",
        confirmed=False,
    ),

    0xd20d: PacketDef(
        opcode=0xd20d,
        name="ZONE_TRAILER",
        direction=Direction.S2C,
        size=None,  # variable: 4b, 8b — always follows ZONE_DATA
        description="Zone data trailer — small variable packet after ZONE_DATA",
        confirmed=False,
    ),

    0x8214: PacketDef(
        opcode=0x8214,
        name="ENTITY_DETAIL_A",
        direction=Direction.S2C,
        size=None,  # variable: 92b, 108b — 36-byte sub-entries, follows ENTITY_BATCH_MOVE
        description="Entity detail batch A — 36-byte sub-entries with sequential sub-opcodes",
        fields=[
            FieldDef("count_marker", 12, 2, "u16le", "Entry count marker (0x02)"),
            FieldDef("speed", 20, 4, "f32", "Speed/range value (~10.42)"),
            FieldDef("x", 24, 4, "i32le", "X coordinate"),
            FieldDef("y", 28, 4, "i32le", "Y coordinate"),
            FieldDef("state", 32, 4, "u32le", "Movement state"),
        ],
        confirmed=False,
    ),

    0x7400: PacketDef(
        opcode=0x7400,
        name="SKILL_EFFECT_NAME",
        direction=Direction.S2C,
        size=None,  # variable: 35b, 387b — contains "ExCeLlence" with f0-delimiters
        description="Skill effect with name — delimited ASCII skill name (e.g. ExCeLlence)",
        fields=[
            FieldDef("delim_start", 2, 2, "bytes", "Start delimiter (0x2d 0xf0)"),
            FieldDef("skill_name", 4, 10, "str", "Skill name (e.g. 'ExCeLlence')"),
            FieldDef("delim_end", 14, 2, "bytes", "End delimiter (0xf0 0x2d)"),
            FieldDef("null", 16, 1, "u8", "Null separator"),
            FieldDef("param_f32", 17, 4, "f32", "Skill parameter (f32, e.g. 58.0)"),
        ],
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

    # ---- Discovered from live_test_02 (2026-02-27, live capture #2) ----

    0x7d0c: PacketDef(
        opcode=0x7d0c,
        name="ENTITY_HEADING",
        direction=Direction.S2C,
        size=14,  # confirmed — 176 instances, consistent 14b structure, heavy TCP coalescing
        description="Entity heading/speed update — direction flags + speed value",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("direction_flags", 6, 4, "u32le", "Direction/facing flags (0x40/0x60/0xC0)"),
            FieldDef("speed", 10, 4, "f32", "Movement speed (~13.5-14.0)"),
        ],
        confirmed=True,
    ),

    0x410c: PacketDef(
        opcode=0x410c,
        name="ENTITY_SPAWN_EX",
        direction=Direction.S2C,
        size=None,  # variable: 34-611b — large entity data with coords
        description="Extended entity spawn/update — variable length with position data",
        confirmed=False,
    ),

    0x5e0c: PacketDef(
        opcode=0x5e0c,
        name="ENTITY_EFFECT_LINK",
        direction=Direction.S2C,
        size=10,  # base size 10b — often coalesced with EFFECT (4a0e) + ENTITY_HEADING (7d0c)
        description="Entity effect link — entity + param, pairs with EFFECT packet",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("param", 6, 4, "u32le", "Effect parameter / color RGBA"),
        ],
        confirmed=False,
    ),

    0x1400: PacketDef(
        opcode=0x1400,
        name="ENTITY_COMBAT_INFO",
        direction=Direction.S2C,
        size=None,  # variable: 7-50b — entity combat state with coords
        description="Entity combat info — variable with entity ID, coords, speed",
        confirmed=False,
    ),

    0x350c: PacketDef(
        opcode=0x350c,
        name="ENTITY_STATE_DATA",
        direction=Direction.S2C,
        size=None,  # variable: 46-86b — mostly zeros, entity family
        description="Entity state/config data block (mostly zeros)",
        confirmed=False,
    ),

    0x360c: PacketDef(
        opcode=0x360c,
        name="ENTITY_ZONE_REF",
        direction=Direction.S2C,
        size=28,  # 1 instance — contains coordinates
        description="Entity zone reference — coordinates + zone data",
        fields=[
            FieldDef("length", 2, 2, "u16le", "Packet length"),
            FieldDef("zone_ref", 4, 4, "u32le", "Zone reference ID"),
        ],
        confirmed=False,
    ),

    0x4e0c: PacketDef(
        opcode=0x4e0c,
        name="ENTITY_CONTROL",
        direction=Direction.S2C,
        size=7,  # 1 instance — minimal entity command
        description="Entity control/command (entity family, 7 bytes)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("command", 6, 1, "u8", "Command type"),
        ],
        confirmed=False,
    ),

    0x4614: PacketDef(
        opcode=0x4614,
        name="ENTITY_DETAIL_C",
        direction=Direction.S2C,
        size=23,  # 1 instance — 0xxx14 entity detail family
        description="Entity detail variant C — entity + coords + speed",
        fields=[
            FieldDef("zeros", 2, 2, "bytes", "Padding"),
            FieldDef("entity_id", 4, 4, "u32le", "Entity ID"),
        ],
        confirmed=False,
    ),

    0x9b0d: PacketDef(
        opcode=0x9b0d,
        name="ENTITY_STAT_EX",
        direction=Direction.S2C,
        size=42,  # 1 instance — 0xxx0d stats family, contains embedded 7d0c refs
        description="Extended entity stat — stat data with embedded entity refs",
        confirmed=False,
    ),

    0x170e: PacketDef(
        opcode=0x170e,
        name="EFFECT_BATCH",
        direction=Direction.S2C,
        size=None,  # variable: 1350b — contains repeated 170e sub-entries
        description="Effect batch — large packet with repeated effect sub-entries",
        confirmed=False,
    ),

    0x0017: PacketDef(
        opcode=0x0017,
        name="SYSTEM_DATA_LARGE",
        direction=Direction.S2C,
        size=None,  # variable: 1092b — large system data block
        description="Large system data block (1092 bytes, contains entity refs)",
        confirmed=False,
    ),

    # ---- Player/entity movement (15-byte position packets, same coord space as ENTITY_POSITION) ----

    0x7b00: PacketDef(
        opcode=0x7b00,
        name="PLAYER_MOVE",
        direction=Direction.S2C,
        size=15,  # chain-validated 538x in live_test_03
        description="Player/entity position update (primary, ~1.2/sec per entity)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("x", 6, 4, "i32le", "X coordinate"),
            FieldDef("y", 10, 4, "i32le", "Y coordinate"),
            FieldDef("state", 14, 1, "u8", "Movement state"),
        ],
        confirmed=True,
    ),

    0xab00: PacketDef(
        opcode=0xab00,
        name="PLAYER_MOVE_B",
        direction=Direction.S2C,
        size=15,  # chain-validated 122x
        description="Player/entity position update (variant B)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("x", 6, 4, "i32le", "X coordinate"),
            FieldDef("y", 10, 4, "i32le", "Y coordinate"),
            FieldDef("state", 14, 1, "u8", "Movement state"),
        ],
        confirmed=True,
    ),

    0xdb00: PacketDef(
        opcode=0xdb00,
        name="PLAYER_MOVE_C",
        direction=Direction.S2C,
        size=15,  # chain-validated 59x
        description="Player/entity position update (variant C)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("x", 6, 4, "i32le", "X coordinate"),
            FieldDef("y", 10, 4, "i32le", "Y coordinate"),
            FieldDef("state", 14, 1, "u8", "Movement state"),
        ],
        confirmed=True,
    ),

    0xa000: PacketDef(
        opcode=0xa000,
        name="PLAYER_MOVE_D",
        direction=Direction.S2C,
        size=15,  # chain-validated 15x
        description="Player/entity position update (variant D, less frequent)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("x", 6, 4, "i32le", "X coordinate"),
            FieldDef("y", 10, 4, "i32le", "Y coordinate"),
            FieldDef("state", 14, 1, "u8", "Movement state"),
        ],
        confirmed=True,
    ),

    0xd000: PacketDef(
        opcode=0xd000,
        name="PLAYER_MOVE_E",
        direction=Direction.S2C,
        size=15,  # chain-validated 4x
        description="Player/entity position update (variant E, rare)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("x", 6, 4, "i32le", "X coordinate"),
            FieldDef("y", 10, 4, "i32le", "Y coordinate"),
            FieldDef("state", 14, 1, "u8", "Movement state"),
        ],
        confirmed=True,
    ),

    0xf500: PacketDef(
        opcode=0xf500,
        name="PLAYER_MOVE_F",
        direction=Direction.S2C,
        size=15,  # chain-validated 1x (rare)
        description="Player/entity position update (variant F, very rare)",
        fields=[
            FieldDef("entity_id", 2, 4, "u32le", "Entity ID"),
            FieldDef("x", 6, 4, "i32le", "X coordinate"),
            FieldDef("y", 10, 4, "i32le", "Y coordinate"),
            FieldDef("state", 14, 1, "u8", "Movement state"),
        ],
        confirmed=False,
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
