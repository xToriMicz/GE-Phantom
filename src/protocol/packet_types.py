"""
Protocol Packet Types — registry of discovered packet structures.

This file grows as we reverse-engineer the protocol. Start empty,
fill in as patterns are confirmed from captures.
"""

from __future__ import annotations

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
    fields: list[FieldDef] = field(default_factory=list)
    confirmed: bool = False  # True once verified from multiple captures


@dataclass
class FieldDef:
    """A field within a packet."""
    name: str
    offset: int
    size: int
    type: str  # "u8", "u16le", "u16be", "u32le", "i32le", "str", "bytes"
    description: str = ""


# ---- Registry of discovered packets ----
# Format: opcode → PacketDef
# This will be populated as we analyze captures.

KNOWN_PACKETS: dict[int, PacketDef] = {
    # Example (placeholder — will be replaced with real data):
    # 0x0001: PacketDef(
    #     opcode=0x0001,
    #     name="ITEM_DROP",
    #     direction=Direction.S2C,
    #     description="Server notifies client about item drop",
    #     fields=[
    #         FieldDef("item_id", 4, 4, "u32le", "Item type ID"),
    #         FieldDef("x", 8, 4, "i32le", "X coordinate"),
    #         FieldDef("y", 12, 4, "i32le", "Y coordinate"),
    #         FieldDef("instance_id", 16, 4, "u32le", "Unique drop instance"),
    #     ],
    #     confirmed=False,
    # ),
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
        case "str":
            return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        case "bytes":
            return raw
        case _:
            return raw


def decode_packet(data: bytes) -> dict | None:
    """Try to decode a packet using known definitions."""
    if len(data) < HEADER_SIZE:
        return None

    # Try both byte orders for opcode (we'll confirm which one is correct)
    for order in ("little", "big"):
        opcode = int.from_bytes(data[:2], order)
        if opcode in KNOWN_PACKETS:
            pdef = KNOWN_PACKETS[opcode]
            result = {"opcode": opcode, "name": pdef.name, "direction": pdef.direction}
            for f in pdef.fields:
                if f.offset + f.size <= len(data):
                    result[f.name] = decode_field(data, f)
            return result

    return None


def register_packet(pdef: PacketDef) -> None:
    """Register a newly discovered packet type."""
    KNOWN_PACKETS[pdef.opcode] = pdef
