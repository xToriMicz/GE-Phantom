# GE_Phantom Protocol Reference

> Reverse-engineered packet structures for the GE MMO client-server protocol.
> Updated: 2026-02-27 | Coverage: 99.9% (live), 100% (historical)

## Overview

- **78 registered opcodes** (51 confirmed, 27 pending additional captures)
- **Header**: 2-byte opcode (big-endian) + 2-byte field (varies)
- **Direction**: S2C (server-to-client, plaintext) and C2S (client-to-server, encrypted payload)
- **Framing**: Fixed-size (49), length-field variable (5), unknown framing (7)

## Opcode Families

Opcodes cluster into families by their low byte, revealing the protocol's internal structure.

### 0xxx0c — Entity & World (28 opcodes)

The largest family. Handles entity lifecycle, movement, combat, and world state.

| Opcode | Name | Size | Confirmed | Description |
|--------|------|------|-----------|-------------|
| 0x000c | COMBAT_FOOTER | 25 | Y | Combat batch summary after COMBAT_DATA entries |
| 0x2f0c | ENTITY_GROUP | 6 | Y | Entity group header, followed by child movement packets |
| 0x3d0c | ENTITY_FLAG | 7 | Y | Entity flag/status change |
| 0x3e0c | MONSTER_SPAWN | 371 | Y | Monster spawn with full data |
| 0x3f0c | NPC_SPAWN | 371 | - | NPC spawn (similar to MONSTER_SPAWN) |
| 0x400c | OBJECT_SPAWN | 371 | Y | Object/structure spawn |
| 0x430c | ENTITY_EVENT | 7 | Y | Entity event trigger (animation, state change) |
| 0x460c | PLAYER_SPAWN | 334 | Y | Player character spawn |
| 0x490c | ITEM_DROP | 57 | Y | Item dropped on ground |
| 0x4b0c | ITEM_EVENT | 6 | Y | Item pickup confirmation |
| 0x520c | PLAYER_NAME | 26 | - | Player name label after PLAYER_SPAWN |
| 0x540c | COMBAT_UPDATE | 38 | Y | Combat update with attack range |
| 0x560c | ENTITY_POSITION | 26 | Y | Entity position update (i32 coords) |
| 0x580c | ENTITY_LABEL | var | Y | Entity name string (length field @ [2:4]) |
| 0x5a0c | ENTITY_STAT_HEADER | 10 | Y | Pairs with ENTITY_STAT (0x530d) |
| 0x5c0c | ENTITY_DATA | 270 | Y | Entity detailed data block (sparse template) |
| 0x5d0c | ENTITY_STATE_F64 | 23 | Y | Entity state data (f64 values, NOT position) |
| 0x5f0c | ENTITY_LINK | 24 | Y | Entity link/association |
| 0x620c | COMBAT_EFFECT | 44 | Y | Combat effect with damage display |
| 0x630c | ENTITY_SYNC | 14 | Y | Entity sync/update |
| 0x660c | BATCH_ENTITY_UPDATE | var | Y | Multi-entity batch (length field @ [2:4]) |
| 0x680c | TARGET_LINK | 15 | Y | Entity targeting (who attacks who) |
| 0x6b0c | ENTITY_MOVE_PATH | 60 | Y | Movement path with 3 waypoints |
| 0x6c0c | ENTITY_TICK | 11 | Y | Entity tick/heartbeat |
| 0x6d0c | ENTITY_MOVE_DETAIL | 72 | Y | Detailed movement with speed + heading |
| 0x750c | ENTITY_BATCH_MOVE | 52 | Y | Batch movement, often followed by EFFECT_DATA |
| 0x7a0c | ENTITY_DESPAWN | 6 | Y | Entity despawn or death |
| 0x7b0c | ENTITY_SPEED | 25 | Y | Entity speed update (f32 values) |
| 0xca0c | SKILL_CAST | var | Y | Skill cast with name string (length field @ [2:4]) |

### 0xxx14 — Entity Detail (4 opcodes)

Sub-entry system for detailed entity data. Uses 36-byte sub-entries with sequential sub-opcodes.

| Opcode | Name | Size | Confirmed | Description |
|--------|------|------|-----------|-------------|
| 0x8114 | ENTITY_MARKER | 13 | Y | Entity marker/config, 0xxx14 family |
| 0x8214 | ENTITY_DETAIL_A | var | - | 36-byte sub-entries (92/108b) |
| 0xba14 | ENTITY_NOTIFY | 21 | - | Small entity notification |
| 0xbe14 | ENTITY_DETAIL_B | 108 | - | 3x36-byte sub-entries with sequential sub-opcodes |

**Structure note**: ENTITY_DETAIL packets contain 36-byte sub-entries with their own sub-opcodes (e.g., 0xbf14, 0xc014). Each sub-entry has coords, speed, and state. The `count_marker` at offset 12 indicates entry count.

### 0xxx0e — Effects (3 opcodes)

Visual effects and combat feedback.

| Opcode | Name | Size | Confirmed | Description |
|--------|------|------|-----------|-------------|
| 0x330e | EFFECT_DATA | 15 | Y | Entity effect trigger |
| 0x4a0e | EFFECT | var | Y | Effect with ASCII strings (length field @ [2:4]) |
| 0x660e | NAME_LABEL | var | - | Character/NPC name label |

### 0xxx0d — Stats & Actions (3 opcodes)

Entity stat updates and action triggers.

| Opcode | Name | Size | Confirmed | Description |
|--------|------|------|-----------|-------------|
| 0x530d | ENTITY_STAT | 22 | Y | Entity stat update (HP/MP/status) |
| 0x540d | ENTITY_ACTION | 8 | Y | Entity action trigger |
| 0xd20d | ZONE_TRAILER | var | - | Zone data trailer (4/8b) |

### 0xxxf1 — System Blocks (2 opcodes)

Large static data blocks. Twin 268-byte structures with similar sparse layout.

| Opcode | Name | Size | Confirmed | Description |
|--------|------|------|-----------|-------------|
| 0x6cf1 | SYSTEM_BLOCK_B | 268 | - | System data block B |
| 0xaef1 | ENTITY_EFFECT_EX | 36 | - | Extended entity effect with coords |

### 0xxx15 — Character & Inventory (3 opcodes)

Character profile and inventory data.

| Opcode | Name | Size | Confirmed | Description |
|--------|------|------|-----------|-------------|
| 0x0c15 | CHARACTER_DATA | var | - | Character data payload |
| 0x1215 | SESSION_PARAM | 9 | - | Session/zone parameter |
| 0x1b15 | INVENTORY_DATA | var | - | Inventory data payload |

### Special Opcodes

| Opcode | Name | Size | Confirmed | Description |
|--------|------|------|-----------|-------------|
| 0x0000 | HEARTBEAT | 6 | Y | Server keepalive |
| 0x0064 | SYSTEM_PING | 8 | Y | System ping (identical payloads) |
| 0xe00c | ACK | 6 | Y | Server acknowledgement |
| 0x301e | COMBAT_RESULT | 33 | Y | Combat damage summary |
| 0xd00e | SKILL_EFFECT | 50 | Y | Skill visual effect |
| 0x380c | ZONE_DATA | var | Y | Zone/map data (large, length field @ [2:4]) |
| 0x5411 | ENTITY_PROFILE | 77 | Y | Entity profile data |
| 0x010a | PLAYER_IDENTITY | 406 | - | Rich profile: name + clan + skill |
| 0x005b | PLAYER_FULL_DATA | 708 | - | Full player data payload |
| 0x5a54 | COMBAT_TRIGGER | 42 | - | Combat trigger with positions |
| 0xf0b7 | SYSTEM_ECHO | 13 | - | 4-byte header repeats at offset 8 |
| 0xfbee | SYSTEM_BLOCK_A | 268 | - | System data block A (twin of 0x6cf1) |
| 0x7400 | SKILL_EFFECT_NAME | var | - | Skill name with f0-delimiters |
| 0x1900 | SERVER_RESPONSE | var | - | Response after ACK (session5 only) |
| 0x7b00 | PLAYER_MOVE | 15 | Y | Player/entity position update (primary) |
| 0xab00 | PLAYER_MOVE_B | 15 | Y | Player/entity position update (variant B) |
| 0xdb00 | PLAYER_MOVE_C | 15 | Y | Player/entity position update (variant C) |
| 0xa000 | PLAYER_MOVE_D | 15 | Y | Player/entity position update (variant D) |
| 0xd000 | PLAYER_MOVE_E | 15 | Y | Player/entity position update (variant E) |
| 0xf500 | PLAYER_MOVE_F | 15 | - | Player/entity position update (variant F, rare) |

### C2S — Client to Server (2 opcodes, encrypted)

Opcodes readable in plaintext, payload encrypted.

| Opcode | Name | Size | Confirmed | Description |
|--------|------|------|-----------|-------------|
| 0x1000 | KEEPALIVE | 18 | Y | Client keepalive (~1/sec) |
| 0x1800 | PLAYER_ACTION | 26 | Y | Player action (attack/skill/pickup) |

**Encryption notes**: C2S payloads after the 2-byte opcode header are encrypted. Analysis shows:
- Not simple XOR cipher (key-recovery fails)
- No single-byte counter patterns
- High entropy (~7+ bits) in data bytes
- Each payload unique (no repeats even for keepalive)
- 18-byte KEEPALIVE not aligned to standard block sizes (not AES)
- Likely stream cipher or PRNG-based encryption

## Structural Patterns

### TCP Coalescing

The game server frequently coalesces multiple packets into single TCP segments:

- 2x ENTITY_POSITION (26b) → 52 bytes
- 2x COMBAT_UPDATE (38b) → 76 bytes
- 3x COMBAT_DATA (23b) + COMBAT_FOOTER (25b) → 94 bytes
- MONSTER_SPAWN (371b) can coalesce with smaller packets

### Spawn Family (371-byte triplets)

MONSTER_SPAWN (0x3e0c), NPC_SPAWN (0x3f0c), OBJECT_SPAWN (0x400c) all share:
- Fixed 371-byte size
- Same field layout with entity_id at offset 2
- Sequential opcodes (0x3e, 0x3f, 0x40)
- PLAYER_SPAWN (0x460c) is similar but 334 bytes

### f0-Delimiters

Skill names in certain packets use `0x2d 0xf0` / `0xf0 0x2d` as delimiters:
- PLAYER_IDENTITY (0x010a): `"ExCeLlence"` at offset 50
- SKILL_EFFECT_NAME (0x7400): skill name starting at offset 4

### Combat Sequence

Typical combat produces a packet chain:
```
TARGET_LINK → COMBAT_UPDATE → COMBAT_DATA (1-3x) → COMBAT_FOOTER → EFFECT_DATA (1-3x)
```

### Position Coordinate Types

- **Entity positions** (0x560c): i32 signed integers
- **Player move** (0x7b00, 0xab00, 0xdb00, 0xa000, 0xd000, 0xf500): i32 same coord space as entity positions
- **Movement paths** (0x6b0c, 0x6d0c): i32 with state byte (30=idle, 81=walk, 119=run)
- **Entity state** (0x5d0c): f64 values — NOT position data despite similar structure

## Coverage by Capture

| Capture | Packets | Coverage | Notes |
|---------|---------|----------|-------|
| live_test_01 | 1795 | 99.9% | Main capture, 2 residual unknowns (0x0054, 0x0018) |
| session1 | 77 | 100% | Basic movement |
| session2_standing | 52 | 100% | Idle/standing |
| session3_combat | 28 | 100% | Short combat |
| session4_combat_full | 344 | 100% | Full combat session |
| session5_pickup | 619 | 100% | Item pickup session |

### Residual Unknowns

The 2 unknown packets in live_test_01 are at opcodes 0x0054 and 0x0018 (17 bytes each).
These are sub-entry tails from ENTITY_DETAIL splitting, not independent opcodes.
`00 xx` patterns cannot be reliably used as boundary markers because zero bytes are
too common in binary data.

## Framing Strategy

The reassembler uses a three-tier approach:

1. **Fixed-size lookup**: Most packets have known fixed sizes (49 opcodes)
2. **Length-field extraction**: Variable packets with u16le length at [2:4] (5 opcodes)
3. **Boundary scanning**: Scan forward for next known opcode (7 opcodes)

Boundary scanning excludes HEARTBEAT (0x0000) from candidates and uses **chain validation**:
when a candidate boundary is found, it verifies the NEXT packet after it also starts with
a known opcode. This two-hop validation prevents false boundaries from coincidental
byte patterns.
