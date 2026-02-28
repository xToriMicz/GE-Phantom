# ENTITY_COMBAT_INFO (0x1400) — Complete Packet Analysis

**Date**: 2026-02-27
**Packet size**: 922 bytes
**Source**: login_capture.json (single occurrence during login sequence)
**Direction**: S2C (Server to Client)
**Entity ID**: 42195 (0xa4d3) — player character

---

## Verdict: NOT an attack_range packet

**ENTITY_COMBAT_INFO is a one-time CHARACTER SKILL + EQUIPMENT INVENTORY dump sent during login.**

- Contains 58 skill entries with skill IDs and level values
- Contains 6 equipment slot entries with item names
- Contains ZERO floating-point values in the 500-1100 range
- Contains ZERO coordinate data
- The `0xe803` (1000) values flagged as suspicious are **skill max-levels**, not attack_range
- attack_range is definitively NOT in this packet

---

## Packet Structure Overview

```
Bytes 0-25:    HEADER           (26 bytes)
Bytes 26-27:   META             (skill_count, flag)
Bytes 28-43:   COUNTS + PADDING (equip_count at byte 31, then zeros)
Bytes 44-507:  SKILL ARRAY      (58 entries x 8 bytes = 464 bytes)
Bytes 508-915: EQUIPMENT ARRAY  (6 entries x 68 bytes = 408 bytes)
Bytes 916-921: TRAILER          (6 zero bytes)
                                 TOTAL: 26 + 2 + 16 + 464 + 408 + 6 = 922 bytes
```

---

## Section 1: Header (bytes 0-25)

| Offset | Size | Type   | Value        | Description                           |
|--------|------|--------|--------------|---------------------------------------|
| 0      | 2    | u16be  | 0x1400       | Opcode                                |
| 2      | 4    | u32le  | 42195        | Entity ID (player character)          |
| 6      | 4    | u32le  | 4            | Parameter A (meaning unknown, possibly type/class) |
| 10     | 8    | bytes  | 00...00      | Zero padding                          |
| 18     | 2    | u16be  | 0xab0e       | Sub-opcode or section marker          |
| 20     | 2    | u16le  | 904          | Sub-section length (922 - 18 = 904)   |
| 22     | 4    | u32le  | 42195        | Entity ID (repeated)                  |

**Key observation**: Entity ID appears twice (bytes 2-5 and 22-25). The sub-length at offset 20 (904) exactly equals the packet size minus 18, confirming this is a length field for the data section starting at offset 18.

## Section 2: Meta (bytes 26-31)

| Offset | Size | Type | Value | Description                             |
|--------|------|------|-------|-----------------------------------------|
| 26     | 1    | u8   | 1     | Sub-type flag (stance? class index?)    |
| 27     | 1    | u8   | 58    | **Skill array entry count** (confirmed) |
| 28-30  | 3    | bytes| 0     | Zero padding                            |
| 31     | 1    | u8   | 6     | **Equipment slot count** (confirmed)    |

**Verification**: 58 skill entries x 8 bytes = 464 bytes (offsets 44-507). 6 equipment entries x 68 bytes = 408 bytes (offsets 508-915). Both counts match perfectly.

## Section 3: Padding (bytes 32-43)

12 bytes of zeros. Likely reserved space or alignment padding.

---

## Section 4: Skill Array (bytes 44-507)

**58 entries, 8 bytes each**

Entry format:
```
[padding: u16le = 0] [skill_id: u16le] [padding: u16le = 0] [value: u16le]
```

### Full Skill Table (sorted by skill_id)

| # | Skill ID | Value | Notes |
|---|----------|-------|-------|
| 1 | 1 | 0 | |
| 2 | 2 | 0 | |
| 3 | 3 | 1000 | MAX LEVEL |
| 4 | 4 | 0 | |
| 5 | 5 | 0 | |
| 6 | 6 | 0 | |
| 7 | 7 | 0 | |
| 8 | 8 | 0 | |
| 9 | 9 | 0 | |
| 10 | 10 | 0 | |
| 11 | 11 | 0 | |
| 12 | 12 | 0 | |
| 13 | 14 | 0 | (no skill 13) |
| 14 | 15 | 0 | |
| 15 | 16 | 0 | |
| 16 | 17 | 0 | |
| 17 | 18 | 0 | |
| 18 | 19 | 0 | |
| 19 | 20 | 0 | |
| 20 | 21 | 0 | |
| 21 | 22 | 0 | |
| 22 | 23 | 131 | Partial level |
| 23 | 24 | 67 | Partial level |
| 24 | 25 | 5 | Low level |
| 25 | 26 | 0 | |
| 26 | 27 | 0 | |
| 27 | 28 | 0 | |
| 28 | 32 | 0 | |
| 29 | 34 | 0 | |
| 30 | 35 | 0 | |
| 31 | 36 | 1000 | MAX LEVEL |
| 32 | 38 | 0 | |
| 33 | 40 | 0 | |
| 34 | 41 | 0 | |
| 35 | 42 | 0 | |
| 36 | 44 | 0 | |
| 37 | 45 | 0 | |
| 38 | 46 | 1000 | MAX LEVEL |
| 39 | 48 | 0 | |
| 40 | 54 | 0 | |
| 41 | 55 | 0 | |
| 42 | 56 | 1000 | MAX LEVEL |
| 43 | 64 | 0 | |
| 44 | 65 | 0 | |
| 45 | 66 | 1000 | MAX LEVEL |
| 46 | 67 | 0 | (duplicate skill_id, different entry) |
| 47 | 67 | 1000 | MAX LEVEL (duplicate skill_id) |
| 48 | 68 | 0 | (duplicate) |
| 49 | 68 | 0 | (duplicate) |
| 50 | 69 | 0 | (duplicate) |
| 51 | 69 | 0 | (duplicate) |
| 52 | 70 | 0 | |
| 53 | 71 | 0 | |
| 54 | 72 | 1000 | MAX LEVEL |
| 55 | 73 | 0 | |
| 56 | 74 | 0 | |
| 57 | 76 | 0 | |
| 58 | 77 | 0 | |

### Skill Stats Summary
- **Total entries**: 58
- **Entries with value > 0**: 10
- **Entries at max level (1000)**: 7
- **Partial levels**: skill 23 = 131, skill 24 = 67, skill 25 = 5
- **Duplicate skill IDs**: 67, 68, 69 appear twice each (possibly different stances?)

---

## Section 5: Equipment Array (bytes 508-915)

**6 entries, 68 bytes each**

Entry format:
```
[padding: u16le = 0] [slot_id: u16le] [padding: u16le = 0] [name: 62-byte null-padded ASCII string]
```

| Slot | Slot ID | Equipment Name | Notes |
|------|---------|----------------|-------|
| 0 | 11 | xMosqi001 | Weapon (mosquito-type weapon model) |
| 1 | 1 | None | Empty slot |
| 2 | 4 | None | Empty slot |
| 3 | 2 | None | Empty slot |
| 4 | 3 | None | Empty slot |
| 5 | 5 | None | Empty slot |

**Interpretation**: Slot IDs likely correspond to equipment categories:
- Slot 1-5: Standard gear slots (head, body, legs, feet, accessory?)
- Slot 11: Weapon slot
- "None" = empty/unequipped
- "xMosqi001" = weapon asset name (mosquito-themed, model ID 001)

---

## Section 6: Trailer (bytes 916-921)

6 bytes, all zeros. Possibly reserved or padding for alignment.

---

## Attack Range Search Results

### Exhaustive scan at EVERY byte offset

| Search | Result |
|--------|--------|
| f32 in [500.0, 1100.0] | **2 hits**: f32@131 = 512.0, f32@443 = 512.0 (both are artifacts of skill value 131 at unaligned offset, NOT real floats) |
| u32le = 539 | None |
| u32le = 700 | None |
| u32le = 803 | None |
| u32le = 850 | None |
| u32le = 1000 | 7 hits (all are skill levels in the skill array) |
| u16le = 539 | None |
| u16le = 700 | None |
| u16le = 803 | None |
| u16le = 850 | None |
| u16le = 1000 | 7 hits at offsets 66, 218, 234, 242, 266, 442, 498 (all skill levels) |
| 0xe8030000 as u32le | None |
| Byte sequence e8 03 | 7 occurrences (all inside skill value fields) |

**The f32 = 512.0 hits are false positives** — they occur at offsets 131 and 443 which straddle skill entry boundaries. At offset 131, the bytes `00 00 83 00` are part of two adjacent skill entries (value=0 for skill 23, then padding=0 for skill 68's ID field, with byte 0x83=131 being part of skill 23's value). These are NOT meaningful float values.

---

## Comparison with COMBAT_UPDATE (0x540c)

| Field | COMBAT_UPDATE (0x540c, 38b) | ENTITY_COMBAT_INFO (0x1400, 922b) |
|-------|------|------|
| Opcode | 0x540c | 0x1400 |
| entity_id | @2 u32le | @2 u32le (same pattern) |
| Coordinates | x@18, y@22 (i32le) | **NONE** |
| Speed | f32 @30 | **NONE** |
| State | u32le @26 | **NONE** |
| Combat flags | u32le @34 | **NONE** |
| Skill data | N/A | 58-entry skill table |
| Equipment | N/A | 6-slot equipment table |
| Frequency | Every combat tick | Once at login |

**COMBAT_UPDATE is a real-time combat state packet. ENTITY_COMBAT_INFO is a static inventory dump.**

---

## Companion Packet: 0xdb0c + 0x410e (combat stat modifiers)

Sent in the same login sequence, the 0xdb0c packet (1124 bytes) contains an embedded 0x410e sub-packet with **20 named combat stat modifiers**:

| Stat Name | Type | f64 Value | Category |
|-----------|------|-----------|----------|
| HumanBane | 2 | 0.0 | Race modifier |
| GolemBane | 2 | 0.0 | Race modifier |
| BeastBane | 2 | 0.0 | Race modifier |
| UndeadBane | 2 | 0.0 | Race modifier |
| DemonBane | 2 | 0.0 | Race modifier |
| PCDef | 2 | 0.0 | PvP defense |
| RIceATK | 2 | 0.0 | Element ATK |
| RPsyATK | 2 | 0.0 | Element ATK |
| MonDam | 2 | 0.0 | Monster damage |
| MediumBane | 2 | 0.0 | Size modifier |
| MetalBane | 2 | 0.0 | Armor modifier |
| RLghtATK | 2 | 0.0 | Element ATK |
| RFireATK | 2 | 0.0 | Element ATK |
| SoftBane | 2 | 0.0 | Armor modifier |
| RHPDrain | 2 | 0.0 | Life steal |
| LHPDrain | 2 | 0.0 | Life steal |
| **MeleeDef** | 2 | **100.0** | **Melee defense** |
| **MSPD_Limit** | 2 | **800.0** | **Movement speed cap** |
| **MagicDef** | 2 | **100.0** | **Magic defense** |
| **ShootDef** | 2 | **100.0** | **Ranged/shoot defense** |

**Notable**: These are all defensive/modifier stats. No "AttackRange", "ShootRange", or "AtkRange" stat exists in this list. The stat names use explicit terminology (MeleeDef, ShootDef, MSPD_Limit) which strongly suggests that if attack_range were a named stat, it would appear here as something like "AtkRange" or "ShootRange" — but it does not.

---

## Conclusions

### 1. What ENTITY_COMBAT_INFO IS
- A **one-time static dump** of the player character's skill levels and equipped items
- Sent during the login/character-load sequence
- Similar to a "character sheet" — lists all 58 skills and 6 equipment slots
- The "xMosqi001" weapon is the only equipped item

### 2. What the 0xe803 (1000) values ARE
- **Skill max-level indicators** — 7 skills are at level 1000
- NOT attack_range, NOT distance values, NOT combat range
- The value 1000 is the GE skill level cap

### 3. Why attack_range is NOT here
- No float values in any plausible range (500-1100)
- No u16/u32 values matching known attack ranges (539, 700, 803, 850)
- The packet structure is purely skill IDs + levels + equipment names
- No coordinate system, no distance calculations, no range values

### 4. Where to look next for attack_range
- **Server-side computation**: Based on phase 2B findings, attack_range may be purely server-authoritative and never transmitted to the client
- **0xdb0c base stats**: The 0xdb0c header (bytes 26-143) contains many u16le values that need deeper analysis — this is where base character stats live
- **Client-side calculation**: The client may compute attack_range from weapon type + skill levels locally, meaning it exists only in game memory (not in packets)
- **Memory scanning**: The Pymem-based approach may be the only viable path if range is computed client-side from skill/weapon data
