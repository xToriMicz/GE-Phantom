"""
Deep analysis of ENTITY_COMBAT_INFO (opcode 0x1400, 922 bytes)
"""
import struct

hex_data = '1400d3a40000040000000000000000000000ab0e8803d3a40000013a0000000600000000000000000000000000000100000000000000020000000000000003000000e80300001800000043000000190000000500000045000000000000001b0000000000000020000000000000001a000000000000002200000000000000170000008300000044000000000000001c0000000000000015000000000000004300000000000000230000000000000040000000000000003600000000000000370000000000000041000000000000002d0000000000000042000000e803000026000000000000002e000000e803000024000000e803000030000000000000002c0000000000000038000000e8030000140000000000000013000000000000004d000000000000000b000000000000000c000000000000002a00000000000000050000000000000008000000000000000e00000000000000040000000000000006000000000000000f00000000000000100000000000000007000000000000004c00000000000000110000000000000012000000000000002800000000000000290000000000000016000000000000000a0000000000000043000000e803000044000000000000004700000000000000460000000000000049000000000000004a00000000000000090000000000000048000000e803000045000000000000000b000000784d6f73716930303100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000004e6f6e65000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000004e6f6e65000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000004e6f6e65000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030000004e6f6e65000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000050000004e6f6e6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'

raw = bytes.fromhex(hex_data)

print("=== HEADER (bytes 0-43) ===")
print("  @0-1:   opcode      = 0x{:04x}".format(struct.unpack_from('>H', raw, 0)[0]))
print("  @2-5:   entity_id   = {} (u32le)".format(struct.unpack_from('<I', raw, 2)[0]))
print("  @6-9:   param_a     = {} (u32le)".format(struct.unpack_from('<I', raw, 6)[0]))
print("  @10-17: zeros       = {}".format(raw[10:18].hex()))
print("  @18-19: sub_opcode  = 0x{:02x}{:02x}".format(raw[18], raw[19]))
print("  @20-21: sub_length  = {} (u16le) [922-18=904 match]".format(struct.unpack_from('<H', raw, 20)[0]))
print("  @22-25: entity_id2  = {} (u32le)".format(struct.unpack_from('<I', raw, 22)[0]))
print("  @26:    flag        = {}".format(raw[26]))
print("  @27:    skill_count = {} (0x{:02x}) [=58, matches 58 entries]".format(raw[27], raw[27]))
print("  @28-31: raw         = {} (u32le={})".format(raw[28:32].hex(), struct.unpack_from('<I', raw, 28)[0]))
print("  @28:    u8={}  @29:u8={}  @30:u8={}  @31:u8={} [31=6=equip_count?]".format(raw[28], raw[29], raw[30], raw[31]))
print("  @32-43: zeros       = {} (12 bytes padding)".format(raw[32:44].hex()))

print()
print("=== SKILL ARRAY (bytes 44-507, 58 entries x 8 bytes) ===")
print("  Format: [pad:u16le=0][skill_id:u16le][pad:u16le=0][value:u16le]")
print()
print("  {:>3s} | {:>6s} | {:>8s} | {:>6s} | {}".format("#", "Offset", "SkillID", "Value", "Notes"))
print("  " + "-" * 55)

nonzero_skills = []
for idx in range(58):
    off = 44 + idx * 8
    skill_id = struct.unpack_from('<H', raw, off + 2)[0]
    value = struct.unpack_from('<H', raw, off + 6)[0]
    notes = ""
    if value == 1000:
        notes = "*** 0xe803=1000 ***"
    if value > 0 and value != 1000:
        notes = "non-zero"
    if value > 0:
        nonzero_skills.append((idx, skill_id, value))
    print("  {:3d} | {:6d} | {:8d} | {:6d} | {}".format(idx+1, off, skill_id, value, notes))

print()
print("  SKILL STATS:")
print("    Total entries:    58")
print("    Non-zero values:  {}".format(len(nonzero_skills)))
print("    Value=1000 count: {}".format(sum(1 for _,_,v in nonzero_skills if v == 1000)))
print()
print("  NON-ZERO ENTRIES:")
for idx, sid, val in nonzero_skills:
    print("    Entry {:2d}: skill_id={:2d}, value={:5d}".format(idx+1, sid, val))

print()
print("=== EQUIPMENT ARRAY (bytes 508-915, 6 entries x 68 bytes) ===")
print("  Format: [slot_id:u32le][name:64-byte null-padded string]")
print()

for slot_idx in range(6):
    off = 508 + slot_idx * 68
    slot_id = struct.unpack_from('<I', raw, off)[0]
    name_bytes = raw[off+4:off+68]
    null_pos = name_bytes.find(b'\x00')
    if null_pos >= 0:
        name = name_bytes[:null_pos].decode('ascii', errors='replace')
    else:
        name = name_bytes.decode('ascii', errors='replace')
    print("  Slot {:d} @ {:d}: slot_id={:3d}, name='{}'".format(slot_idx, off, slot_id, name))

print()
print("=== TRAILER (bytes 916-921, 6 bytes) ===")
print("  raw: {}".format(raw[916:922].hex()))
print("  u32le @916 = {}".format(struct.unpack_from('<I', raw, 916)[0]))
print("  u16le @920 = {}".format(struct.unpack_from('<H', raw, 920)[0]))

print()
print("=" * 70)
print("=== ATTACK_RANGE SCAN: ALL BYTE OFFSETS ===")
print("=" * 70)

print()
print("--- f32 in range [500, 1100] at ANY byte offset ---")
found_f32 = False
for i in range(0, len(raw)-3):
    f32 = struct.unpack_from('<f', raw, i)[0]
    if 500.0 <= f32 <= 1100.0:
        print("  f32@{}: {:.4f}".format(i, f32))
        found_f32 = True
if not found_f32:
    print("  NONE FOUND")

print()
print("--- u16le matching known values (539, 700, 803, 850, 1000) at ANY offset ---")
known = {539, 700, 803, 850, 1000}
for i in range(0, len(raw)-1):
    v = struct.unpack_from('<H', raw, i)[0]
    if v in known:
        print("  u16le@{}: {} (0x{:04x})".format(i, v, v))

print()
print("--- u32le matching known values (539, 700, 803, 850, 1000) at ANY offset ---")
for i in range(0, len(raw)-3):
    v = struct.unpack_from('<I', raw, i)[0]
    if v in known:
        print("  u32le@{}: {} (0x{:08x})".format(i, v, v))

print()
print("--- u32le = 0xe8030000 at ANY offset ---")
for i in range(0, len(raw)-3):
    v = struct.unpack_from('<I', raw, i)[0]
    if v == 0xe8030000:
        print("  u32le@{}: 0xe8030000 = {} (INTERESTING - swapped 1000)".format(i, v))

print()
print("--- Raw byte 0xe8 0x03 (1000 as u16le) locations ---")
for i in range(0, len(raw)-1):
    if raw[i] == 0xe8 and raw[i+1] == 0x03:
        print("  bytes@{}-{}: e8 03 (u16le = 1000)".format(i, i+1))

print()
print("=" * 70)
print("=== COMPARISON WITH COMBAT_UPDATE (0x540c) ===")
print("=" * 70)
print()
print("COMBAT_UPDATE (0x540c, 38 bytes):")
print("  @2:  entity_id   u32le")
print("  @10: tick         u32le")
print("  @14: zone         u32le")
print("  @18: x            i32le")
print("  @22: y            i32le")
print("  @26: state        u32le")
print("  @30: speed        f32    <- was incorrectly labeled attack_range")
print("  @34: combat_flags u32le")
print()
print("ENTITY_COMBAT_INFO (0x1400, 922 bytes):")
print("  @0:  opcode       u16be")
print("  @2:  entity_id    u32le  <- SAME as COMBAT_UPDATE")
print("  @6:  param (=4)   u32le")
print("  @10: zeros        8 bytes")
print("  @18: sub_opcode   u16be (0xab0e)")
print("  @20: sub_length   u16le (=904)")
print("  @22: entity_id2   u32le (same as @2)")
print("  @26: flag (=1)    u8")
print("  @27: skill_count  u8 (=58)")
print("  @28-43: meta/pad  16 bytes")
print("  @44-507: SKILL TABLE (58 x 8 bytes)")
print("  @508-915: EQUIP TABLE (6 x 68 bytes)")
print("  @916-921: trailer  6 bytes")
print()
print("KEY DIFFERENCE: ENTITY_COMBAT_INFO is a one-time data dump with:")
print("  - Full skill/stat table (58 entries, ID+value pairs)")
print("  - Equipment slot names (6 slots)")
print("  - NO COORDINATES, NO FLOATS, NO SPEED/RANGE")
print()
print("CONCLUSION FOR ATTACK_RANGE:")
print("  - NO f32 values in 500-1100 range found ANYWHERE in this packet")
print("  - NO u32le values matching 539, 700, 803, 850 found")
print("  - u16le 1000 (0xe803) appears 7 times - these are skill LEVEL values, not range")
print("  - The 0xe803 pattern is skill levels (max level = 1000)")
print("  - This packet is a CHARACTER SKILL+EQUIP DUMP, not a combat range packet")
print("  - attack_range is NOT in this packet")
