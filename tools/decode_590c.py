# -*- coding: utf-8 -*-
import json, struct, sys
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)

with open('D:/Project/GE_Phantom/data/autoattack_dummy.json', 'r') as f:
    data = json.load(f)

items = []
for p in data['packets']:
    for parsed in p.get('parsed', []):
        if parsed.get('opcode') == '0x590c':
            items.append({'time': p['time_str'], 'hex': parsed['hex'], 'size': parsed.get('size', len(parsed['hex'])//2)})

NUL = b'\x00'

print('=== 0x590c COMPLETE STRUCTURE DECODE ===')
print()

raw = bytes.fromhex(items[0]['hex'])
font = raw[12:76].split(NUL)[0].decode('ascii')
dmg = raw[86:96].split(NUL)[0].decode('ascii', errors='replace')
print('SIZE 219 VARIANT (24 instances) - Instance 1:')
print(f'  [0-1]   opcode:      0x590c')
print(f'  [2-3]   payload_len: u16le = {struct.unpack_from("<H", raw, 2)[0]}')
print(f'  [4-7]   entity_id:   0x{struct.unpack_from("<I", raw, 4)[0]:08x} = {struct.unpack_from("<I", raw, 4)[0]}')
print(f'  [8]     byte8:       0x{raw[8]:02x} = {raw[8]}  (0xCC=204)')
print(f'  [9]     byte9:       0x{raw[9]:02x} = {raw[9]}')
print(f'  [10]    byte10:      0x{raw[10]:02x} = {raw[10]}  (0xFF)')
print(f'  [11]    byte11:      0x{raw[11]:02x} = {raw[11]}  (0x7D=125)')
print(f'  [12-75] font_name:   "{font}" + null padding to 64 bytes')
print(f'  [76-77] u16@76:      {struct.unpack_from("<H", raw, 76)[0]}  <<<< ALWAYS 700!')
print(f'  [78-79] u16@78:      {struct.unpack_from("<H", raw, 78)[0]}  (=5)')
print(f'  [80-81] u16@80:      {struct.unpack_from("<H", raw, 80)[0]}  (=0)')
print(f'  [82-83] u16@82:      {struct.unpack_from("<H", raw, 82)[0]}  (=300)')
print(f'  [84-85] u16@84:      {struct.unpack_from("<H", raw, 84)[0]}  (=0)')
print(f'  [86-95] damage_text: "{dmg}" (null-terminated)')
print()
print('  --- EMBEDDED BATCH_ENTITY_UPDATE at offset 96 ---')
print(f'  [96-97]   opcode:     0x{struct.unpack_from("<H", raw, 96)[0]:04x} = BATCH_ENTITY_UPDATE')
print(f'  [98-99]   u16le:      {struct.unpack_from("<H", raw, 98)[0]} (=123, batch payload len)')

# Player entity in batch
print(f'  [100-103] player_eid: 0x{struct.unpack_from("<I", raw, 100)[0]:08x}')
print(f'  [104-107] player_x:   {struct.unpack_from("<i", raw, 104)[0]}')
print(f'  [108-111] player_y:   {struct.unpack_from("<i", raw, 108)[0]}')
print(f'  [112-113] player_z:   {struct.unpack_from("<H", raw, 112)[0]}')
print(f'  [114-117] u32:        {struct.unpack_from("<I", raw, 114)[0]}  (=1683)')

# Target entity
print(f'  [118-121] target_eid: 0x{struct.unpack_from("<I", raw, 118)[0]:08x}')
print(f'  [122-125] target_x:   {struct.unpack_from("<i", raw, 122)[0]}')
print(f'  [126-129] target_y:   {struct.unpack_from("<i", raw, 126)[0]}')
print(f'  [130-131] target_z:   {struct.unpack_from("<H", raw, 130)[0]}')
print(f'  [132-135] u32:        {struct.unpack_from("<I", raw, 132)[0]}')

# Key float region
print(f'  [136-137] u16:        {struct.unpack_from("<H", raw, 136)[0]}')
print(f'  [138-141] u32/f32:    {struct.unpack_from("<I", raw, 138)[0]} / {struct.unpack_from("<f", raw, 138)[0]:.4f}')
print(f'  [140-143] u32/f32:    {struct.unpack_from("<I", raw, 140)[0]} / {struct.unpack_from("<f", raw, 140)[0]:.4f}')

f64_142 = struct.unpack_from('<d', raw, 142)[0]
f64_148 = struct.unpack_from('<d', raw, 148)[0]
print(f'  [142-149] f64:        {f64_142:.6f}  (oscillates between -2, 0, 2)')
print(f'  [148-155] f64:        {f64_148:.6f}')

# Actually let me decode the f64@148 bytes directly
f64_bytes = raw[148:156]
print(f'            raw bytes:  {f64_bytes.hex()}')

# What about decoding bytes 148+ differently?
print(f'  [148-151] f32:        {struct.unpack_from("<f", raw, 148)[0]:.6f}')
print(f'  [152-155] f32:        {struct.unpack_from("<f", raw, 152)[0]:.6f}  <<< THIS IS THE BIG ONE')

# Let me decode f32@152 for ALL instances
print()
print('=== f32@152 for ALL 0x590c instances ===')
for i, item in enumerate(items):
    raw = bytes.fromhex(item['hex'])
    if len(raw) > 156:
        v = struct.unpack_from('<f', raw, 152)[0]
        raw_hex = raw[152:156].hex()
        print(f'  #{i+1:2d} t={item["time"]} f32@152 = {v:.4f}  hex={raw_hex}')

# The f64 values at 148 are confusing because they cross the entity boundary
# Let me look at what's really at offset 148
print()
print('=== ACTUAL f64@148 VALUES (all 0x590c) ===')
for i, item in enumerate(items):
    raw = bytes.fromhex(item['hex'])
    if len(raw) > 156:
        v = struct.unpack_from('<d', raw, 148)[0]
        raw_hex = raw[148:156].hex()
        # Also try reading as two u32
        u32a = struct.unpack_from('<I', raw, 148)[0]
        u32b = struct.unpack_from('<I', raw, 152)[0]
        print(f'  #{i+1:2d} t={item["time"]} f64@148={v:.4f}  u32@148={u32a} u32@152={u32b}')

# DAMAGE TEXT across all
print()
print('=== DAMAGE TEXTS ===')
for i, item in enumerate(items):
    raw = bytes.fromhex(item['hex'])
    dmg = raw[86:96].split(NUL)[0].decode('ascii', errors='replace')
    print(f'  #{i+1:2d} t={item["time"]} size={item["size"]} damage="{dmg}"')

# SIZE 215 VARIANT structural comparison
print()
print('=== SIZE 215 VARIANT - first instance ===')
raw215 = bytes.fromhex([i for i in items if i['size']==215][0]['hex'])
font215 = raw215[12:76].split(NUL)[0].decode('ascii')
dmg215 = raw215[86:96].split(NUL)[0].decode('ascii', errors='replace')

print(f'  Bytes 0-95 identical header structure')
print(f'  font: "{font215}"')
print(f'  u16@76: {struct.unpack_from("<H", raw215, 76)[0]}')
print(f'  u16@82: {struct.unpack_from("<H", raw215, 82)[0]}')
print(f'  damage: "{dmg215}"')

# Check: is the 215 variant missing the damage text or has a shorter one?
print(f'  Offset 84-96 hex: {raw215[84:96].hex()}')
# The size difference is 219-215 = 4 bytes
# Check where the bytes differ
print()
print('=== Checking if 0x590c is a DAMAGE FLOAT TEXT PACKET ===')
print(f'  Size 219 instances show damage "259 (259)" = consistent damage')
print(f'  Size 215 instances show damage "1 (1)" = miss/minimal damage')
print(f'  u16@76 = 700 ALWAYS = THIS IS attack_range!')
print(f'  u16@82 = 300 ALWAYS')

# bd0c analysis
print()
print('=== 0xbd0c DECODE (19 instances, 10-byte) ===')
bd_items = []
for p in data['packets']:
    for parsed in p.get('parsed', []):
        if parsed.get('opcode') == '0xbd0c':
            bd_items.append({'time': p['time_str'], 'hex': parsed['hex'], 'size': parsed.get('size', len(parsed['hex'])//2)})

for i, item in enumerate(bd_items):
    raw = bytes.fromhex(item['hex'])
    if len(raw) == 10:
        eid = struct.unpack_from('<I', raw, 2)[0]
        val = struct.unpack_from('<I', raw, 6)[0]
        val16 = struct.unpack_from('<H', raw, 6)[0]
        print(f'  #{i+1:2d} t={item["time"]} eid=0x{eid:08x} u32@6={val} u16@6={val16}')
    else:
        print(f'  #{i+1:2d} t={item["time"]} size={len(raw)}B (DIFFERENT SIZE)')
        # Decode the big one
        if len(raw) > 100:
            print(f'       This is the 589-byte variant with embedded stat data')
            # Find texts
            texts = []
            j = 0
            while j < len(raw):
                if 32 <= raw[j] < 127:
                    start = j
                    while j < len(raw) and 32 <= raw[j] < 127:
                        j += 1
                    s = ''.join(chr(b) for b in raw[start:j])
                    if len(s) >= 3:
                        texts.append((start, s))
                else:
                    j += 1
            for off, s in texts:
                sl = s.lower()
                flag = ""
                if any(k in sl for k in ['range', 'atk', 'shoot', 'attack', 'dist', 'reach']):
                    flag = ' *** KEYWORD ***'
                print(f'       TEXT @{off}: "{s}"{flag}')
