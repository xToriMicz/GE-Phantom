import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

"""Deep analysis of real ge.exe - understand its structure"""
import pefile
import struct
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

REAL_GE = r"D:\Games\Granado Espada\ge.exe"

pe = pefile.PE(REAL_GE)
data = open(REAL_GE, 'rb').read()
ib = pe.OPTIONAL_HEADER.ImageBase

def va_to_offset(va):
    rva = va - ib
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

def read_string_at(va, max_len=200):
    off = va_to_offset(va)
    if off is None: return "<unresolvable>"
    s = []
    for b in data[off:off+max_len]:
        if b == 0: break
        if 32 <= b < 127: s.append(chr(b))
        else: break
    return ''.join(s)

# ===========================================================
print("=" * 70)
print("1. IMPORTS - What DLLs does real ge.exe use?")
print("=" * 70)

if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('ascii', errors='replace')
        funcs = [imp.name.decode('ascii', errors='replace') if imp.name else f"ord#{imp.ordinal}" for imp in entry.imports[:5]]
        more = f" ... +{len(entry.imports)-5} more" if len(entry.imports) > 5 else ""
        print(f"  {dll:30s} ({len(entry.imports)} funcs) {', '.join(funcs)}{more}")

# ===========================================================
print("\n" + "=" * 70)
print("2. SplRange CONTEXT - What's around the only found string?")
print("=" * 70)

# SplRange at 0x006E549C
spl_va = 0x006E549C
spl_off = va_to_offset(spl_va)
print(f"SplRange at VA=0x{spl_va:08X}, file offset=0x{spl_off:08X}")
print(f"Section: .rdata (starts at VA=0x{ib + 0x002DF000:08X})")

# Read surrounding strings
print("\nNearby strings (+-256 bytes):")
for delta in range(-256, 512):
    test_va = spl_va + delta
    s = read_string_at(test_va, 50)
    if len(s) >= 4 and s[0].isalpha() and not any(c in s for c in '{}[]'):
        # Deduplicate - only print if this is the START of the string
        prev_off = va_to_offset(test_va - 1)
        if prev_off and data[prev_off] == 0:
            print(f"  0x{test_va:08X}: \"{s}\"")

# ===========================================================
print("\n" + "=" * 70)
print("3. SEARCH FOR PROPERTY-RELATED STRINGS")
print("=" * 70)

# Since KeepRange is missing, search for partial/related strings
partial_searches = [
    b'Range',
    b'Property',
    b'tolua',
    b'GetBy',
    b'SetBy',
    b'vtable',
    b'idspace',
    b'IES',
    b'ClassList',
    b'propName',
    b'propId',
    b'prop_id',
    b'KeepR',
    b'keepr',
    b'keepRange',
]

for needle in partial_searches:
    count = 0
    pos = 0
    first_va = None
    while True:
        pos = data.find(needle, pos)
        if pos < 0: break
        if count == 0:
            for s in pe.sections:
                if s.PointerToRawData <= pos < s.PointerToRawData + s.SizeOfRawData:
                    first_va = ib + s.VirtualAddress + (pos - s.PointerToRawData)
                    break
        count += 1
        pos += 1
    name = needle.decode('ascii', errors='replace')
    if count > 0:
        print(f"  '{name}': {count} occurrences, first at VA=0x{first_va:08X}")
    else:
        print(f"  '{name}': NOT FOUND")

# ===========================================================
print("\n" + "=" * 70)
print("4. ALL 'Range' STRING OCCURRENCES")
print("=" * 70)

pos = 0
range_strings = []
while True:
    pos = data.find(b'Range', pos)
    if pos < 0: break
    # Check if it's a proper string (preceded by null or alpha)
    if pos > 0 and data[pos-1] == 0:
        # Read the full string
        end = pos
        while end < len(data) and data[end] != 0:
            end += 1
        s = data[pos:end].decode('ascii', errors='replace')
        if len(s) >= 5 and len(s) <= 50 and s.isprintable():
            for sec in pe.sections:
                if sec.PointerToRawData <= pos < sec.PointerToRawData + sec.SizeOfRawData:
                    va = ib + sec.VirtualAddress + (pos - sec.PointerToRawData)
                    range_strings.append((va, s))
                    break
    pos += 1

for va, s in range_strings[:40]:
    print(f"  0x{va:08X}: \"{s}\"")
print(f"  Total: {len(range_strings)}")

# ===========================================================
print("\n" + "=" * 70)
print("5. GAME DIRECTORY - Look for DLLs and other executables")
print("=" * 70)

import os
game_dir = r"D:\Games\Granado Espada"
interesting = []
for f in os.listdir(game_dir):
    fp = os.path.join(game_dir, f)
    if os.path.isfile(fp):
        ext = os.path.splitext(f)[1].lower()
        if ext in ('.exe', '.dll', '.ipf'):
            size = os.path.getsize(fp)
            interesting.append((f, size, ext))

interesting.sort(key=lambda x: -x[1])
for name, size, ext in interesting[:30]:
    print(f"  {name:40s} {size:>12,} bytes  {ext}")

# Check for subdirectories with DLLs
print("\nSubdirectories:")
for d in os.listdir(game_dir):
    dp = os.path.join(game_dir, d)
    if os.path.isdir(dp):
        files = os.listdir(dp)
        dll_count = sum(1 for f in files if f.lower().endswith(('.dll', '.exe')))
        print(f"  {d:30s} ({len(files)} files, {dll_count} dll/exe)")

# ===========================================================
print("\n" + "=" * 70)
print("6. CHECK IF GAME LOADS CODE FROM IPF FILES")
print("=" * 70)

# Search for .ipf references in ge.exe
ipf_strings = []
pos = 0
while True:
    pos = data.find(b'.ipf', pos)
    if pos < 0: break
    # Read surrounding context
    start = max(0, pos - 30)
    end = min(len(data), pos + 20)
    ctx = data[start:end]
    # Extract printable context
    s = ''
    for b in ctx:
        if 32 <= b < 127:
            s += chr(b)
        else:
            s += '.'
    ipf_strings.append(s)
    pos += 1

print(f"Found {len(ipf_strings)} .ipf references")
# Show unique ones
seen = set()
for s in ipf_strings:
    cleaned = s.strip('.')
    if cleaned not in seen and len(cleaned) > 5:
        seen.add(cleaned)
        print(f"  {cleaned}")
    if len(seen) > 30:
        print(f"  ... and more")
        break

print("\n\nDone.")
