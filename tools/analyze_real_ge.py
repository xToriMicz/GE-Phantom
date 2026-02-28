import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

"""Analyze the REAL game ge.exe at D:\\Games\\Granado Espada\\ge.exe
Compare with AIgeHS ge.exe to understand differences and find equivalent functions.
"""
import pefile
import struct
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

REAL_GE = r"D:\Games\Granado Espada\ge.exe"
AIGE_GE = r"D:\AutoDownload-Chrome\AIgeHS Version.2025-10-03a By HeavenSaber\release\release\ge.exe"

def load_bin(path):
    pe = pefile.PE(path)
    raw = open(path, 'rb').read()
    ib = pe.OPTIONAL_HEADER.ImageBase
    return pe, raw, ib

pe_real, data_real, ib_real = load_bin(REAL_GE)
pe_aige, data_aige, ib_aige = load_bin(AIGE_GE)

print("=" * 70)
print("1. BASIC COMPARISON")
print("=" * 70)
print(f"Real ge.exe:  {len(data_real):,} bytes, ImageBase=0x{ib_real:08X}")
print(f"AIgeHS ge.exe: {len(data_aige):,} bytes, ImageBase=0x{ib_aige:08X}")

print(f"\nReal ge.exe sections:")
for s in pe_real.sections:
    name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    print(f"  {name:10s} VA=0x{s.VirtualAddress:08X} VSize=0x{s.Misc_VirtualSize:08X} "
          f"RawSize=0x{s.SizeOfRawData:08X} Flags=0x{s.Characteristics:08X}")

print(f"\nAIgeHS ge.exe sections:")
for s in pe_aige.sections:
    name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    print(f"  {name:10s} VA=0x{s.VirtualAddress:08X} VSize=0x{s.Misc_VirtualSize:08X} "
          f"RawSize=0x{s.SizeOfRawData:08X} Flags=0x{s.Characteristics:08X}")

# Check if real ge.exe is packed
print(f"\nReal ge.exe entry point: 0x{pe_real.OPTIONAL_HEADER.AddressOfEntryPoint + ib_real:08X}")
print(f"AIgeHS ge.exe entry point: 0x{pe_aige.OPTIONAL_HEADER.AddressOfEntryPoint + ib_aige:08X}")

# Check for packing signatures
if data_real[:2] == b'MZ':
    # Check for UPX
    if b'UPX' in data_real[:0x1000]:
        print("\nReal ge.exe: UPX packed!")
    else:
        print("\nReal ge.exe: NOT UPX packed")

    # Check for Themida/VMProtect/other
    section_names = [s.Name.rstrip(b'\x00').decode('ascii', errors='replace') for s in pe_real.sections]
    print(f"Section names: {section_names}")

# ===========================================================
print("\n" + "=" * 70)
print("2. SEARCH FOR KEY STRINGS IN REAL ge.exe")
print("=" * 70)

search_strings = [
    b'KeepRange\x00',
    b'SplRange\x00',
    b'AiRange\x00',
    b'ViewRange\x00',
    b'GetPropertyNumber\x00',
    b'SetPropertyNumber\x00',
    b'ScalePropertyNumberAll\x00',
    b'PropertyNumberAll\x00',
    b'imcPropertySys\x00',
    b'ge.pdb\x00',
    b'D:\\THI\\',
    b'tolua',
    b'GetByClassName\x00',
]

def find_string_va(pe, raw, ib, needle):
    pos = raw.find(needle)
    if pos < 0:
        return None
    for s in pe.sections:
        if s.PointerToRawData <= pos < s.PointerToRawData + s.SizeOfRawData:
            return ib + s.VirtualAddress + (pos - s.PointerToRawData)
    return None

for needle in search_strings:
    va = find_string_va(pe_real, data_real, ib_real, needle)
    name = needle.rstrip(b'\x00').decode('ascii', errors='replace')
    if va:
        print(f"  {name:30s} -> VA=0x{va:08X}")
    else:
        print(f"  {name:30s} -> NOT FOUND")

# ===========================================================
print("\n" + "=" * 70)
print("3. FIND PDB PATH AND COMPILE INFO")
print("=" * 70)

# Search for .pdb path
for m in re.finditer(rb'[A-Z]:\\[^\x00]{5,100}\.pdb', data_real):
    print(f"  PDB: {m.group().decode('ascii', errors='replace')}")

# Search for compile date strings
for m in re.finditer(rb'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4}', data_real):
    print(f"  Date: {m.group().decode('ascii', errors='replace')}")

# ===========================================================
print("\n" + "=" * 70)
print("4. IF STRINGS FOUND - TRACE XREFS")
print("=" * 70)

def va_to_offset(pe, raw, ib, va):
    rva = va - ib
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

def find_xrefs(pe, raw, ib, target_va):
    results = []
    target_bytes = struct.pack('<I', target_va)
    for section in pe.sections:
        name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        chars = section.Characteristics
        # Only scan executable sections
        if not (chars & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
            continue
        sec_data = raw[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
        pos = 0
        while True:
            pos = sec_data.find(target_bytes, pos)
            if pos < 0: break
            ref_va = ib + section.VirtualAddress + pos
            prev = sec_data[pos-1] if pos > 0 else 0
            results.append((ref_va, prev))
            pos += 1
    return results

def disasm_at(pe, raw, ib, va, count=20):
    off = va_to_offset(pe, raw, ib, va)
    if off is None: return "  [cannot resolve]"
    chunk = raw[off:off+200]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    lines = []
    for insn in md.disasm(chunk, va):
        lines.append(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")
        if len(lines) >= count: break
    return '\n'.join(lines)

# Try KeepRange
kr_va = find_string_va(pe_real, data_real, ib_real, b'KeepRange\x00')
if kr_va:
    print(f"\nKeepRange xrefs (VA=0x{kr_va:08X}):")
    xrefs = find_xrefs(pe_real, data_real, ib_real, kr_va)
    print(f"  Found {len(xrefs)} xrefs")
    for ref_va, prev in xrefs[:5]:
        if prev == 0x68:
            print(f"\n  PUSH at 0x{ref_va-1:08X}:")
            print(disasm_at(pe_real, data_real, ib_real, ref_va - 15, 20))

# Try GetPropertyNumber
gpn_va = find_string_va(pe_real, data_real, ib_real, b'GetPropertyNumber\x00')
if gpn_va:
    print(f"\nGetPropertyNumber xrefs (VA=0x{gpn_va:08X}):")
    xrefs = find_xrefs(pe_real, data_real, ib_real, gpn_va)
    print(f"  Found {len(xrefs)} xrefs")
    for ref_va, prev in xrefs[:3]:
        if prev == 0x68:
            print(f"\n  PUSH at 0x{ref_va-1:08X}:")
            print(disasm_at(pe_real, data_real, ib_real, ref_va - 10, 25))

# ===========================================================
print("\n" + "=" * 70)
print("5. SIGNATURE SCAN - Match core function by byte pattern")
print("=" * 70)

# The core GetPropertyNumber in AIgeHS ge.exe starts with:
# 55 8B EC 51 51 FF 75 10 8D 4D FC E8 xx xx xx xx FF 75 08 8D 4D F8 E8 xx xx xx xx
# (push ebp; mov ebp,esp; push ecx; push ecx; push [ebp+10]; lea ecx,[ebp-4]; call rel32;
#  push [ebp+8]; lea ecx,[ebp-8]; call rel32)
#
# Create a pattern with wildcards for call targets

# Pattern bytes (xx = wildcard)
pattern = bytes([
    0x55,                       # push ebp
    0x8B, 0xEC,                 # mov ebp, esp
    0x51,                       # push ecx
    0x51,                       # push ecx
    0xFF, 0x75, 0x10,           # push [ebp+10]
    0x8D, 0x4D, 0xFC,           # lea ecx, [ebp-4]
])
# After this: E8 xx xx xx xx FF 75 08 8D 4D F8 E8 xx xx xx xx 8D 45 FC 50 FF 75 0C 8D 45 F8 50

suffix_pattern = bytes([
    0xFF, 0x75, 0x08,           # push [ebp+8]
    0x8D, 0x4D, 0xF8,           # lea ecx, [ebp-8]
])

# The full pattern: prefix + E8 xx xx xx xx + suffix + E8 xx xx xx xx + ...
# Scan .text section

for section in pe_real.sections:
    name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    chars = section.Characteristics
    if not (chars & 0x20000000): continue

    sec_data = data_real[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
    sec_va = ib_real + section.VirtualAddress

    pos = 0
    matches = []
    while pos < len(sec_data) - 30:
        # Check prefix
        if sec_data[pos:pos+11] == pattern:
            # Check for E8 (call) at pos+11
            if sec_data[pos+11] == 0xE8:
                # Check suffix at pos+16
                if sec_data[pos+16:pos+22] == suffix_pattern:
                    # Check for E8 (call) at pos+22
                    if sec_data[pos+22] == 0xE8:
                        match_va = sec_va + pos
                        matches.append(match_va)
        pos += 1

    if matches:
        print(f"Found {len(matches)} signature matches in {name}:")
        for m_va in matches:
            print(f"\n  Match at VA=0x{m_va:08X}:")
            print(disasm_at(pe_real, data_real, ib_real, m_va, 15))

            # Extract the call targets
            off = va_to_offset(pe_real, data_real, ib_real, m_va)
            # First call at offset +11: E8 xx xx xx xx
            call1_rel = struct.unpack_from('<i', data_real, off + 12)[0]
            call1_target = m_va + 11 + 5 + call1_rel
            # Second call at offset +22: E8 xx xx xx xx
            call2_rel = struct.unpack_from('<i', data_real, off + 23)[0]
            call2_target = m_va + 22 + 5 + call2_rel

            print(f"  -> String resolver (call 1): 0x{call1_target:08X}")
            print(f"  -> String resolver (call 2): 0x{call2_target:08X}")

            # Third call should be inner_get
            # Pattern continues: 8D 45 FC 50 FF 75 0C 8D 45 F8 50 E8 xx xx xx xx
            if sec_data[pos-1+27] == 0x8D:  # lea eax, [ebp-4]
                # Find the next E8 call
                for scan in range(27, 40):
                    if off + scan < len(data_real) and data_real[off + scan] == 0xE8:
                        call3_rel = struct.unpack_from('<i', data_real, off + scan + 1)[0]
                        call3_target = m_va + scan + 5 + call3_rel
                        print(f"  -> Inner get_property (call 3): 0x{call3_target:08X}")
                        break
    else:
        print(f"No matches in {name}")

print("\n\nDone.")
