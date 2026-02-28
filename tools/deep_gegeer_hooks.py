"""Deep analysis of geGeer.exe - hook strings, xrefs, PropertyNumberAll"""
import pefile
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

GEGEER = r"D:\AutoDownload-Chrome\AIgeHS Version.2025-10-03a By HeavenSaber\release\release\geGeer.exe"

pe = pefile.PE(GEGEER)
data = open(GEGEER, 'rb').read()
image_base = pe.OPTIONAL_HEADER.ImageBase  # usually 0x00400000

def va_to_offset(va):
    rva = va - image_base
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

def offset_to_va(off):
    for s in pe.sections:
        if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
            rva = s.VirtualAddress + (off - s.PointerToRawData)
            return image_base + rva
    return None

def disasm_at(va, count=40, ctx_before=32):
    """Disassemble around a VA with context before"""
    off = va_to_offset(va)
    if off is None:
        return f"  [Cannot resolve VA 0x{va:08X}]"

    start_off = max(0, off - ctx_before)
    start_va = offset_to_va(start_off) or (va - ctx_before)
    chunk = data[start_off:start_off + ctx_before + 200]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    lines = []
    for insn in md.disasm(chunk, start_va):
        marker = " <<<" if insn.address == va else ""
        if abs(insn.address - va) <= 80:
            lines.append(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}{marker}")
        if len(lines) >= count:
            break
    return '\n'.join(lines)

def find_xrefs_to_va(target_va, scan_sections=['.text']):
    """Find all PUSH/MOV references to a VA in code sections"""
    results = []
    target_bytes_le = struct.pack('<I', target_va)

    for section in pe.sections:
        name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if scan_sections and name not in scan_sections:
            continue

        sec_data = data[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
        pos = 0
        while True:
            pos = sec_data.find(target_bytes_le, pos)
            if pos < 0:
                break

            file_off = section.PointerToRawData + pos
            ref_va = image_base + section.VirtualAddress + pos

            # Check preceding byte for PUSH (0x68) or MOV variants
            if pos > 0:
                prev_byte = sec_data[pos - 1]
                if prev_byte == 0x68:  # PUSH imm32
                    results.append((ref_va - 1, 'PUSH', target_va))
                elif prev_byte in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF):  # MOV reg, imm32
                    reg_names = ['EAX','ECX','EDX','EBX','ESP','EBP','ESI','EDI']
                    reg = reg_names[prev_byte - 0xB8]
                    results.append((ref_va - 1, f'MOV {reg}', target_va))
                else:
                    results.append((ref_va, 'REF', target_va))
            pos += 1
    return results

def read_string_at_va(va, max_len=100):
    off = va_to_offset(va)
    if off is None:
        return "<unresolvable>"
    end = min(off + max_len, len(data))
    s = []
    for b in data[off:end]:
        if b == 0:
            break
        if 32 <= b < 127:
            s.append(chr(b))
        else:
            break
    return ''.join(s)

# ===========================================================
print("=" * 70)
print("TASK 1: HOOK STRINGS DISASSEMBLY")
print("=" * 70)

hook_addresses = [
    (0x0084A661, '"hook" #1'),
    (0x0084A693, '"hook" #2'),
    (0x0084A6A7, '"hook" #3'),
    (0x008F625A, '"HookEx"'),
]

for va, label in hook_addresses:
    print(f"\n--- {label} at VA=0x{va:08X} ---")
    # First read what string is actually there
    s = read_string_at_va(va)
    print(f"  String: \"{s}\"")
    print(f"\n  Context (code referencing this area):")

    # Find xrefs TO this string address
    xrefs = find_xrefs_to_va(va)
    if xrefs:
        for xva, xtype, _ in xrefs:
            print(f"\n  XREF: {xtype} at 0x{xva:08X}")
            print(disasm_at(xva))
    else:
        # The VA might BE code, not a string reference
        print(f"  No xrefs found - disassembling AT this VA:")
        print(disasm_at(va))

# ===========================================================
print("\n" + "=" * 70)
print("TASK 2: AiRange / ViewRange VTABLE ANALYSIS")
print("=" * 70)

# From handoff: AiRange VA=0x00BC545C, ViewRange VA=0x00BC5450
# These use vtable[0x14] instead of [0x10]
for prop_name, str_va in [("AiRange", 0x00BC545C), ("ViewRange", 0x00BC5450)]:
    print(f"\n--- {prop_name} (string VA=0x{str_va:08X}) ---")
    s = read_string_at_va(str_va)
    print(f"  String: \"{s}\"")

    xrefs = find_xrefs_to_va(str_va)
    print(f"  Found {len(xrefs)} xrefs:")
    for xva, xtype, _ in xrefs[:10]:  # limit output
        print(f"\n  XREF: {xtype} at 0x{xva:08X}")
        print(disasm_at(xva, count=25))

# Also show KeepRange for comparison
print(f"\n--- KeepRange (string VA=0x00B9F6C0) for comparison ---")
kr_xrefs = find_xrefs_to_va(0x00B9F6C0)
print(f"  Found {len(kr_xrefs)} xrefs:")
for xva, xtype, _ in kr_xrefs[:5]:
    print(f"\n  XREF: {xtype} at 0x{xva:08X}")
    print(disasm_at(xva, count=25))

# ===========================================================
print("\n" + "=" * 70)
print("TASK 3: PropertyNumberAll XREFS")
print("=" * 70)

pna_va = 0x00BCA021
s = read_string_at_va(pna_va)
print(f"PropertyNumberAll string: \"{s}\" at VA=0x{pna_va:08X}")

xrefs = find_xrefs_to_va(pna_va)
print(f"Found {len(xrefs)} xrefs:")
for xva, xtype, _ in xrefs:
    print(f"\n  XREF: {xtype} at 0x{xva:08X}")
    print(disasm_at(xva, count=30))

# Also check nearby strings for context
print("\n--- Nearby strings around PropertyNumberAll ---")
for offset in range(-64, 65, 1):
    test_va = pna_va + offset
    s = read_string_at_va(test_va, 30)
    if len(s) >= 5 and s.isascii():
        print(f"  0x{test_va:08X}: \"{s}\"")

# ===========================================================
print("\n" + "=" * 70)
print("TASK 5: GetPropertyNumber XREFS in geGeer")
print("=" * 70)

gpn_va = 0x00BFE02C
s = read_string_at_va(gpn_va)
print(f"GetPropertyNumber string: \"{s}\" at VA=0x{gpn_va:08X}")

xrefs = find_xrefs_to_va(gpn_va)
print(f"Found {len(xrefs)} xrefs:")
for xva, xtype, _ in xrefs:
    print(f"\n  XREF: {xtype} at 0x{xva:08X}")
    print(disasm_at(xva, count=30))

# Also check SetPropertyNumber
spn_va = 0x00BCA0C8
s = read_string_at_va(spn_va)
print(f"\nSetPropertyNumber string: \"{s}\" at VA=0x{spn_va:08X}")

xrefs = find_xrefs_to_va(spn_va)
print(f"Found {len(xrefs)} xrefs:")
for xva, xtype, _ in xrefs:
    print(f"\n  XREF: {xtype} at 0x{xva:08X}")
    print(disasm_at(xva, count=30))

print("\n\nDone.")
