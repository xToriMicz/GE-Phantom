"""Phase 2: Deep analysis of geGeer.exe
- Disassemble GetPropertyNumber callback (0x008CF7EC)
- Check string at 0x00bc5464 (vtable[0x1c] call)
- Find ScalePropertyNumberAll xrefs
- Find UPDATE_PROPERTY packet handler code
- Map the full vtable layout
"""
import pefile
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

GEGEER = r"D:\AutoDownload-Chrome\AIgeHS Version.2025-10-03a By HeavenSaber\release\release\geGeer.exe"

pe = pefile.PE(GEGEER)
data = open(GEGEER, 'rb').read()
image_base = pe.OPTIONAL_HEADER.ImageBase

def va_to_offset(va):
    rva = va - image_base
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

def offset_to_va(off):
    for s in pe.sections:
        if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
            return image_base + s.VirtualAddress + (off - s.PointerToRawData)
    return None

def read_string_at_va(va, max_len=200):
    off = va_to_offset(va)
    if off is None:
        return "<unresolvable>"
    s = []
    for b in data[off:off+max_len]:
        if b == 0: break
        if 32 <= b < 127: s.append(chr(b))
        else: break
    return ''.join(s)

def disasm_at(va, count=50):
    off = va_to_offset(va)
    if off is None:
        return f"  [Cannot resolve VA 0x{va:08X}]"
    chunk = data[off:off+300]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    lines = []
    for insn in md.disasm(chunk, va):
        lines.append(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")
        if len(lines) >= count:
            break
    return '\n'.join(lines)

def find_all_refs(target_va, sections=['.text']):
    """Find all 4-byte references to target_va in code"""
    results = []
    target_bytes = struct.pack('<I', target_va)
    for section in pe.sections:
        name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if sections and name not in sections:
            continue
        sec_data = data[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
        pos = 0
        while True:
            pos = sec_data.find(target_bytes, pos)
            if pos < 0: break
            ref_va = image_base + section.VirtualAddress + pos
            prev = sec_data[pos-1] if pos > 0 else 0
            results.append((ref_va, prev))
            pos += 1
    return results

# ===========================================================
print("=" * 70)
print("1. GetPropertyNumber CALLBACK at 0x008CF7EC")
print("=" * 70)
print("This is the tolua callback for GetPropertyNumber in geGeer")
print()
print(disasm_at(0x008CF7EC, 60))

# ===========================================================
print("\n" + "=" * 70)
print("2. STRING at 0x00BC5464 (used with vtable[0x1c])")
print("=" * 70)
s = read_string_at_va(0x00BC5464)
print(f"  VA 0x00BC5464: \"{s}\"")

# Also check nearby strings
for delta in range(-32, 64, 1):
    va = 0x00BC5464 + delta
    ss = read_string_at_va(va, 40)
    if len(ss) >= 4 and ss[0].isupper():
        print(f"  VA 0x{va:08X}: \"{ss}\"")

# ===========================================================
print("\n" + "=" * 70)
print("3. ScalePropertyNumberAll XREFS")
print("=" * 70)
# The full string is at 0x00BCA01C
spna_va = 0x00BCA01C
refs = find_all_refs(spna_va)
print(f"Refs to 0x{spna_va:08X} (\"ScalePropertyNumberAll\"): {len(refs)}")
for ref_va, prev in refs:
    if prev == 0x68:
        print(f"\n  PUSH at 0x{ref_va-1:08X}:")
        print(disasm_at(ref_va - 1, 20))
    elif prev >= 0xB8 and prev <= 0xBF:
        print(f"\n  MOV reg at 0x{ref_va-1:08X}:")
        print(disasm_at(ref_va - 1, 20))
    else:
        print(f"\n  REF at 0x{ref_va:08X} (prev_byte=0x{prev:02X}):")
        print(disasm_at(ref_va - 5, 20))

# ===========================================================
print("\n" + "=" * 70)
print("4. UPDATE_PROPERTY PACKET HANDLERS")
print("=" * 70)

# Find the string VAs for the new packet types
update_packets = [
    "PKS_BC_UPDATE_PROPERTY_NUMBER",
    "PKS_BC_UPDATE_PROPERTY_STRING",
    "PKS_ZC_UPDATE_PROPERTY_NUMBER",
    "PKS_ZC_UPDATE_PROPERTY_STRING",
    "PKS_ZC_FIELDOBJECT_PROPERTY",
]

for pkt_name in update_packets:
    pkt_bytes = pkt_name.encode('ascii') + b'\x00'
    pos = data.find(pkt_bytes)
    if pos < 0:
        print(f"  {pkt_name}: NOT FOUND")
        continue
    str_va = offset_to_va(pos)
    print(f"\n--- {pkt_name} (string VA=0x{str_va:08X}) ---")

    refs = find_all_refs(str_va)
    print(f"  {len(refs)} xrefs:")
    for ref_va, prev in refs[:5]:
        if prev == 0x68:
            print(f"  PUSH at 0x{ref_va-1:08X}:")
            print(disasm_at(ref_va - 1, 15))

# ===========================================================
print("\n" + "=" * 70)
print("5. VTABLE LAYOUT RECONSTRUCTION")
print("=" * 70)

# We know from the code:
# vtable[0x10] = GET (used by KeepRange)
# vtable[0x14] = GET_float (used by ViewRange, AiRange)
# vtable[0x1c] = unknown (used after AiRange)
# vtable[0x28] = SET (used by KeepRange setter)
#
# Let's find the actual vtable by looking at how the property object is accessed.
# From KeepRange xref#1: mov esi, [eax + 0x198] → esi = property object
# Then: mov edi, [esi] → edi = vtable
# So property object is at offset 0x198 in some parent object

# Let's look at the function at 0x006B17xx more carefully - it reads ViewRange, AiRange
# and also uses vtable[0x1c]
print("Function reading ViewRange/AiRange/??? (full disassembly from function start):")
# Walk back to find function start (look for push ebp or sub esp pattern)
# The ViewRange code is at 0x006B17C2, let's scan back
func_start = 0x006B1700  # rough estimate
print(disasm_at(func_start, 80))

# ===========================================================
print("\n" + "=" * 70)
print("6. imcPropertySys STRING CONTEXT")
print("=" * 70)
prop_sys_bytes = b'imcPropertySys\x00'
pos = data.find(prop_sys_bytes)
if pos >= 0:
    str_va = offset_to_va(pos)
    print(f"  \"imcPropertySys\" at VA=0x{str_va:08X}")
    refs = find_all_refs(str_va)
    print(f"  {len(refs)} xrefs:")
    for ref_va, prev in refs[:5]:
        if prev == 0x68:
            print(f"\n  PUSH at 0x{ref_va-1:08X}:")
            print(disasm_at(ref_va-1, 20))

# ===========================================================
print("\n" + "=" * 70)
print("7. COMPARE GetPropertyNumber callback: geGeer vs ge.exe")
print("=" * 70)
# In geGeer the tolua registration pushes callback 0x8cf7ec
# Let's also check what ge.exe registers for GetPropertyNumber
import pefile as pefile2
GE = r"D:\AutoDownload-Chrome\AIgeHS Version.2025-10-03a By HeavenSaber\release\release\ge.exe"
pe_ge = pefile.PE(GE)
data_ge = open(GE, 'rb').read()
ib_ge = pe_ge.OPTIONAL_HEADER.ImageBase

# Find "GetPropertyNumber" in ge.exe
gpn_bytes = b'GetPropertyNumber\x00'
ge_pos = data_ge.find(gpn_bytes)
if ge_pos >= 0:
    # Get VA
    for s in pe_ge.sections:
        if s.PointerToRawData <= ge_pos < s.PointerToRawData + s.SizeOfRawData:
            ge_gpn_va = ib_ge + s.VirtualAddress + (ge_pos - s.PointerToRawData)
            break
    print(f"  ge.exe: \"GetPropertyNumber\" at VA=0x{ge_gpn_va:08X}")

    # Find xrefs
    target = struct.pack('<I', ge_gpn_va)
    for section in pe_ge.sections:
        name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if name != '.text': continue
        sec = data_ge[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
        pos = 0
        while True:
            pos = sec.find(target, pos)
            if pos < 0: break
            ref_va = ib_ge + section.VirtualAddress + pos
            prev = sec[pos-1] if pos > 0 else 0
            if prev == 0x68:
                # Found PUSH of the string - look at what callback is pushed before
                xref_off = section.PointerToRawData + pos
                # Disassemble context
                chunk = data_ge[xref_off - 10:xref_off + 30]
                md = Cs(CS_ARCH_X86, CS_MODE_32)
                print(f"\n  ge.exe XREF at 0x{ref_va-1:08X}:")
                for insn in md.disasm(chunk, ref_va - 10):
                    print(f"    0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")
                    if insn.address > ref_va + 20:
                        break

                # The pattern is: push callback; push string; push lua_state; call register
                # Look backward to find the callback push
                chunk2 = data_ge[xref_off - 30:xref_off]
                for insn2 in md.disasm(chunk2, ref_va - 30):
                    if insn2.mnemonic == 'push' and insn2.address < ref_va - 1:
                        print(f"    [preceding push] 0x{insn2.address:08X}: {insn2.mnemonic:8s} {insn2.op_str}")
            pos += 1

print("\n\nDone phase 2.")
