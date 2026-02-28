import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

"""Match GetPropertyNumber core implementation between geGeer.exe and ge.exe
Strategy:
1. ge.exe callback at 0x008ABD73 — disassemble to find the core call (equiv of 0x008C333C)
2. Compare function signatures/patterns
3. Also find the string resolver equivalent (0x6269b0 in geGeer)
"""
import pefile
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

GE = r"D:\AutoDownload-Chrome\AIgeHS Version.2025-10-03a By HeavenSaber\release\release\ge.exe"
GEGEER = r"D:\AutoDownload-Chrome\AIgeHS Version.2025-10-03a By HeavenSaber\release\release\geGeer.exe"

def load_binary(path):
    pe = pefile.PE(path)
    raw = open(path, 'rb').read()
    ib = pe.OPTIONAL_HEADER.ImageBase
    return pe, raw, ib

pe_ge, data_ge, ib_ge = load_binary(GE)
pe_gg, data_gg, ib_gg = load_binary(GEGEER)

def va_to_offset(pe, raw, ib, va):
    rva = va - ib
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

def read_string(raw, pe, ib, va, max_len=100):
    off = va_to_offset(pe, raw, ib, va)
    if off is None: return "<unresolvable>"
    s = []
    for b in raw[off:off+max_len]:
        if b == 0: break
        if 32 <= b < 127: s.append(chr(b))
        else: break
    return ''.join(s)

def disasm_func(raw, pe, ib, va, max_insns=80):
    off = va_to_offset(pe, raw, ib, va)
    if off is None: return []
    chunk = raw[off:off+500]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    insns = []
    for insn in md.disasm(chunk, va):
        insns.append(insn)
        if len(insns) >= max_insns:
            break
    return insns

# ===========================================================
print("=" * 70)
print("1. ge.exe: GetPropertyNumber CALLBACK at 0x008ABD73")
print("=" * 70)

ge_callback = 0x008ABD73
insns = disasm_func(data_ge, pe_ge, ib_ge, ge_callback)
core_call_ge = None
for insn in insns:
    s = ""
    # Annotate known patterns
    if insn.mnemonic == 'call':
        # Check if it's the core implementation call (3 args: obj, prop_id, ctx)
        s = " <-- potential core call"
    if insn.mnemonic == 'push' and insn.op_str.startswith('0x'):
        try:
            val = int(insn.op_str, 16)
            if 0x00B00000 <= val <= 0x00D00000:
                ss = read_string(data_ge, pe_ge, ib_ge, val)
                if len(ss) >= 3: s = f'  // "{ss}"'
        except: pass
    print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}{s}")
    if insn.mnemonic == 'ret' and insn.address > ge_callback + 10:
        break

# ===========================================================
print("\n" + "=" * 70)
print("2. SIDE-BY-SIDE: Find the core call in both callbacks")
print("=" * 70)

# geGeer callback (0x008CF7EC) calls 0x008C333C as core impl
# The pattern is: after reading lua args, the last 'call' before 'fstp' is the core
# Let's find the equivalent in ge.exe

print("\ngeGeer callback flow (0x008CF7EC):")
gg_insns = disasm_func(data_gg, pe_gg, ib_gg, 0x008CF7EC)
for insn in gg_insns:
    if insn.mnemonic in ('call', 'push', 'fstp', 'cvttsd2si', 'ret'):
        note = ""
        if insn.mnemonic == 'call' and insn.op_str == '0x8c333c':
            note = "  ** CORE GetPropertyNumber impl"
        elif insn.mnemonic == 'call' and insn.op_str == '0x5f96b0':
            note = "  (tolua_tousertype)"
        elif insn.mnemonic == 'call' and insn.op_str == '0x5f9660':
            note = "  (tolua_tonumber)"
        elif insn.mnemonic == 'call' and insn.op_str == '0x5f91c0':
            note = "  (tolua_pushnumber)"
        elif insn.mnemonic == 'call' and insn.op_str == '0x5f7d10':
            note = "  (tolua_isusertype)"
        elif insn.mnemonic == 'call' and insn.op_str == '0x5f7c00':
            note = "  (tolua_isnumber)"
        elif insn.mnemonic == 'call' and insn.op_str == '0x5f7bc0':
            note = "  (tolua_isnoobj)"
        elif insn.mnemonic == 'call' and insn.op_str == '0x5f7950':
            note = "  (tolua_error)"
        print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}{note}")
    if insn.mnemonic == 'ret' and insn.address > 0x008CF800:
        break

print("\nge.exe callback flow (0x008ABD73):")
ge_insns = disasm_func(data_ge, pe_ge, ib_ge, ge_callback)
# Map tolua functions by position in call sequence
call_idx = 0
for insn in ge_insns:
    if insn.mnemonic in ('call', 'push', 'fstp', 'cvttsd2si', 'ret'):
        note = ""
        if insn.mnemonic == 'call':
            call_idx += 1
            # Match by call position:
            # calls 1-4: validators (isusertype, isnumber, isusertype, isnoobj)
            # call 5: tolua_tousertype(L,1,0)
            # call 6: tolua_tonumber(L,2,0)
            # call 7: tolua_tousertype(L,3,0)
            # call 8: ** CORE GetPropertyNumber
            # call 9: tolua_pushnumber
            if call_idx <= 4:
                note = f"  (validator #{call_idx})"
            elif call_idx == 5:
                note = "  (tolua_tousertype arg1)"
            elif call_idx == 6:
                note = "  (tolua_tonumber arg2=prop_id)"
            elif call_idx == 7:
                note = "  (tolua_tousertype arg3=ctx)"
            elif call_idx == 8:
                note = "  ** CORE GetPropertyNumber impl"
                core_call_ge = int(insn.op_str, 16) if insn.op_str.startswith('0x') else insn.op_str
            elif call_idx == 9:
                note = "  (tolua_pushnumber result)"
            elif call_idx == 10:
                note = "  (tolua_error)"
        print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}{note}")
    if insn.mnemonic == 'ret' and insn.address > ge_callback + 10:
        break

# ===========================================================
print("\n" + "=" * 70)
print(f"3. CORE GetPropertyNumber: geGeer=0x008C333C vs ge.exe={core_call_ge}")
print("=" * 70)

if core_call_ge and isinstance(core_call_ge, int):
    print(f"\n--- ge.exe core at 0x{core_call_ge:08X} ---")
    insns = disasm_func(data_ge, pe_ge, ib_ge, core_call_ge, 60)
    for insn in insns:
        s = ""
        if insn.mnemonic == 'push' and insn.op_str.startswith('0x'):
            try:
                val = int(insn.op_str, 16)
                if 0x00B00000 <= val <= 0x00D00000:
                    ss = read_string(data_ge, pe_ge, ib_ge, val)
                    if len(ss) >= 3: s = f'  // "{ss}"'
            except: pass
        if insn.mnemonic == 'call' and 'dword ptr' in insn.op_str:
            s = "  <-- vtable call!"
        print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}{s}")
        if insn.mnemonic == 'ret' and insn.address > core_call_ge + 10:
            break

    print(f"\n--- geGeer core at 0x008C333C ---")
    insns = disasm_func(data_gg, pe_gg, ib_gg, 0x008C333C, 60)
    for insn in insns:
        s = ""
        if insn.mnemonic == 'push' and insn.op_str.startswith('0x'):
            try:
                val = int(insn.op_str, 16)
                if 0x00B00000 <= val <= 0x00D00000:
                    ss = read_string(data_gg, pe_gg, ib_gg, val)
                    if len(ss) >= 3: s = f'  // "{ss}"'
            except: pass
        if insn.mnemonic == 'call' and 'dword ptr' in insn.op_str:
            s = "  <-- vtable call!"
        print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}{s}")
        if insn.mnemonic == 'ret' and insn.address > 0x008C3340:
            break

# ===========================================================
print("\n" + "=" * 70)
print("4. STRING RESOLVER: Find ge.exe equivalent of 0x6269b0")
print("=" * 70)

# In geGeer, KeepRange xref#1 at 0x0054ADD3 calls 0x6269b0 as resolver
# In ge.exe, KeepRange xref#1 should have similar code
# Let's find KeepRange string in ge.exe and its xrefs

ge_kr_bytes = b'KeepRange\x00'
kr_pos = data_ge.find(ge_kr_bytes)
if kr_pos >= 0:
    for s in pe_ge.sections:
        if s.PointerToRawData <= kr_pos < s.PointerToRawData + s.SizeOfRawData:
            kr_va_ge = ib_ge + s.VirtualAddress + (kr_pos - s.PointerToRawData)
            break
    print(f"ge.exe KeepRange string at VA=0x{kr_va_ge:08X}")

    # Find xrefs
    target = struct.pack('<I', kr_va_ge)
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
            if prev == 0x68:  # PUSH
                print(f"\n  PUSH at 0x{ref_va-1:08X}:")
                xrefs = disasm_func(data_ge, pe_ge, ib_ge, ref_va - 20, 25)
                for insn in xrefs:
                    mark = " <<<" if insn.address == ref_va - 1 else ""
                    note = ""
                    if insn.mnemonic == 'call' and insn.address > ref_va - 1:
                        # The call right after PUSH KeepRange is the resolver
                        note = "  ** STRING RESOLVER **"
                    if insn.mnemonic == 'call' and 'dword ptr' in insn.op_str:
                        note = "  <-- vtable call"
                    print(f"    0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}{mark}{note}")
            pos += 1

# ===========================================================
print("\n" + "=" * 70)
print("5. FUNCTION SIGNATURE MATCH (byte pattern)")
print("=" * 70)

# Extract the first N bytes of geGeer's core function for pattern matching
if core_call_ge and isinstance(core_call_ge, int):
    gg_off = va_to_offset(pe_gg, data_gg, ib_gg, 0x008C333C)
    ge_off = va_to_offset(pe_ge, data_ge, ib_ge, core_call_ge)

    if gg_off and ge_off:
        gg_bytes = data_gg[gg_off:gg_off+32]
        ge_bytes = data_ge[ge_off:ge_off+32]

        print(f"geGeer 0x008C333C first 32 bytes: {gg_bytes.hex()}")
        print(f"ge.exe 0x{core_call_ge:08X} first 32 bytes: {ge_bytes.hex()}")

        # Compare byte-by-byte (ignoring call target differences)
        match = 0
        for i in range(min(32, len(gg_bytes), len(ge_bytes))):
            if gg_bytes[i] == ge_bytes[i]:
                match += 1
        print(f"Byte match: {match}/32 ({match*100//32}%)")

print("\n\nDone.")
