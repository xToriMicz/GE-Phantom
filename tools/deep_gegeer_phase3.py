"""Phase 3: Map the full property-reading function and find ScalePropertyNumberAll callback"""
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

def read_string_at_va(va, max_len=100):
    off = va_to_offset(va)
    if off is None: return "<unresolvable>"
    s = []
    for b in data[off:off+max_len]:
        if b == 0: break
        if 32 <= b < 127: s.append(chr(b))
        else: break
    return ''.join(s)

def disasm_range(start_va, end_va):
    off = va_to_offset(start_va)
    if off is None: return
    size = end_va - start_va
    chunk = data[off:off+size]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for insn in md.disasm(chunk, start_va):
        yield insn

# ===========================================================
print("=" * 70)
print("1. FULL ViewRange/AiRange FUNCTION (find start, map all properties)")
print("=" * 70)

# ViewRange xref is at 0x006B17C2. Walk back to find function prologue
# Look for 'push ebp; mov ebp, esp' or 'sub esp' pattern
off_start = va_to_offset(0x006B17C2)
# Search backward for push ebp (0x55) followed by mov ebp, esp (0x8B 0xEC)
func_va = None
for i in range(off_start, off_start - 500, -1):
    if i >= 2 and data[i] == 0x55 and data[i+1] == 0x8B and data[i+2] == 0xEC:
        func_va = 0x006B17C2 - (off_start - i)
        print(f"Function starts at VA=0x{func_va:08X}")
        break
if func_va is None:
    func_va = 0x006B1680  # fallback: start ~256 bytes before ViewRange
    print(f"Prologue not found, using fallback VA=0x{func_va:08X}")

# Disassemble the full function and find all PUSH imm32 that reference strings
# and all vtable calls
print("\nProperty reads in this function:")
resolve_func = 0x6269b0  # string resolver

for insn in disasm_range(func_va, func_va + 800):
    # Look for PUSH imm32 of string addresses (0x00B9xxxx - 0x00C0xxxx range)
    if insn.mnemonic == 'push' and insn.op_str.startswith('0x'):
        try:
            val = int(insn.op_str, 16)
            if 0x00B90000 <= val <= 0x00C10000:
                s = read_string_at_va(val)
                if len(s) >= 3:
                    print(f"  0x{insn.address:08X}: push 0x{val:08X}  // \"{s}\"")
        except:
            pass
    # Look for vtable calls
    if insn.mnemonic == 'call' and 'dword ptr' in insn.op_str:
        print(f"  0x{insn.address:08X}: call {insn.op_str}")

    # Look for struct offset stores (mov [edi+X], eax/reg)
    if insn.mnemonic == 'mov' and insn.op_str.startswith('dword ptr [edi +'):
        print(f"  0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}")

    if insn.mnemonic == 'ret':
        print(f"  0x{insn.address:08X}: ret  (end of function)")
        break

# ===========================================================
print("\n" + "=" * 70)
print("2. ScalePropertyNumberAll CALLBACK (look before push at 0x006F3F64)")
print("=" * 70)

# The tolua registration pattern is:
# push callback_addr
# push string_addr
# push lua_state
# call tolua_function (0x5f8ab0)
# So we need to find what callback was pushed BEFORE push 0xbca01c

# Disassemble from 0x006F3F40 to see context
print("Context before ScalePropertyNumberAll registration:")
md = Cs(CS_ARCH_X86, CS_MODE_32)
off = va_to_offset(0x006F3F30)
chunk = data[off:off+120]
for insn in md.disasm(chunk, 0x006F3F30):
    s = ""
    if insn.mnemonic == 'push' and insn.op_str.startswith('0x'):
        try:
            val = int(insn.op_str, 16)
            if 0x00B90000 <= val <= 0x00C10000:
                ss = read_string_at_va(val)
                if len(ss) >= 3:
                    s = f'  // "{ss}"'
            elif 0x00400000 <= val <= 0x00A00000:
                s = f'  // callback?'
        except:
            pass
    print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}{s}")
    if insn.address > 0x006F3FA6:
        break

# ===========================================================
print("\n" + "=" * 70)
print("3. DISASSEMBLE ScalePropertyNumberAll callback")
print("=" * 70)

# From the registration pattern, we need to find the push right before
# push 0xbca01c. Let's look for it
off2 = va_to_offset(0x006F3F50)
chunk2 = data[off2:off2+20]
for insn in md.disasm(chunk2, 0x006F3F50):
    if insn.mnemonic == 'push' and insn.op_str.startswith('0x'):
        val = int(insn.op_str, 16)
        if 0x00400000 <= val <= 0x00A00000:
            callback_va = val
            print(f"ScalePropertyNumberAll callback at 0x{callback_va:08X}:")
            off3 = va_to_offset(callback_va)
            chunk3 = data[off3:off3+400]
            for insn3 in md.disasm(chunk3, callback_va):
                s = ""
                if insn3.mnemonic == 'push' and insn3.op_str.startswith('0x'):
                    try:
                        v = int(insn3.op_str, 16)
                        if 0x00B90000 <= v <= 0x00C10000:
                            ss = read_string_at_va(v)
                            if len(ss) >= 3: s = f'  // "{ss}"'
                    except: pass
                print(f"  0x{insn3.address:08X}: {insn3.mnemonic:8s} {insn3.op_str}{s}")
                if insn3.mnemonic == 'ret' and insn3.address > callback_va + 10:
                    break
            break

# ===========================================================
print("\n" + "=" * 70)
print("4. GetPropertyNumber CALLBACK DEEP (what vtable call does it make?)")
print("=" * 70)

# Continue the callback disassembly from 0x008CF7EC
# The callback reads lua args, then calls the actual property getter
# We need to find the vtable dispatch call inside it
off4 = va_to_offset(0x008CF7EC)
chunk4 = data[off4:off4+400]
print("Full GetPropertyNumber callback (0x008CF7EC):")
for insn in md.disasm(chunk4, 0x008CF7EC):
    s = ""
    if insn.mnemonic == 'push' and insn.op_str.startswith('0x'):
        try:
            v = int(insn.op_str, 16)
            if 0x00B90000 <= v <= 0x00C10000:
                ss = read_string_at_va(v)
                if len(ss) >= 3: s = f'  // "{ss}"'
        except: pass
    print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}{s}")
    if insn.mnemonic == 'ret' and insn.address > 0x008CF800:
        break

# ===========================================================
print("\n" + "=" * 70)
print("5. VTABLE OFFSET MAP (check what's at each vtable slot)")
print("=" * 70)

# From the code we can see the object's vtable is accessed via [obj] → vtable
# We know:
# [0x10] = GET number (KeepRange)
# [0x14] = GET float (ViewRange, AiRange)
# [0x1c] = GET string (SaveWarp)
# [0x28] = SET number (KeepRange set)
# Let's catalog ALL vtable calls in the code we've analyzed

vtable_map = {
    0x10: "GetPropertyNumber (int) - used by KeepRange xref#1",
    0x14: "GetPropertyFloat (SSE float) - used by ViewRange, AiRange",
    0x1c: "GetPropertyString? - used with SaveWarp",
    0x28: "SetPropertyNumber (double) - used by KeepRange xref#2",
    0x2c: "Unknown - seen in imcPropertySys init",
    0x68: "Unknown - seen in imcPropertySys init",
}

print("Known vtable layout for property object:")
for offset in sorted(vtable_map.keys()):
    print(f"  [0x{offset:02X}] = {vtable_map[offset]}")

# ===========================================================
print("\n" + "=" * 70)
print("6. PACKET OPCODES SUMMARY (geGeer property packets)")
print("=" * 70)

# From the packet registration analysis:
packets = {
    0x4B: "PKS_BC_UPDATE_PROPERTY_NUMBER",
    0x4C: "PKS_BC_UPDATE_PROPERTY_STRING",
    0xBD6: "PKS_ZC_FIELDOBJECT_PROPERTY",
    0xE48: "PKS_ZC_UPDATE_PROPERTY_NUMBER",
    0xE49: "PKS_ZC_UPDATE_PROPERTY_STRING",
}

print("Packet opcodes for property updates:")
for opcode in sorted(packets.keys()):
    print(f"  0x{opcode:04X} ({opcode:5d}) = {packets[opcode]}")

# Now let's also find the actual packet HANDLER functions
# The registration call is 0x70f17e(opcode, flags, name) - but we need the handler
# The handler is likely registered elsewhere or determined by the opcode
# Let's look at what function 0x70f17e does
print("\nPacket register function (0x70f17e):")
off5 = va_to_offset(0x70f17e)
chunk5 = data[off5:off5+200]
for insn in md.disasm(chunk5, 0x70f17e):
    print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")
    if insn.mnemonic == 'ret' and insn.address > 0x70f180:
        break

print("\n\nDone phase 3.")
