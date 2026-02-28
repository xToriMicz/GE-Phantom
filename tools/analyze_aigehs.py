"""Analyze AIgeHS executable for range-related hooks and memory addresses."""
import struct

path = "tools/aigehs_unpacked.exe"
print("[*] Scanning AIgeHS strings...")

with open(path, "rb") as f:
    data = f.read()

print(f"    Size: {len(data):,} bytes")

# Extract ASCII strings (min 6 chars)
strings = []
current = bytearray()
start = 0
for i in range(len(data)):
    b = data[i]
    if 32 <= b < 127:
        if not current:
            start = i
        current.append(b)
    else:
        if len(current) >= 6:
            strings.append((start, current.decode("ascii")))
        current = bytearray()

print(f"    Strings: {len(strings):,}")

# Search patterns
keywords = [
    "KeepRange", "SplRange", "AiRange", "ViewRange", "MaxLinkRange",
    "attack_range", "AttackRange", "Range",
    "PropertyNumber", "GetProp", "SetProp", "Property",
    "vtable", "VTable", "vfunc",
    "hook", "Hook", "detour", "Detour", "patch", "Patch",
    "WriteProcessMemory", "ReadProcessMemory", "VirtualProtect",
    "CreateRemoteThread", "LoadLibrary", "inject", "Inject",
    "ge.exe",
]

seen = set()
results = []
for offset, s in strings:
    sl = s.lower()
    for kw in keywords:
        if kw.lower() in sl:
            key = s[:80]
            if key not in seen:
                seen.add(key)
                results.append((offset, s[:200], kw))
            break

# Group by keyword category
categories = {
    "RANGE": ["KeepRange", "SplRange", "AiRange", "ViewRange", "MaxLinkRange", "attack_range", "AttackRange", "Range"],
    "PROPERTY": ["PropertyNumber", "GetProp", "SetProp", "Property"],
    "HOOK/PATCH": ["vtable", "VTable", "vfunc", "hook", "Hook", "detour", "Detour", "patch", "Patch"],
    "WIN32 API": ["WriteProcessMemory", "ReadProcessMemory", "VirtualProtect", "CreateRemoteThread", "LoadLibrary", "inject", "Inject"],
    "TARGET": ["ge.exe"],
}

for cat, kws in categories.items():
    cat_results = [(o, s, k) for o, s, k in results if k in kws]
    if cat_results:
        print(f"\n=== {cat} ({len(cat_results)} hits) ===")
        for offset, s, kw in cat_results[:30]:
            print(f"  0x{offset:08X}: {s}")

# Also search for hex addresses that match known GE addresses
print("\n=== KNOWN GE ADDRESSES in binary ===")
known_addrs = {
    0x0089D5FC: "GetPropertyNumber",
    0x005C62A2: "SetPropertyNumber",
    0x005E79F2: "resolve_string",
    0x004FEA4B: "KeepRange_xref1",
    0x0050A942: "KeepRange_xref2",
    0x00B82770: "str_KeepRange",
    0x00B9BD64: "str_SplRange",
}

for addr, label in known_addrs.items():
    needle = struct.pack("<I", addr)
    pos = 0
    count = 0
    while True:
        pos = data.find(needle, pos)
        if pos == -1:
            break
        count += 1
        if count <= 3:
            print(f"  0x{addr:08X} ({label}): found at file offset 0x{pos:08X}")
        pos += 1
    if count > 3:
        print(f"  0x{addr:08X} ({label}): {count} total occurrences")
    elif count == 0:
        print(f"  0x{addr:08X} ({label}): NOT FOUND")

