"""Compare .rdata strings between ge.exe and geGeer.exe to find ALL new strings"""
import pefile
import re

GE_PATH = r"D:\AutoDownload-Chrome\AIgeHS Version.2025-10-03a By HeavenSaber\release\release\ge.exe"
GEGEER_PATH = r"D:\AutoDownload-Chrome\AIgeHS Version.2025-10-03a By HeavenSaber\release\release\geGeer.exe"

def extract_strings(filepath, min_len=4):
    """Extract printable strings from all data sections"""
    pe = pefile.PE(filepath)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    strings = {}

    for section in pe.sections:
        name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        # Include .rdata, .data, and other non-code sections
        if name in ['.text']:
            continue

        sec_data = section.get_data()
        sec_va = image_base + section.VirtualAddress

        # Find printable ASCII strings
        for m in re.finditer(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}', sec_data):
            s = m.group().decode('ascii')
            va = sec_va + m.start()
            strings[s] = va

    return strings

print("Extracting strings from ge.exe...")
ge_strings = extract_strings(GE_PATH)
print(f"  Found {len(ge_strings)} strings")

print("Extracting strings from geGeer.exe...")
gegeer_strings = extract_strings(GEGEER_PATH)
print(f"  Found {len(gegeer_strings)} strings")

# Find strings ONLY in geGeer (not in ge.exe)
only_gegeer = {s: va for s, va in gegeer_strings.items() if s not in ge_strings}

# Categorize
game_keywords = ['Range', 'Property', 'hook', 'Hook', 'tolua', 'Geer', 'geer',
                 'hack', 'cheat', 'inject', 'patch', 'modify', 'speed', 'teleport',
                 'god', 'infinite', 'unlock', 'bypass', 'skill', 'Skill', 'damage',
                 'attack', 'Atk', 'Def', 'HP', 'MP', 'Ai', 'View', 'Spl',
                 'phantom', 'dll', 'DLL', 'load', 'detour', 'trampoline',
                 'vtable', 'virtual', 'offset', 'pointer', 'addr', 'memory',
                 'engine', 'Engine', 'config', 'option', 'enable', 'disable',
                 'packet', 'send', 'recv', 'socket', 'network']

print("\n" + "=" * 70)
print(f"STRINGS ONLY IN geGeer.exe ({len(only_gegeer)} total)")
print("=" * 70)

# High-value strings first
print("\n--- HIGH-VALUE (game/hack related) ---")
high_value = {}
for s, va in sorted(only_gegeer.items(), key=lambda x: x[1]):
    for kw in game_keywords:
        if kw.lower() in s.lower():
            high_value[s] = va
            break

for s, va in sorted(high_value.items(), key=lambda x: x[1]):
    print(f"  0x{va:08X}: \"{s}\"")

# All other new strings grouped by section/address range
print(f"\n--- ALL NEW STRINGS (sorted by VA) ---")
for s, va in sorted(only_gegeer.items(), key=lambda x: x[1]):
    if s not in high_value:
        # Skip common runtime/compiler strings
        if any(skip in s for skip in ['Microsoft', 'Visual C++', 'Runtime',
                                       'Copyright', '.dll', 'MSVC', 'CRT']):
            continue
        print(f"  0x{va:08X}: \"{s}\"")

# Also find strings in ge.exe that are MISSING from geGeer (removed strings)
only_ge = {s: va for s, va in ge_strings.items() if s not in gegeer_strings}
print(f"\n--- STRINGS REMOVED FROM ge.exe (in ge, not in geGeer): {len(only_ge)} ---")
removed_interesting = {}
for s, va in sorted(only_ge.items(), key=lambda x: x[1]):
    for kw in game_keywords:
        if kw.lower() in s.lower():
            removed_interesting[s] = va
            break
for s, va in sorted(removed_interesting.items(), key=lambda x: x[1]):
    print(f"  0x{va:08X}: \"{s}\"")

# Summary
print(f"\n\n=== SUMMARY ===")
print(f"ge.exe strings:     {len(ge_strings)}")
print(f"geGeer.exe strings: {len(gegeer_strings)}")
print(f"Only in geGeer:     {len(only_gegeer)}")
print(f"  High-value:       {len(high_value)}")
print(f"Only in ge.exe:     {len(only_ge)}")
print(f"  Interesting:      {len(removed_interesting)}")
