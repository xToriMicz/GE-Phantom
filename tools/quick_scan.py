"""Compare character struct WITH vs WITHOUT weapon.

Run twice:
  1) With weapon equipped   -> saves data/struct_weapon_on.bin
  2) Without weapon         -> saves data/struct_weapon_off.bin
Then auto-compares and shows diff.
"""
import pymem
import struct
import sys
from pathlib import Path

CHAR_STRUCT_ADDR = 0xD26B17  # ATK address from diff scan
DUMP_START = CHAR_STRUCT_ADDR - 256
DUMP_SIZE = 1024  # -256 to +768 from ATK

ON_PATH = Path("data/struct_weapon_on.bin")
OFF_PATH = Path("data/struct_weapon_off.bin")
DIFF_PATH = Path("data/struct_diff.txt")

pm = pymem.Pymem('ge.exe')
print(f"[+] Attached (PID {pm.process_id})")

# Verify struct is still valid
atk = pm.read_short(CHAR_STRUCT_ADDR)
print(f"[*] Current ATK at 0x{CHAR_STRUCT_ADDR:X} = {atk}")

if "--off" in sys.argv:
    label = "WEAPON OFF"
    out_path = OFF_PATH
elif "--on" in sys.argv:
    label = "WEAPON ON"
    out_path = ON_PATH
elif ON_PATH.exists() and OFF_PATH.exists():
    label = "COMPARE"
else:
    print("\nUsage:")
    print("  1) Equip weapon,   run: python tools/quick_scan.py --on")
    print("  2) Unequip weapon, run: python tools/quick_scan.py --off")
    print("  3) Compare:        run: python tools/quick_scan.py")
    sys.exit(0)

if label != "COMPARE":
    data = pm.read_bytes(DUMP_START, DUMP_SIZE)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    print(f"[+] Saved {label} dump to {out_path} ({len(data)} bytes)")

    if label == "WEAPON ON":
        print(f"\n  Now UNEQUIP weapon and run:")
        print(f"    python tools/quick_scan.py --off")
    elif label == "WEAPON OFF":
        print(f"\n  Now run comparison:")
        print(f"    python tools/quick_scan.py")
    sys.exit(0)

# Compare mode
print(f"\n[*] Comparing weapon ON vs OFF...\n")
data_on = ON_PATH.read_bytes()
data_off = OFF_PATH.read_bytes()

lines = []
lines.append(f"Character Struct Diff — base=0x{CHAR_STRUCT_ADDR:X}")
lines.append(f"Dump range: -{256} to +{DUMP_SIZE - 256}")
lines.append(f"{'='*110}")
lines.append("")
lines.append(f"{'Offset':>6s}  {'Address':>10s}  "
             f"{'ON (i16)':>8s} {'OFF (i16)':>9s}  "
             f"{'ON (i32)':>10s} {'OFF (i32)':>10s}  "
             f"{'ON (f32)':>10s} {'OFF (f32)':>10s}  "
             f"Note")
lines.append("-" * 110)

diffs = 0
for off in range(0, min(len(data_on), len(data_off)) - 3, 2):
    rel = off - 256  # relative to ATK address
    abs_addr = DUMP_START + off

    # Read i16 from both
    i16_on = struct.unpack_from('<h', data_on, off)[0]
    i16_off = struct.unpack_from('<h', data_off, off)[0]

    if i16_on == i16_off:
        continue  # skip identical

    diffs += 1

    # Also read i32 and f32 at same offset
    if off + 4 <= len(data_on):
        i32_on = struct.unpack_from('<i', data_on, off)[0]
        i32_off = struct.unpack_from('<i', data_off, off)[0]
        f32_on = struct.unpack_from('<f', data_on, off)[0]
        f32_off = struct.unpack_from('<f', data_off, off)[0]
        f32_on_s = f"{f32_on:.2f}" if (abs(f32_on) > 0.01 and abs(f32_on) < 1e6 and f32_on == f32_on) else "---"
        f32_off_s = f"{f32_off:.2f}" if (abs(f32_off) > 0.01 and abs(f32_off) < 1e6 and f32_off == f32_off) else "---"
    else:
        i32_on = i32_off = 0
        f32_on_s = f32_off_s = "---"

    # Annotate
    note = ""
    if rel == 0: note = "<-- ATK"
    elif rel == -2: note = "<-- ATK_Rate"
    elif rel == 2: note = "<-- Critical"
    elif rel == 4: note = "<-- DEF_Rate"
    elif rel == 6: note = "<-- DEF"
    elif rel == 8: note = "<-- Accuracy"
    elif rel == 12: note = "<-- ATK_Spd"
    elif abs(i16_on - i16_off) > 0 and 100 < abs(i16_on) < 2000:
        note = "** INTERESTING **"

    # Flag possible range values
    if (50 < i32_on < 5000 and i32_off == 0) or (50 < i32_on < 5000 and abs(i32_on - i32_off) > 10):
        note += " RANGE_CANDIDATE?"

    lines.append(
        f"{rel:+5d}  0x{abs_addr:X}  "
        f"{i16_on:>8d} {i16_off:>9d}  "
        f"{i32_on:>10d} {i32_off:>10d}  "
        f"{f32_on_s:>10s} {f32_off_s:>10s}  "
        f"{note}"
    )

lines.append("")
lines.append(f"Total differences: {diffs} (out of {DUMP_SIZE // 2} i16 slots)")

text = "\n".join(lines)
DIFF_PATH.write_text(text, encoding="utf-8")
print(f"[+] Saved diff to {DIFF_PATH} ({diffs} differences)")
print(f"    notepad data\\struct_diff.txt")

# Also print to console
for line in lines:
    print(f"  {line}")
