"""
try_classnames.py -- Try GET_PROP with candidate class names from thunk scan

From the S-Z thunk scan we found these potential class/objName values:
  Skill, Stance, WorldProperty, WorldPropertyClass, WorldPropertyString, etc.

Also try: empty string, NULL, common IES table names.
Test with SplRange as propName and various idSpaces.
"""

import sys
import struct
import time
sys.path.insert(0, ".")

from range_control import PhantomCmd

# Class name candidates to try as objName
CLASS_NAMES = [
    # From thunk scan (likely IES table names)
    "Skill",
    "Stance",
    "WorldProperty",
    "WorldPropertyClass",
    "WorldPropertyString",
    "Weapon",
    "Type",
    # Common GE IES table names (from game data knowledge)
    "Skill_BareKnuckle",
    "Skill_Hack",
    "Skill_Slash",
    "Character",
    "Monster",
    "Item",
    "Map",
    "PC",
    "Char",
    # Empty / special
    "",
]

# Property names to test
PROP_NAMES = ["SplRange", "KeepRange", "Level"]

# ID spaces to test
ID_SPACES = [0, 1, 2, 3, 4, 5, 10]

# Sentinel values that mean "not found"
DBL_MIN = 2.2250738585072014e-308


def is_sentinel(val):
    """Check if value is a known sentinel (not found)."""
    if val is None:
        return True
    if abs(val) < 1e-300 and val != 0.0:
        return True  # DBL_MIN or similar
    if val == -9999.0:
        return True
    return False


def main():
    try:
        cmd = PhantomCmd()
    except RuntimeError as e:
        print(f"[!] {e}")
        return 1

    if not cmd.ping():
        print("[!] DLL not responding")
        cmd.close()
        return 1

    print("[+] Connected\n")

    # First, quick test with SplRange across all class names and idspace=0
    print("=" * 70)
    print("  Phase 1: SplRange with various objNames (idSpace=0)")
    print("=" * 70)

    hits = []

    for cls in CLASS_NAMES:
        val = cmd.get_property("SplRange", 0, cls)
        marker = ""
        if val is not None and not is_sentinel(val):
            marker = " *** HIT! ***"
            hits.append(("SplRange", 0, cls, val))
        elif val is None:
            marker = " (error)"
        elif is_sentinel(val):
            marker = " (sentinel)"

        display_cls = f'"{cls}"' if cls else '""'
        display_val = f"{val}" if val is not None else "None"
        print(f"  GET({display_cls}, 0, SplRange) = {display_val}{marker}")

    print()

    # Phase 2: Try different idSpaces with promising class names
    print("=" * 70)
    print("  Phase 2: Promising names x idSpaces x properties")
    print("=" * 70)

    # Always test these
    test_names = ["Skill", "Stance", "WorldProperty", "WorldPropertyClass",
                  "Weapon", "", "PC", "Character"]

    for cls in test_names:
        for ids in ID_SPACES:
            for prop in PROP_NAMES:
                val = cmd.get_property(prop, ids, cls)
                if val is not None and not is_sentinel(val):
                    display_cls = f'"{cls}"' if cls else '""'
                    print(f"  *** HIT: GET({display_cls}, {ids}, {prop}) = {val}")
                    hits.append((prop, ids, cls, val))

    print()

    if hits:
        print("=" * 70)
        print(f"  FOUND {len(hits)} valid results!")
        print("=" * 70)
        for prop, ids, cls, val in hits:
            display_cls = f'"{cls}"' if cls else '""'
            print(f"  GetPropertyNumber({display_cls}, {ids}, {prop}) = {val}")
    else:
        print("[!] No valid results found with any combination")
        print("    All returned sentinel values")
        print()
        print("    Next step: try Approach C (hook to log game's own calls)")
        print("    Or scan for actual IES ClassName strings in game data")

    cmd.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
