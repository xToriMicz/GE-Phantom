"""
try_skills.py -- Test skill-specific class names with various idSpaces

We confirmed GetPropertyNumber works with "WorldProperty" idSpace=1+.
Now try actual skill IES class names to find SplRange values > 0.

GE skill IES tables: Skill_BareKnuckle, Skill_Hack, Skill_Slash, etc.
The objName might need to be the IES class/table name.
"""

import sys
sys.path.insert(0, ".")

from range_control import PhantomCmd

DBL_MIN = 2.2250738585072014e-308

def is_valid(val):
    if val is None:
        return False
    if abs(val) < 1e-300 and val != 0.0:
        return False  # DBL_MIN
    if val == -9999.0:
        return False
    return True

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

    # Skill IES class names from GE
    SKILL_NAMES = [
        # With Skill_ prefix
        "Skill_BareKnuckle", "Skill_Hack", "Skill_Slash", "Skill_Shoot",
        "Skill_Cast", "Skill_MartialArts", "Skill_Rapier", "Skill_Dagger",
        "Skill_Sabre", "Skill_Polearm", "Skill_Cannon", "Skill_Rifle",
        "Skill_Crossbow", "Skill_Shield", "Skill_Staff", "Skill_Rod",
        "Skill_Fire", "Skill_Ice", "Skill_Lightning", "Skill_Healing",
        # Without prefix
        "BareKnuckle", "Hack", "Slash", "Shoot", "Cast",
        "MartialArts", "Rapier", "Dagger", "Sabre",
        # Character classes
        "Fighter", "Scout", "Wizard", "Musketeer", "Elementalist",
        # Misc
        "SkillProperty", "SkillList",
    ]

    # More idSpaces
    ID_SPACES = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100, 1000]

    # Properties to check
    PROPS = ["SplRange", "KeepRange", "Level"]

    print("Phase 1: Quick scan - SplRange with all skill names, idSpace=1")
    print("-" * 70)

    for name in SKILL_NAMES:
        val = cmd.get_property("SplRange", 1, name)
        marker = ""
        if is_valid(val):
            marker = f" *** VALID ({val})"
        elif val is not None and abs(val) < 1e-300 and val != 0.0:
            marker = " (sentinel)"
        else:
            marker = ""
        if is_valid(val):
            print(f"  GET(\"{name}\", 1, SplRange) = {val}{marker}")

    print("\nPhase 2: Wider idSpace scan for working names")
    print("-" * 70)

    # Test working names with more idSpaces
    WORKING = ["WorldProperty", "WorldPropertyClass", "PC"]
    WORKING.extend(SKILL_NAMES)

    found_nonzero = []

    for name in WORKING:
        for ids in ID_SPACES:
            val = cmd.get_property("SplRange", ids, name)
            if is_valid(val) and val != 0.0:
                print(f"  *** NONZERO: GET(\"{name}\", {ids}, SplRange) = {val}")
                found_nonzero.append((name, ids, val))

    if not found_nonzero:
        print("  No non-zero SplRange values found\n")

    # Phase 3: Try KeepRange and Level on working combos
    print("\nPhase 3: Other props on working names")
    print("-" * 70)

    for name in ["WorldProperty", "WorldPropertyClass", "PC"]:
        for ids in [1, 2, 3, 4, 5]:
            for prop in ["Level", "STR", "DEX", "INT", "MHP", "MSP",
                         "PATK", "MATK", "DEF", "MDEF", "HR", "DR",
                         "ASPD", "MSPD", "CRT", "ClassName",
                         "HP", "SP", "MovingShot"]:
                val = cmd.get_property(prop, ids, name)
                if is_valid(val) and val != 0.0:
                    print(f"  {name}[{ids}].{prop} = {val}")

    # Phase 4: Brute force idSpace on WorldProperty for SplRange
    print("\nPhase 4: WorldProperty SplRange for idSpaces 0-50")
    print("-" * 70)

    for ids in range(51):
        val = cmd.get_property("SplRange", ids, "WorldProperty")
        if is_valid(val) and val != 0.0:
            print(f"  WorldProperty[{ids}].SplRange = {val}")

    print("\n[*] Done")
    cmd.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
