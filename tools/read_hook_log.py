"""
read_hook_log.py -- Parse phantom_hook_v3.log for GetPropertyNumber hook entries

Shows what parameters the game uses when calling GetPropertyNumber.
Run after enabling the hook and playing the game.
"""

import sys
import re
from collections import Counter

LOG_PATH = "tools/phantom_hook/phantom_hook_v3.log"

def main():
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[!] Log not found: {LOG_PATH}")
        return 1

    # Parse HOOK_GET lines
    # Format: [TICK] HOOK_GET #N: obj="..." idSpace=N prop="..."
    # Format: [TICK] HOOK_GET #N: -> VALUE (obj="..." prop="...")
    pat_call = re.compile(
        r'HOOK_GET #(\d+): obj="(.*?)" idSpace=(\d+) prop="(.*?)"'
    )
    pat_result = re.compile(
        r'HOOK_GET #(\d+): -> ([\d.e+\-]+) \(obj="(.*?)" prop="(.*?)"\)'
    )

    calls = {}  # call_id -> {obj, idSpace, prop}
    results = {}  # call_id -> value

    for line in lines:
        m = pat_call.search(line)
        if m:
            cid = int(m.group(1))
            calls[cid] = {
                "obj": m.group(2),
                "idSpace": int(m.group(3)),
                "prop": m.group(4),
            }
            continue

        m = pat_result.search(line)
        if m:
            cid = int(m.group(1))
            results[cid] = float(m.group(2))

    total = len(calls)
    nonzero = sum(1 for cid in results if results[cid] != 0.0)

    print(f"Total GetPropertyNumber calls logged: {total}")
    print(f"Non-zero results: {nonzero}")
    print()

    if total == 0:
        print("[!] No calls logged yet. Play the game (use skills, attack, etc.)")
        return 0

    # Show unique (obj, idSpace, prop) combinations
    combos = Counter()
    combo_vals = {}
    for cid, c in calls.items():
        key = (c["obj"], c["idSpace"], c["prop"])
        combos[key] += 1
        if cid in results and results[cid] != 0.0:
            combo_vals[key] = results[cid]

    # Print all unique combinations
    print(f"{'obj':>30s}  {'idSpace':>7s}  {'prop':>20s}  {'count':>5s}  {'value':>10s}")
    print("-" * 80)

    for (obj, ids, prop), count in combos.most_common():
        val = combo_vals.get((obj, ids, prop), "")
        val_str = f"{val}" if val != "" else ""
        marker = " ***" if val_str else ""
        print(f"{obj:>30s}  {ids:>7d}  {prop:>20s}  {count:>5d}  {val_str:>10s}{marker}")

    # Show non-zero results separately
    if combo_vals:
        print(f"\n{'='*80}")
        print("NON-ZERO RESULTS:")
        print(f"{'='*80}")
        for (obj, ids, prop), val in sorted(combo_vals.items()):
            print(f"  GetPropertyNumber(\"{obj}\", {ids}, \"{prop}\") = {val}")

    # Show unique objNames
    obj_names = set(c["obj"] for c in calls.values())
    print(f"\nUnique objNames ({len(obj_names)}):")
    for name in sorted(obj_names):
        print(f"  \"{name}\"")

    # Show unique propNames
    prop_names = set(c["prop"] for c in calls.values())
    print(f"\nUnique propNames ({len(prop_names)}):")
    for name in sorted(prop_names):
        print(f"  \"{name}\"")

    return 0


if __name__ == "__main__":
    sys.exit(main())
