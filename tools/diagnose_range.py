"""
Phase 2B — Diagnostic: Why didn't range modification work?

Checks:
1. Are the addresses still valid after map change?
2. Did our writes actually persist?
3. Differential scan: find what actually changes when you change weapon/skill

Run in Admin terminal:
    python tools/diagnose_range.py check       # Re-read all candidates
    python tools/diagnose_range.py diff-scan    # Find the REAL range address
"""

from __future__ import annotations

import json
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.bot.memory import GameProcess, MemoryError

RESULTS_PATH = ROOT / "data" / "phase2b_results.json"
DIAG_PATH = ROOT / "data" / "diagnose_results.json"

# All candidates from discovery
CANDIDATES = [
    (1, 0x4C903410, 850.0),
    (1, 0x4C903418, 1000.0),
    (2, 0x4927A7D0, 850.0),
    (2, 0x4927A7F8, 1000.0),
    (3, 0x4C8BEDB0, 850.0),
    (3, 0x4C8BEE00, 1000.0),
    (4, 0x45196E88, 850.0),
    (4, 0x45196EF8, 1000.0),
]


def attach() -> GameProcess:
    if not GameProcess.is_admin():
        print("[!] Run as Administrator!")
        sys.exit(1)
    gp = GameProcess()
    gp.open()
    print(f"[+] Attached to ge.exe (PID {gp.pid})")
    return gp


def cmd_check(gp: GameProcess) -> None:
    """Re-read all candidate addresses — see what's there now."""
    print("\n[*] Re-reading all candidate addresses...")
    print(f"{'Group':>6}  {'Address':>14}  {'Expected':>10}  {'Current':>10}  {'Status'}")
    print("-" * 65)

    for group, addr, expected in CANDIDATES:
        try:
            val = gp.read_f32(addr)
            if abs(val - expected) < 0.1:
                status = "MATCH"
            elif abs(val - 99999.0) < 1.0:
                status = "OUR_WRITE (99999)"
            elif 500 <= val <= 1100:
                status = f"RANGE_VALUE"
            else:
                status = "DIFFERENT"
            print(f"  #{group:>3}  0x{addr:>012X}  {expected:>10.1f}  {val:>10.2f}  {status}")
        except MemoryError:
            print(f"  #{group:>3}  0x{addr:>012X}  {expected:>10.1f}  {'UNREADABLE':>10}  DEAD")

    print()
    print("If status = OUR_WRITE: writes persisted but don't affect gameplay")
    print("  -> These are likely a data table, not the live combat value")
    print("  -> Need diff-scan to find the real address")
    print()
    print("If status = DIFFERENT: addresses shifted after map change")
    print("  -> Need full re-scan: python tools/live_test_phase2b.py")


def cmd_diff_scan(gp: GameProcess) -> None:
    """Differential scan: snapshot f32 values, wait for change, find what moved.

    Strategy: Your character has a known attack_range (e.g. 850.0).
    1. Snapshot all memory locations containing that value
    2. You change something in-game (equip different weapon, use a buff)
    3. We re-scan and find which addresses changed

    This finds the LIVE value, not a static table.
    """
    print("\n" + "=" * 50)
    print("  Differential Scan — Find the REAL range address")
    print("=" * 50)

    print("\n  First, we need your character's current attack_range.")
    print("  Check the sniffer/dashboard, or enter a known value.")
    print("  (Common values: 539, 560, 580, 600, 620, 640, 660, 680,")
    print("   700, 720, 740, 760, 780, 800, 803, 850, 900, 950, 1000)")

    val_str = input("\n  Your current attack_range value: ").strip()
    try:
        current_range = float(val_str)
    except ValueError:
        print(f"  [!] Invalid number: {val_str}")
        return

    # Step 1: Snapshot
    print(f"\n[1/3] Scanning for all f32 = {current_range:.1f} in writable memory...")
    hits1 = gp.scan_f32(current_range, writable_only=True)
    print(f"  Found {len(hits1)} addresses")

    if len(hits1) == 0:
        print("  [!] No matches found. Try a different value?")
        return

    if len(hits1) > 50000:
        print(f"  [!] Too many matches ({len(hits1)}). Value might be too common.")
        print("  Try a more specific value.")
        return

    snapshot = set(hits1)

    # Step 2: Wait for in-game change
    print(f"\n[2/3] Now change something in-game that should modify attack_range:")
    print("  - Equip a different weapon")
    print("  - Use a range-changing buff/skill")
    print("  - Switch character class")
    print("  - Or just move to trigger a game state update")

    new_val_str = input("\n  Press Enter when done, then type the NEW expected value: ").strip()
    if not new_val_str:
        new_val_str = input("  New attack_range value: ").strip()

    try:
        new_range = float(new_val_str)
    except ValueError:
        print(f"  [!] Invalid number")
        return

    # Step 3: Re-scan for both old and new value
    print(f"\n[3/3] Re-scanning...")

    # Check which old addresses no longer hold the old value
    print(f"  Checking {len(snapshot)} addresses for changes...")
    changed_from_old = []
    still_old = []
    now_new = []

    for addr in snapshot:
        try:
            val = gp.read_f32(addr)
            if abs(val - current_range) < 0.1:
                still_old.append(addr)
            elif abs(val - new_range) < 0.1:
                now_new.append(addr)
                changed_from_old.append((addr, current_range, val))
            else:
                changed_from_old.append((addr, current_range, val))
        except MemoryError:
            pass

    # Also scan for new value in all memory
    print(f"  Scanning for new value {new_range:.1f}...")
    hits_new = gp.scan_f32(new_range, writable_only=True)
    new_but_not_old = [a for a in hits_new if a not in snapshot]

    # Results
    print(f"\n{'='*50}")
    print(f"  RESULTS")
    print(f"{'='*50}")
    print(f"  Old value ({current_range:.1f}): {len(snapshot)} addresses")
    print(f"  Still old value: {len(still_old)}")
    print(f"  Changed to new ({new_range:.1f}): {len(now_new)}")
    print(f"  Changed to other: {len(changed_from_old) - len(now_new)}")
    print(f"  New addresses with {new_range:.1f}: {len(new_but_not_old)}")

    # The addresses that changed from old to new are our targets!
    if now_new:
        print(f"\n  [+] FOUND {len(now_new)} address(es) that tracked the change!")
        print(f"      These are likely the LIVE attack_range value(s):")
        for i, addr in enumerate(now_new[:20]):
            print(f"      {i+1}. 0x{addr:X}")

        # Dump context around top candidates
        if len(now_new) <= 10:
            print(f"\n  Hex context around candidates:")
            for addr in now_new[:5]:
                print(f"\n  --- 0x{addr:X} ---")
                try:
                    # Read 64 bytes before and after
                    start = max(0, addr - 64)
                    data = gp.read_bytes(start, 192)
                    # Show some neighboring f32 values
                    print(f"  Nearby f32 values:")
                    for off in range(0, len(data) - 3, 4):
                        fval = struct.unpack_from("<f", data, off)[0]
                        abs_addr = start + off
                        marker = " <<<" if abs_addr == addr else ""
                        if 1.0 < abs(fval) < 100000 and fval == fval:  # skip NaN/tiny
                            print(f"    0x{abs_addr:X} (+{off-64:+d}): {fval:.2f}{marker}")
                except MemoryError:
                    pass

        # Save results
        diag = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "old_value": current_range,
            "new_value": new_range,
            "total_old_hits": len(snapshot),
            "changed_to_new": [f"0x{a:X}" for a in now_new],
            "changed_to_new_int": now_new,
            "recommendation": "Try writing to these addresses",
        }
        DIAG_PATH.parent.mkdir(parents=True, exist_ok=True)
        DIAG_PATH.write_text(json.dumps(diag, indent=2))
        print(f"\n  [*] Results saved to {DIAG_PATH}")

        print(f"\n  Next: Try applying to the first candidate:")
        print(f"    python tools/live_apply_test.py --apply 0x{now_new[0]:X} --value 99999")

    elif changed_from_old:
        print(f"\n  [-] {len(changed_from_old)} addresses changed but not to the expected new value.")
        print(f"      Sample changes:")
        for addr, old, new in changed_from_old[:10]:
            print(f"      0x{addr:X}: {old:.2f} -> {new:.2f}")
        print(f"\n  This might mean the value format isn't f32, or the range")
        print(f"  is calculated differently than expected.")
    else:
        print(f"\n  [-] No addresses changed from {current_range:.1f} to {new_range:.1f}")
        print(f"      Possible reasons:")
        print(f"      1. Attack range didn't actually change in-game")
        print(f"      2. Value is stored in a different format (not f32)")
        print(f"      3. Value is server-side only")
        print(f"      4. The range is read-only memory (not writable pages)")
        print(f"\n  Try: python tools/diagnose_range.py diff-scan")
        print(f"  with a buff that visibly changes your range")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python tools/diagnose_range.py check      # Re-read candidates")
        print("  python tools/diagnose_range.py diff-scan   # Find real address")
        sys.exit(1)

    gp = attach()

    cmd = sys.argv[1]
    if cmd == "check":
        cmd_check(gp)
    elif cmd == "diff-scan":
        cmd_diff_scan(gp)
    else:
        print(f"Unknown command: {cmd}")

    gp.close()


if __name__ == "__main__":
    main()
