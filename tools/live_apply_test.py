"""
Phase 2B — In-Game Apply Test

Run in Admin terminal when you're on a map with monsters:
    python tools/live_apply_test.py

Tests each candidate group one by one:
  1. Re-reads current value (confirms address still valid)
  2. Writes 1200.0 (increased range)
  3. Waits for you to test in-game (press Enter to continue)
  4. Restores original value
  5. Moves to next group

Also supports direct apply mode:
    python tools/live_apply_test.py --apply 0x4C903410 --value 1200
    python tools/live_apply_test.py --monitor 0x4C903410 --reapply 1200
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.bot.memory import GameProcess, MemoryError

RESULTS_PATH = ROOT / "data" / "phase2b_results.json"
LOG_PATH = ROOT / "data" / "apply_test_log.json"

# Top candidates from discovery
DEFAULT_CANDIDATES = [
    {"group": 1, "addr": 0x4C903410, "expected": 850.0, "span": 8},
    {"group": 1, "addr": 0x4C903418, "expected": 1000.0, "span": 8},
    {"group": 2, "addr": 0x4927A7D0, "expected": 850.0, "span": 40},
    {"group": 2, "addr": 0x4927A7F8, "expected": 1000.0, "span": 40},
    {"group": 3, "addr": 0x4C8BEDB0, "expected": 850.0, "span": 80},
    {"group": 3, "addr": 0x4C8BEE00, "expected": 1000.0, "span": 80},
    {"group": 4, "addr": 0x45196E88, "expected": 850.0, "span": 112},
    {"group": 4, "addr": 0x45196EF8, "expected": 1000.0, "span": 112},
]

TEST_VALUE = 1200.0


def attach() -> GameProcess:
    if not GameProcess.is_admin():
        print("[!] Not running as Administrator!")
        sys.exit(1)
    gp = GameProcess()
    gp.open()
    print(f"[+] Attached to ge.exe (PID {gp.pid})")
    return gp


def check_addresses(gp: GameProcess) -> list[dict]:
    """Re-read all candidate addresses to see which are still valid."""
    print("\n[*] Checking candidate addresses...")
    valid = []
    for c in DEFAULT_CANDIDATES:
        addr = c["addr"]
        try:
            val = gp.read_f32(addr)
            status = "match" if abs(val - c["expected"]) < 0.1 else "changed"
            print(f"  Group #{c['group']}  0x{addr:X}  = {val:.2f}  "
                  f"(expected {c['expected']:.1f}) [{status}]")
            valid.append({**c, "current": val, "status": status})
        except MemoryError:
            print(f"  Group #{c['group']}  0x{addr:X}  = UNREADABLE")
            valid.append({**c, "current": None, "status": "unreadable"})
    return valid


def interactive_test(gp: GameProcess, candidates: list[dict]) -> list[dict]:
    """Test each group interactively."""
    log = []

    # Group candidates by group number, only test matching ones
    groups: dict[int, list[dict]] = {}
    for c in candidates:
        if c["status"] == "match":
            groups.setdefault(c["group"], []).append(c)

    if not groups:
        print("\n[!] No addresses still hold expected values!")
        print("    Addresses may have shifted after zone change.")
        print("    Run: python tools/live_test_phase2b.py  (full re-scan)")
        return log

    print(f"\n[*] Testing {len(groups)} group(s) with matching values")
    print(f"    Will write {TEST_VALUE:.0f} to each 850.0 address")
    print(f"    Press Enter after checking in-game to continue")
    print("=" * 50)

    for gnum, addrs in sorted(groups.items()):
        # Find the 850.0 address in this group (the one we'll modify)
        target = next((a for a in addrs if abs(a["expected"] - 850.0) < 0.1), None)
        if not target:
            continue

        addr = target["addr"]
        original = target["current"]

        print(f"\n--- Group #{gnum} @ 0x{addr:X} ---")
        print(f"  Current: {original:.2f}")
        print(f"  Writing: {TEST_VALUE:.2f}")

        # Write
        try:
            gp.write_f32(addr, TEST_VALUE)
            readback = gp.read_f32(addr)
            print(f"  Written! Read-back: {readback:.2f}")
        except MemoryError as e:
            print(f"  [!] Write failed: {e}")
            log.append({"group": gnum, "addr": f"0x{addr:X}", "result": "write_failed"})
            continue

        # Wait for user to test
        print(f"\n  >>> Go test in-game! Does auto-attack reach further? <<<")
        print(f"  >>> Press Enter when done testing (or 'y' if it worked) <<<")
        response = input("  Result: ").strip().lower()

        worked = response in ("y", "yes", "1", "true")

        # Read value again to check if game reset it
        try:
            after_val = gp.read_f32(addr)
            was_reset = abs(after_val - TEST_VALUE) > 0.1
        except MemoryError:
            after_val = None
            was_reset = True

        entry = {
            "group": gnum,
            "addr": f"0x{addr:X}",
            "addr_int": addr,
            "original": original,
            "test_value": TEST_VALUE,
            "readback": readback,
            "after_test": after_val,
            "was_reset": was_reset,
            "user_confirmed_effect": worked,
            "result": "SUCCESS" if worked else ("reset_by_game" if was_reset else "no_effect"),
        }
        log.append(entry)

        if worked:
            print(f"  [+] GROUP #{gnum} WORKS!")
        elif was_reset:
            print(f"  [-] Value was reset to {after_val:.2f} by game loop")
        else:
            print(f"  [-] No in-game effect observed")

        # Restore
        try:
            gp.write_f32(addr, original)
            print(f"  Restored to {original:.2f}")
        except MemoryError:
            print(f"  [!] Could not restore!")

    return log


def monitor_mode(gp: GameProcess, addr: int, reapply: float | None = None) -> None:
    """Monitor a single address continuously."""
    print(f"\n[*] Monitoring 0x{addr:X} (Ctrl+C to stop)")
    if reapply is not None:
        print(f"    Auto-reapply: {reapply:.2f}")

    last_val = None
    reapply_count = 0

    try:
        while True:
            try:
                val = gp.read_f32(addr)
            except MemoryError:
                print(f"  [!] Read failed — process may have closed")
                break

            if last_val is None or abs(val - last_val) > 0.01:
                ts = time.strftime("%H:%M:%S")
                delta = f"  (delta: {val - last_val:+.2f})" if last_val is not None else ""
                print(f"  [{ts}] {val:.2f}{delta}")
                last_val = val

                if reapply is not None and abs(val - reapply) > 0.1:
                    try:
                        gp.write_f32(addr, reapply)
                        reapply_count += 1
                        print(f"  [{ts}] Reapplied {reapply:.2f} (#{reapply_count})")
                    except MemoryError:
                        print(f"  [{ts}] [!] Reapply failed")

            time.sleep(0.3)
    except KeyboardInterrupt:
        print(f"\n[*] Stopped. Reapplied {reapply_count} times.")


def main() -> None:
    print("=" * 50)
    print("  GE_Phantom — Phase 2B In-Game Test")
    print("=" * 50)

    # Parse simple args
    args = sys.argv[1:]

    gp = attach()

    # Direct apply mode
    if "--apply" in args:
        idx = args.index("--apply")
        addr = int(args[idx + 1], 16) if args[idx + 1].startswith("0x") else int(args[idx + 1])
        value = float(args[args.index("--value") + 1]) if "--value" in args else TEST_VALUE
        try:
            original = gp.read_f32(addr)
            print(f"  0x{addr:X}: {original:.2f} -> {value:.2f}")
            gp.write_f32(addr, value)
            readback = gp.read_f32(addr)
            print(f"  Written! Read-back: {readback:.2f}")
        except MemoryError as e:
            print(f"  [!] Failed: {e}")
        gp.close()
        return

    # Direct monitor mode
    if "--monitor" in args:
        idx = args.index("--monitor")
        addr = int(args[idx + 1], 16) if args[idx + 1].startswith("0x") else int(args[idx + 1])
        reapply = float(args[args.index("--reapply") + 1]) if "--reapply" in args else None
        monitor_mode(gp, addr, reapply)
        gp.close()
        return

    # Interactive test mode (default)
    candidates = check_addresses(gp)
    log = interactive_test(gp, candidates)

    # Save log
    if log:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        LOG_PATH.write_text(json.dumps(log, indent=2))
        print(f"\n[*] Test log saved to {LOG_PATH}")

        # Summary
        successes = [e for e in log if e["result"] == "SUCCESS"]
        if successes:
            print(f"\n[+] {len(successes)} working address(es) found!")
            for s in successes:
                print(f"    {s['addr']} (group #{s['group']})")
            print(f"\n  To apply permanently:")
            print(f"    python tools/live_apply_test.py --apply {successes[0]['addr']} --value 1200")
            print(f"  To monitor with auto-reapply:")
            print(f"    python tools/live_apply_test.py --monitor {successes[0]['addr']} --reapply 1200")

    gp.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
