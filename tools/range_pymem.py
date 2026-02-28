"""
GE_Phantom — Attack Range Modifier (Approach B: Pymem Process Injection)

Attaches to ge.exe process using Pymem for direct memory read/write.
Can scan for range values, write new values, and inject a freeze thread
that keeps the range value constant even when the server overwrites it.

Requires:
  pip install pymem
  Run as Administrator!

Usage:
  python -m tools.range_pymem scan                      # Scan for known range values
  python -m tools.range_pymem scan --value 850           # Scan specific value
  python -m tools.range_pymem write --addr 0x1234 --range 5000  # Write once
  python -m tools.range_pymem freeze --addr 0x1234 --range 5000 # Continuous freeze
  python -m tools.range_pymem aob                        # AOB scan for COMBAT_UPDATE struct
  python -m tools.range_pymem diff                       # Differential scan (change weapon)
"""

from __future__ import annotations

import argparse
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# Known attack_range values from protocol analysis
KNOWN_RANGES = [539.0, 560.0, 580.0, 600.0, 620.0, 640.0, 660.0, 680.0,
                700.0, 720.0, 740.0, 760.0, 780.0, 800.0, 803.0, 850.0,
                900.0, 950.0, 1000.0]


def get_pm():
    """Attach to ge.exe with Pymem."""
    try:
        import pymem
    except ImportError:
        print("[!] pymem not installed.")
        print("    pip install pymem")
        sys.exit(1)

    try:
        pm = pymem.Pymem('ge.exe')
    except pymem.exception.ProcessNotFound:
        print("[!] ge.exe not found — is the game running?")
        sys.exit(1)
    except pymem.exception.CouldNotOpenProcess:
        print("[!] Could not open ge.exe — run as Administrator!")
        sys.exit(1)

    print(f"[+] Attached to ge.exe (PID {pm.process_id})")
    return pm


def cmd_scan(pm, target_value: float | None = None) -> None:
    """Scan process memory for attack range float values."""
    import pymem.process

    values = [target_value] if target_value else KNOWN_RANGES[:5]  # top 5 to keep it fast

    print(f"\n[*] Scanning ge.exe for range values: {values}")

    for val in values:
        pattern = struct.pack('<f', val)
        print(f"\n  Scanning for {val:.1f} ({pattern.hex()})...")

        try:
            results = pm.pattern_scan_all(pattern, return_multiple=True)
        except Exception as e:
            print(f"    Error: {e}")
            continue

        if results:
            print(f"  Found {len(results)} match(es):")
            for addr in results[:20]:
                # Read surrounding context
                try:
                    context = pm.read_bytes(addr - 16, 48)
                    nearby_floats = []
                    for off in range(0, 48, 4):
                        f = struct.unpack_from('<f', context, off)[0]
                        if 1.0 < abs(f) < 100000 and f == f:  # skip NaN/tiny
                            marker = " <<<" if off == 16 else ""
                            nearby_floats.append(f"    +{off-16:+3d}: {f:.2f}{marker}")
                    print(f"    0x{addr:X}")
                    for line in nearby_floats:
                        print(line)
                except Exception:
                    print(f"    0x{addr:X} (context unreadable)")
            if len(results) > 20:
                print(f"    ... and {len(results) - 20} more")
        else:
            print(f"  No matches")


def cmd_aob(pm) -> None:
    """AOB (Array of Bytes) scan — find COMBAT_UPDATE-like structures in memory.

    Look for the opcode 0x540c followed by plausible field values that match
    a COMBAT_UPDATE packet layout: [opcode:2][eid:4][...][range:f32@30]
    """
    print("\n[*] AOB Scan — looking for COMBAT_UPDATE structures in memory...")

    # Strategy: scan for the opcode bytes followed by plausible data
    # COMBAT_UPDATE opcode in big-endian: 0x54, 0x0c
    opcode_pattern = b'\x54\x0c'

    try:
        results = pm.pattern_scan_all(opcode_pattern, return_multiple=True)
    except Exception as e:
        print(f"  Error: {e}")
        return

    if not results:
        print("  No 0x540c byte sequences found")
        return

    print(f"  Found {len(results)} occurrences of 0x540c bytes")
    print(f"  Checking for valid COMBAT_UPDATE structure...\n")

    candidates = []

    for addr in results:
        try:
            data = pm.read_bytes(addr, 38)
        except Exception:
            continue

        # Check attack_range field at offset 30
        attack_range = struct.unpack_from('<f', data, 30)[0]
        entity_id = struct.unpack_from('<I', data, 2)[0]
        zone = struct.unpack_from('<I', data, 14)[0]
        state = struct.unpack_from('<I', data, 26)[0]

        # Plausibility checks
        if not (100.0 < attack_range < 10000.0):
            continue
        if entity_id == 0 or entity_id > 0x00FFFFFF:
            continue
        if state not in (0, 2, 4, 30, 81, 119):
            continue

        candidates.append({
            'addr': addr,
            'range_addr': addr + 30,
            'entity_id': entity_id,
            'attack_range': attack_range,
            'zone': zone,
            'state': state,
        })

    if candidates:
        print(f"  Found {len(candidates)} plausible COMBAT_UPDATE structure(s):\n")
        for c in candidates[:30]:
            state_name = {30: "idle", 81: "walk", 119: "run"}.get(c['state'], str(c['state']))
            print(f"    0x{c['addr']:X}  eid={c['entity_id']:<8d}  "
                  f"range={c['attack_range']:>7.1f}  zone={c['zone']}  state={state_name}")
            print(f"      range addr: 0x{c['range_addr']:X}")

        print(f"\n  To modify range, use:")
        first = candidates[0]
        print(f"    python -m tools.range_pymem write --addr 0x{first['range_addr']:X} --range 5000")
        print(f"    python -m tools.range_pymem freeze --addr 0x{first['range_addr']:X} --range 5000")
    else:
        print("  No plausible COMBAT_UPDATE structures found in memory")
        print("  (Game might not have received any COMBAT_UPDATEs yet — try moving around)")


def cmd_write(pm, addr: int, new_range: float) -> None:
    """Write a new range value to a specific address (one-shot)."""
    print(f"\n[*] Writing {new_range:.1f} to 0x{addr:X}...")

    try:
        old = pm.read_float(addr)
        print(f"  Current value: {old:.2f}")
    except Exception as e:
        print(f"  [!] Cannot read address: {e}")
        return

    try:
        pm.write_float(addr, new_range)
        verify = pm.read_float(addr)
        print(f"  Written:  {new_range:.1f}")
        print(f"  Verified: {verify:.2f}")

        if abs(verify - new_range) < 0.1:
            print(f"  [+] Success!")
            print(f"\n  Note: The server may overwrite this value.")
            print(f"  If it resets, use 'freeze' mode instead:")
            print(f"    python -m tools.range_pymem freeze --addr 0x{addr:X} --range {new_range:.0f}")
        else:
            print(f"  [!] Value didn't stick — address may be read-only or recalculated")
    except Exception as e:
        print(f"  [!] Write failed: {e}")


def cmd_freeze(pm, addr: int, new_range: float, interval: float = 0.05) -> None:
    """Continuously write range value to combat server overwrites.

    Writes every `interval` seconds until Ctrl+C.
    """
    print(f"\n[*] Freezing 0x{addr:X} to {new_range:.1f}")
    print(f"    Interval: {interval*1000:.0f}ms")
    print(f"    Press Ctrl+C to stop.\n")

    writes = 0
    overwrites = 0

    try:
        while True:
            try:
                current = pm.read_float(addr)
                if abs(current - new_range) > 0.1:
                    pm.write_float(addr, new_range)
                    overwrites += 1
                    ts = time.strftime("%H:%M:%S")
                    print(f"  [{ts}] Overwrote: {current:.1f} -> {new_range:.1f}  "
                          f"(total: {overwrites})")
                writes += 1
            except Exception as e:
                print(f"  [!] Error: {e}")
                print(f"  [!] Address may have become invalid")
                break

            time.sleep(interval)
    except KeyboardInterrupt:
        pass

    print(f"\n  Freeze stopped: {writes} checks, {overwrites} overwrites")


def cmd_diff(pm) -> None:
    """Differential scan: find addresses that track range changes.

    1. Snapshot all f32 addresses matching a known range
    2. User changes weapon/skill in-game
    3. Re-scan to find which addresses updated
    """
    print("\n" + "=" * 55)
    print("  Differential Scan — Find LIVE range address")
    print("=" * 55)

    print("\n  Your character's current attack_range?")
    print("  (Check sniffer/dashboard, or enter value)")
    print("  Common: 539 560 580 600 620 640 660 680 700 720")
    print("          740 760 780 800 803 850 900 950 1000")

    val_str = input("\n  Current range value: ").strip()
    try:
        current_range = float(val_str)
    except ValueError:
        print(f"  [!] Invalid number: {val_str}")
        return

    # Step 1: Snapshot
    print(f"\n[1/3] Scanning for f32 = {current_range:.1f}...")
    pattern = struct.pack('<f', current_range)

    try:
        hits = pm.pattern_scan_all(pattern, return_multiple=True)
    except Exception as e:
        print(f"  Error: {e}")
        return

    print(f"  Found {len(hits)} addresses")

    if not hits:
        print("  [!] No matches. Try a different value.")
        return
    if len(hits) > 50000:
        print(f"  [!] Too many matches ({len(hits)}). Value too common.")
        return

    snapshot = set(hits)

    # Step 2: Wait for change
    print(f"\n[2/3] Now change something in-game:")
    print("  - Equip a different weapon")
    print("  - Use a range buff/skill")
    print("  - Switch character")

    new_str = input("\n  New expected range value: ").strip()
    try:
        new_range = float(new_str)
    except ValueError:
        print(f"  [!] Invalid number")
        return

    # Step 3: Check which addresses changed
    print(f"\n[3/3] Re-reading {len(snapshot)} addresses...")

    still_old = []
    now_new = []
    changed_other = []

    for addr in snapshot:
        try:
            val = pm.read_float(addr)
            if abs(val - current_range) < 0.1:
                still_old.append(addr)
            elif abs(val - new_range) < 0.1:
                now_new.append(addr)
            else:
                changed_other.append((addr, val))
        except Exception:
            pass

    print(f"\n{'='*55}")
    print(f"  RESULTS")
    print(f"{'='*55}")
    print(f"  Original addresses:    {len(snapshot)}")
    print(f"  Still old value:       {len(still_old)}")
    print(f"  Changed to new range:  {len(now_new)}")
    print(f"  Changed to other:      {len(changed_other)}")

    if now_new:
        print(f"\n  [+] FOUND {len(now_new)} LIVE address(es)!")
        for i, addr in enumerate(now_new[:20]):
            try:
                val = pm.read_float(addr)
                print(f"    {i+1}. 0x{addr:X}  = {val:.2f}")
            except Exception:
                print(f"    {i+1}. 0x{addr:X}  (unreadable now)")

        if len(now_new) <= 10:
            print(f"\n  Context around top candidates:")
            for addr in now_new[:3]:
                try:
                    data = pm.read_bytes(addr - 32, 96)
                    print(f"\n  --- 0x{addr:X} ---")
                    for off in range(0, 96, 4):
                        f = struct.unpack_from('<f', data, off)[0]
                        abs_addr = addr - 32 + off
                        marker = " <<<" if abs_addr == addr else ""
                        if 1.0 < abs(f) < 100000 and f == f:
                            print(f"    0x{abs_addr:X}: {f:.2f}{marker}")
                except Exception:
                    pass

        first = now_new[0]
        print(f"\n  Next steps:")
        print(f"    python -m tools.range_pymem write --addr 0x{first:X} --range 5000")
        print(f"    python -m tools.range_pymem freeze --addr 0x{first:X} --range 5000")
    elif changed_other:
        print(f"\n  [-] Addresses changed but not to expected value:")
        for addr, val in changed_other[:10]:
            print(f"    0x{addr:X}: {current_range:.1f} -> {val:.2f}")
    else:
        print(f"\n  [-] No addresses changed from {current_range:.1f} to {new_range:.1f}")
        print(f"      Possible: range is server-side only, or stored in different format")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GE_Phantom — Attack Range Modifier (Pymem)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Commands:
  scan              Scan memory for known range float values
  aob               AOB scan for COMBAT_UPDATE packet structures in memory
  write             Write a new range value (one-shot)
  freeze            Continuously overwrite range (combats server resets)
  diff              Differential scan (find LIVE range address)
""",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan for range values")
    p_scan.add_argument("--value", type=float, help="Specific float to scan for")

    # aob
    sub.add_parser("aob", help="AOB scan for COMBAT_UPDATE structures")

    # write
    p_write = sub.add_parser("write", help="Write range value (one-shot)")
    p_write.add_argument("--addr", required=True, help="Target address (hex, e.g. 0x1234)")
    p_write.add_argument("--range", type=float, required=True, dest="new_range",
                         help="New range value")

    # freeze
    p_freeze = sub.add_parser("freeze", help="Freeze range value (continuous)")
    p_freeze.add_argument("--addr", required=True, help="Target address (hex, e.g. 0x1234)")
    p_freeze.add_argument("--range", type=float, required=True, dest="new_range",
                          help="New range value")
    p_freeze.add_argument("--interval", type=float, default=0.05,
                          help="Write interval in seconds (default: 0.05)")

    # diff
    sub.add_parser("diff", help="Differential scan (find live address)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Check admin
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[!] Not running as Administrator!")
            print("[!] Right-click terminal -> Run as Administrator")
            sys.exit(1)
    except AttributeError:
        pass

    pm = get_pm()

    if args.command == "scan":
        cmd_scan(pm, args.value)
    elif args.command == "aob":
        cmd_aob(pm)
    elif args.command == "write":
        addr = int(args.addr, 16)
        cmd_write(pm, addr, args.new_range)
    elif args.command == "freeze":
        addr = int(args.addr, 16)
        cmd_freeze(pm, addr, args.new_range, args.interval)
    elif args.command == "diff":
        cmd_diff(pm)


if __name__ == "__main__":
    main()
