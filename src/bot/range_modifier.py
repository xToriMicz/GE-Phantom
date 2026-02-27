"""
GE_Phantom — Smart Attack Range Finder & Modifier

Interactive CLI tool for discovering and modifying attack/search range
values in ge.exe memory.

Three phases:
  A) Discovery — scan-only, safe. Finds candidate addresses.
  B) Verification — single write, reversible. Tests if modification works.
  C) Production — auto-apply on startup once confirmed.

Must run as Administrator!

Usage:
    python -m src.bot.range_modifier discover --values 850.0 803.0
    python -m src.bot.range_modifier verify --addr 0x1A2B3C4D --value 1200.0
    python -m src.bot.range_modifier apply --addr 0x1A2B3C4D --value 1200.0
    python -m src.bot.range_modifier monitor --addr 0x1A2B3C4D
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from src.bot.memory import GameProcess, MemoryError

# Known attack_range values from COMBAT_UPDATE packet analysis (f32, 539-1000)
KNOWN_RANGES: list[float] = [
    539.0, 560.0, 580.0, 600.0, 620.0, 640.0, 660.0, 680.0,
    700.0, 720.0, 740.0, 760.0, 780.0, 800.0, 803.0, 850.0,
    900.0, 950.0, 1000.0,
]

# Where to save/load confirmed addresses
CACHE_PATH = Path("data/range_addresses.json")


@dataclass
class ScanResult:
    """A candidate memory address for an attack_range value."""
    address: int
    value: float
    writable: bool = True
    nearby_context: str = ""  # hex dump for visual inspection
    score: float = 0.0       # higher = more likely to be the real one


@dataclass
class CandidateGroup:
    """A group of addresses where multiple range values cluster together."""
    base_address: int
    span: int
    matches: list[tuple[int, float]]  # (addr, value)
    score: float = 0.0

    def __str__(self) -> str:
        lines = [
            f"  Group @ 0x{self.base_address:012X}  "
            f"(span={self.span} bytes, {len(self.matches)} hits, score={self.score:.1f})",
        ]
        for addr, val in self.matches:
            offset = addr - self.base_address
            lines.append(f"    +{offset:4d}  0x{addr:012X}  = {val:.1f}")
        return "\n".join(lines)


# ---- Phase A: Discovery ----

def discover(
    gp: GameProcess,
    values: list[float] | None = None,
    *,
    max_gap: int = 256,
    dump_radius: int = 256,
) -> list[CandidateGroup]:
    """Phase A: Scan memory for attack_range values and find candidate addresses.

    Args:
        gp: Open GameProcess handle.
        values: Float values to scan for (defaults to KNOWN_RANGES subset).
        max_gap: Max bytes between matches to form a group.
        dump_radius: Bytes to dump around each group for inspection.

    Returns:
        Sorted list of CandidateGroups (best first).
    """
    scan_values = values or _pick_scan_values()

    print(f"[*] Scanning for {len(scan_values)} float values in ge.exe memory...")
    print(f"    Values: {', '.join(f'{v:.1f}' for v in scan_values)}")

    # Individual scans
    hit_counts: dict[float, int] = {}
    for v in scan_values:
        pattern = struct.pack("<f", v)
        hits = gp.scan_f32(v, writable_only=True)
        hit_counts[v] = len(hits)
        print(f"    {v:>8.1f} → {len(hits):>6d} writable hits")

    # Correlate: find groups where multiple values are nearby
    print(f"\n[*] Correlating — looking for clusters (max gap = {max_gap} bytes)...")
    groups_raw = gp.correlate_scan(scan_values, max_gap=max_gap, writable_only=True)

    if not groups_raw:
        print("[!] No correlated groups found.")
        print("    Try: different values, larger max_gap, or scan without writable_only")
        return []

    # Convert to CandidateGroup with scoring
    candidates: list[CandidateGroup] = []
    for g in groups_raw:
        cg = CandidateGroup(
            base_address=g["base"],
            span=g["span"],
            matches=g["matches"],
        )
        # Score: more distinct values = better, tighter span = better
        cg.score = g["distinct_values"] * 10.0 - g["span"] * 0.01
        candidates.append(cg)

    candidates.sort(key=lambda c: -c.score)

    print(f"\n[*] Found {len(candidates)} candidate groups:")
    for i, cg in enumerate(candidates[:10]):
        print(f"\n  #{i + 1}")
        print(str(cg))

    # Dump hex context around top candidates
    if dump_radius > 0:
        print(f"\n[*] Hex dump around top candidates (+/- {dump_radius} bytes):")
        for i, cg in enumerate(candidates[:3]):
            print(f"\n  === Candidate #{i + 1} @ 0x{cg.base_address:012X} ===")
            print(gp.dump_hex(cg.base_address, dump_radius))

    return candidates


def _pick_scan_values() -> list[float]:
    """Pick a good subset of known ranges for scanning.

    We don't scan all 18+ — too many false positives. Pick 3-4 spread values.
    """
    # Pick from low, mid, high range for best discrimination
    spread = [539.0, 803.0, 850.0, 1000.0]
    return [v for v in spread if v in KNOWN_RANGES] or KNOWN_RANGES[:4]


# ---- Phase B: Verification ----

@dataclass
class VerifyResult:
    """Result of a single verify attempt."""
    address: int
    original_value: float
    test_value: float
    write_ok: bool
    read_back: float | None
    persisted: bool  # value still there after short delay
    restored: bool   # successfully restored original


def verify_single(
    gp: GameProcess,
    address: int,
    test_value: float | None = None,
    *,
    wait_seconds: float = 2.0,
    auto_restore: bool = True,
) -> VerifyResult:
    """Phase B: Test if writing to an address actually modifies the game value.

    Steps:
        1. Read current value (backup)
        2. Write test value (default: current * 1.5)
        3. Wait, then re-read to check persistence
        4. Optionally restore original

    Args:
        gp: Open GameProcess handle.
        address: Memory address to test.
        test_value: Value to write (default: current * 1.5).
        wait_seconds: How long to wait before re-reading.
        auto_restore: If True, restore original value after test.

    Returns:
        VerifyResult with all details.
    """
    # 1. Read current value
    try:
        original = gp.read_f32(address)
    except MemoryError as e:
        print(f"[!] Cannot read 0x{address:X}: {e}")
        return VerifyResult(address, 0.0, 0.0, False, None, False, False)

    if test_value is None:
        test_value = original * 1.5  # subtle increase

    print(f"[*] Verify @ 0x{address:012X}")
    print(f"    Current value: {original:.2f}")
    print(f"    Test value:    {test_value:.2f}")

    # 2. Write test value
    try:
        gp.write_f32(address, test_value)
        write_ok = True
    except MemoryError as e:
        print(f"[!] Write failed: {e}")
        return VerifyResult(address, original, test_value, False, None, False, False)

    # Immediate read-back
    try:
        readback = gp.read_f32(address)
    except MemoryError:
        readback = None

    if readback is not None and abs(readback - test_value) < 0.1:
        print(f"    Write confirmed (immediate read-back: {readback:.2f})")
    else:
        print(f"    [!] Write may have failed (read-back: {readback})")

    # 3. Wait and check persistence
    print(f"    Waiting {wait_seconds:.1f}s to check persistence...")
    time.sleep(wait_seconds)

    try:
        after_wait = gp.read_f32(address)
        persisted = abs(after_wait - test_value) < 0.1
        print(f"    After wait: {after_wait:.2f} ({'persisted' if persisted else 'RESET by game'})")
    except MemoryError:
        after_wait = None
        persisted = False
        print(f"    [!] Could not re-read after wait")

    # 4. Restore
    restored = False
    if auto_restore:
        try:
            gp.write_f32(address, original)
            verify_restore = gp.read_f32(address)
            restored = abs(verify_restore - original) < 0.1
            print(f"    Restored to {original:.2f}: {'OK' if restored else 'FAILED'}")
        except MemoryError:
            print(f"    [!] Failed to restore original value!")

    return VerifyResult(
        address=address,
        original_value=original,
        test_value=test_value,
        write_ok=write_ok,
        read_back=readback,
        persisted=persisted,
        restored=restored,
    )


def verify_group(
    gp: GameProcess,
    group: CandidateGroup,
    *,
    test_multiplier: float = 1.5,
    wait_seconds: float = 2.0,
) -> list[VerifyResult]:
    """Verify all addresses in a candidate group.

    Returns list of VerifyResults, sorted by most promising first.
    """
    results: list[VerifyResult] = []

    for addr, val in group.matches:
        test_val = val * test_multiplier
        result = verify_single(
            gp, addr, test_val,
            wait_seconds=wait_seconds, auto_restore=True,
        )
        results.append(result)
        print()

    # Sort: persistent writes first
    results.sort(key=lambda r: (-r.persisted, -r.write_ok))
    return results


# ---- Phase C: Production ----

def apply_range(
    gp: GameProcess,
    address: int,
    value: float,
) -> bool:
    """Phase C: Apply a range modification (for confirmed working addresses).

    Args:
        gp: Open GameProcess handle.
        address: Confirmed working address.
        value: New range value to set.

    Returns:
        True if write succeeded and verified.
    """
    try:
        original = gp.read_f32(address)
        print(f"[*] Apply @ 0x{address:012X}: {original:.2f} -> {value:.2f}")

        gp.write_f32(address, value)
        readback = gp.read_f32(address)

        if abs(readback - value) < 0.1:
            print(f"[+] Success! Value is now {readback:.2f}")
            return True
        else:
            print(f"[!] Write didn't stick (read-back: {readback:.2f})")
            return False
    except MemoryError as e:
        print(f"[!] Apply failed: {e}")
        return False


def monitor_address(
    gp: GameProcess,
    address: int,
    *,
    interval: float = 0.5,
    reapply_value: float | None = None,
) -> None:
    """Monitor an address continuously, optionally re-applying a value if reset.

    Args:
        gp: Open GameProcess handle.
        address: Address to monitor.
        interval: Seconds between reads.
        reapply_value: If set, re-apply this value whenever the game resets it.
    """
    print(f"[*] Monitoring 0x{address:012X} (Ctrl+C to stop)")
    if reapply_value is not None:
        print(f"    Auto-reapply: {reapply_value:.2f}")

    last_val = None
    reapply_count = 0

    try:
        while True:
            try:
                val = gp.read_f32(address)
            except MemoryError:
                print(f"  [!] Read failed — process may have closed")
                break

            if val != last_val:
                ts = time.strftime("%H:%M:%S")
                change = ""
                if last_val is not None:
                    delta = val - last_val
                    change = f"  (delta: {delta:+.2f})"
                print(f"  [{ts}] value = {val:.2f}{change}")
                last_val = val

                # Reapply if game reset the value
                if (reapply_value is not None
                        and abs(val - reapply_value) > 0.1):
                    try:
                        gp.write_f32(address, reapply_value)
                        reapply_count += 1
                        print(f"  [{ts}] Reapplied {reapply_value:.2f} "
                              f"(#{reapply_count})")
                    except MemoryError:
                        print(f"  [{ts}] [!] Reapply failed")

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n[*] Stopped. Reapplied {reapply_count} times.")


# ---- Address cache ----

def save_addresses(addresses: dict[str, int], path: Path = CACHE_PATH) -> None:
    """Save confirmed addresses to JSON for reuse."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Convert int addresses to hex strings for readability
    data = {k: f"0x{v:X}" for k, v in addresses.items()}
    path.write_text(json.dumps(data, indent=2))
    print(f"[*] Saved {len(addresses)} addresses to {path}")


def load_addresses(path: Path = CACHE_PATH) -> dict[str, int]:
    """Load previously saved addresses."""
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {k: int(v, 16) for k, v in data.items()}


# ---- CLI ----

def cmd_discover(args: argparse.Namespace) -> None:
    """Run Phase A discovery scan."""
    values = [float(v) for v in args.values] if args.values else None

    with GameProcess() as gp:
        print(f"[*] Connected to ge.exe (PID {gp.pid})")
        candidates = discover(
            gp, values,
            max_gap=args.max_gap,
            dump_radius=args.dump_radius,
        )

        if candidates and args.save:
            # Save top candidate addresses
            addr_map = {}
            for i, cg in enumerate(candidates[:5]):
                for addr, val in cg.matches:
                    addr_map[f"candidate_{i}_{val:.0f}"] = addr
            save_addresses(addr_map)


def cmd_verify(args: argparse.Namespace) -> None:
    """Run Phase B verification on a specific address."""
    address = int(args.addr, 16) if args.addr.startswith("0x") else int(args.addr)

    with GameProcess() as gp:
        print(f"[*] Connected to ge.exe (PID {gp.pid})")
        result = verify_single(
            gp, address,
            test_value=args.value,
            wait_seconds=args.wait,
            auto_restore=not args.no_restore,
        )

        if result.persisted and result.write_ok:
            print("\n[+] This address looks promising!")
            print("    Test in-game: does auto-attack reach further?")
        elif result.write_ok and not result.persisted:
            print("\n[~] Write works but game resets the value.")
            print("    Try: monitor mode with auto-reapply")
        else:
            print("\n[-] This address doesn't seem to be the right one.")


def cmd_apply(args: argparse.Namespace) -> None:
    """Run Phase C: apply modification."""
    address = int(args.addr, 16) if args.addr.startswith("0x") else int(args.addr)

    with GameProcess() as gp:
        print(f"[*] Connected to ge.exe (PID {gp.pid})")
        ok = apply_range(gp, address, args.value)

        if ok and args.monitor:
            monitor_address(
                gp, address,
                reapply_value=args.value if args.reapply else None,
            )


def cmd_monitor(args: argparse.Namespace) -> None:
    """Monitor an address for changes."""
    address = int(args.addr, 16) if args.addr.startswith("0x") else int(args.addr)

    with GameProcess() as gp:
        print(f"[*] Connected to ge.exe (PID {gp.pid})")
        monitor_address(
            gp, address,
            interval=args.interval,
            reapply_value=args.reapply,
        )


def cmd_scan_range(args: argparse.Namespace) -> None:
    """Scan for any f32 in a value range (broad search)."""
    with GameProcess() as gp:
        print(f"[*] Connected to ge.exe (PID {gp.pid})")
        print(f"[*] Scanning for f32 in [{args.min:.1f}, {args.max:.1f}]...")

        results = gp.scan_f32_range(
            args.min, args.max, writable_only=True,
        )
        print(f"[*] Found {len(results)} writable matches")

        # Group by value (rounded)
        by_value: dict[int, int] = {}
        for addr, val in results:
            key = round(val)
            by_value[key] = by_value.get(key, 0) + 1

        print("\n  Value distribution:")
        for val, count in sorted(by_value.items()):
            bar = "#" * min(count, 60)
            print(f"    {val:>6d}: {count:>5d}  {bar}")

        # Show sample addresses for interesting values
        if args.show_addrs:
            for addr, val in results[:args.show_addrs]:
                print(f"    0x{addr:012X} = {val:.2f}")


def cmd_rescan(args: argparse.Namespace) -> None:
    """Re-scan to verify previously saved addresses still hold expected values."""
    addresses = load_addresses()
    if not addresses:
        print("[!] No saved addresses found. Run 'discover --save' first.")
        return

    with GameProcess() as gp:
        print(f"[*] Connected to ge.exe (PID {gp.pid})")
        print(f"[*] Checking {len(addresses)} saved addresses...\n")

        for label, addr in addresses.items():
            try:
                val = gp.read_f32(addr)
                in_range = 500.0 <= val <= 1100.0
                mark = "OK" if in_range else "??"
                print(f"  [{mark}] {label}: 0x{addr:012X} = {val:.2f}")
            except MemoryError:
                print(f"  [!!] {label}: 0x{addr:012X} = UNREADABLE")


def main() -> None:
    if not GameProcess.is_admin():
        print("[!] Not running as Administrator!")
        print("[!] Right-click terminal -> Run as Administrator")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="GE_Phantom — Smart Attack Range Finder & Modifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  discover                         Scan with default known values
  discover --values 850 803        Scan for specific values
  verify --addr 0x1A2B3C4D         Test a candidate address
  apply --addr 0x1A2B3C4D -v 1200  Set range to 1200
  monitor --addr 0x1A2B3C4D        Watch for value changes
  scan-range --min 500 --max 1100  Broad f32 range scan
  rescan                           Check saved addresses
""",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # discover
    p_disc = sub.add_parser("discover", help="Phase A: Scan and correlate")
    p_disc.add_argument("--values", nargs="+", type=float,
                        help="Float values to scan for")
    p_disc.add_argument("--max-gap", type=int, default=256,
                        help="Max bytes between correlated matches (default: 256)")
    p_disc.add_argument("--dump-radius", type=int, default=256,
                        help="Hex dump radius around top candidates (default: 256)")
    p_disc.add_argument("--save", action="store_true",
                        help="Save candidate addresses to data/range_addresses.json")
    p_disc.set_defaults(func=cmd_discover)

    # verify
    p_ver = sub.add_parser("verify", help="Phase B: Test a candidate address")
    p_ver.add_argument("--addr", required=True, help="Address to test (hex or decimal)")
    p_ver.add_argument("--value", type=float, default=None,
                       help="Test value (default: current * 1.5)")
    p_ver.add_argument("--wait", type=float, default=2.0,
                       help="Seconds to wait before re-reading (default: 2)")
    p_ver.add_argument("--no-restore", action="store_true",
                       help="Don't restore original value after test")
    p_ver.set_defaults(func=cmd_verify)

    # apply
    p_app = sub.add_parser("apply", help="Phase C: Apply modification")
    p_app.add_argument("--addr", required=True, help="Confirmed address")
    p_app.add_argument("-v", "--value", type=float, required=True,
                       help="New range value")
    p_app.add_argument("--monitor", action="store_true",
                       help="Continue monitoring after apply")
    p_app.add_argument("--reapply", action="store_true",
                       help="Auto-reapply if game resets the value")
    p_app.set_defaults(func=cmd_apply)

    # monitor
    p_mon = sub.add_parser("monitor", help="Monitor an address for changes")
    p_mon.add_argument("--addr", required=True, help="Address to watch")
    p_mon.add_argument("--interval", type=float, default=0.5,
                       help="Poll interval in seconds (default: 0.5)")
    p_mon.add_argument("--reapply", type=float, default=None,
                       help="Auto-reapply this value if game resets it")
    p_mon.set_defaults(func=cmd_monitor)

    # scan-range
    p_range = sub.add_parser("scan-range", help="Broad f32 range scan")
    p_range.add_argument("--min", type=float, default=500.0,
                         help="Minimum f32 value (default: 500)")
    p_range.add_argument("--max", type=float, default=1100.0,
                         help="Maximum f32 value (default: 1100)")
    p_range.add_argument("--show-addrs", type=int, default=0,
                         help="Show N sample addresses (default: 0)")
    p_range.set_defaults(func=cmd_scan_range)

    # rescan
    p_rescan = sub.add_parser("rescan", help="Re-verify saved addresses")
    p_rescan.set_defaults(func=cmd_rescan)

    args = parser.parse_args()
    try:
        args.func(args)
    except MemoryError as e:
        print(f"\n[!] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")


if __name__ == "__main__":
    main()
