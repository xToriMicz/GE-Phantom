"""
Phase 2B — Automated Live Test Script

Run this in an ADMIN terminal with ge.exe running:
    cd D:\\Project\\GE_Phantom
    python tools/live_test_phase2b.py

This script:
1. Discovers candidate attack_range addresses
2. Auto-verifies the top candidates (write/read/persist test)
3. Saves structured results to data/phase2b_results.json

The JSON output can be read by Claude for analysis.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.bot.memory import GameProcess, MemoryError
from src.bot.range_modifier import (
    discover,
    verify_single,
    verify_group,
    save_addresses,
    KNOWN_RANGES,
)

OUTPUT_PATH = ROOT / "data" / "phase2b_results.json"


def main() -> None:
    print("=" * 60)
    print("  GE_Phantom — Phase 2B Live Test")
    print("=" * 60)

    # ---- Admin check ----
    if not GameProcess.is_admin():
        print("\n[!] Not running as Administrator!")
        print("[!] Right-click terminal -> Run as Administrator")
        sys.exit(1)

    results: dict = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "phase": "2B",
        "discovery": {},
        "verification": [],
        "summary": {},
    }

    # ---- Step 1: Attach to ge.exe ----
    print("\n[1/4] Attaching to ge.exe...")
    try:
        gp = GameProcess()
        gp.open()
        regions = gp._ensure_regions()
        print(f"  PID: {gp.pid}")
        print(f"  Regions: {len(regions)} ({sum(r.size for r in regions) / 1024 / 1024:.0f} MB)")
        results["discovery"]["pid"] = gp.pid
        results["discovery"]["regions"] = len(regions)
        results["discovery"]["total_mb"] = round(sum(r.size for r in regions) / 1024 / 1024, 1)
    except Exception as e:
        print(f"  [!] Failed to attach: {e}")
        print("  [!] Is ge.exe running?")
        results["summary"]["error"] = str(e)
        _save(results)
        sys.exit(1)

    # ---- Step 2: Discovery scan ----
    print("\n[2/4] Running discovery scan...")
    try:
        candidates = discover(gp, max_gap=256, dump_radius=128)
        results["discovery"]["candidate_count"] = len(candidates)
        results["discovery"]["candidates"] = []
        for i, cg in enumerate(candidates[:20]):  # top 20
            results["discovery"]["candidates"].append({
                "rank": i + 1,
                "base_address": f"0x{cg.base_address:X}",
                "base_address_int": cg.base_address,
                "span": cg.span,
                "match_count": len(cg.matches),
                "score": round(cg.score, 2),
                "matches": [
                    {"addr": f"0x{a:X}", "addr_int": a, "value": round(v, 2)}
                    for a, v in cg.matches
                ],
            })
    except Exception as e:
        print(f"  [!] Discovery failed: {e}")
        results["summary"]["error"] = str(e)
        _save(results)
        sys.exit(1)

    if not candidates:
        print("\n[!] No candidates found. Try with specific values:")
        print("    python tools/live_test_phase2b.py --values 850.0 803.0")
        results["summary"]["outcome"] = "no_candidates"
        _save(results)
        return

    # ---- Step 3: Verify top 3 groups ----
    print(f"\n[3/4] Verifying top {min(3, len(candidates))} candidate groups...")
    for i, cg in enumerate(candidates[:3]):
        print(f"\n  --- Group #{i + 1} @ 0x{cg.base_address:X} (score={cg.score:.1f}) ---")
        try:
            vresults = verify_group(gp, cg, test_multiplier=1.5, wait_seconds=3.0)
            group_result = {
                "group_rank": i + 1,
                "base_address": f"0x{cg.base_address:X}",
                "verifications": [],
            }
            for vr in vresults:
                group_result["verifications"].append({
                    "address": f"0x{vr.address:X}",
                    "address_int": vr.address,
                    "original_value": round(vr.original_value, 2),
                    "test_value": round(vr.test_value, 2),
                    "write_ok": vr.write_ok,
                    "read_back": round(vr.read_back, 2) if vr.read_back is not None else None,
                    "persisted": vr.persisted,
                    "restored": vr.restored,
                })
            results["verification"].append(group_result)
        except Exception as e:
            print(f"  [!] Verify failed for group #{i + 1}: {e}")
            results["verification"].append({
                "group_rank": i + 1,
                "base_address": f"0x{cg.base_address:X}",
                "error": str(e),
            })

    # ---- Step 4: Summarize ----
    print(f"\n[4/4] Summary")
    print("-" * 40)

    total_verified = 0
    total_persisted = 0
    best_addr = None

    for gres in results["verification"]:
        for v in gres.get("verifications", []):
            total_verified += 1
            if v["write_ok"] and v["persisted"]:
                total_persisted += 1
                if best_addr is None:
                    best_addr = v

    results["summary"] = {
        "total_candidates": len(candidates),
        "groups_verified": len(results["verification"]),
        "addresses_tested": total_verified,
        "persisted_writes": total_persisted,
        "best_candidate": best_addr,
        "outcome": "found_writable" if total_persisted > 0 else "no_persistent_writes",
    }

    if total_persisted > 0:
        print(f"  [+] Found {total_persisted} address(es) where writes persist!")
        print(f"  [+] Best candidate: {best_addr['address']} "
              f"(was {best_addr['original_value']}, wrote {best_addr['test_value']}, persisted)")
        print(f"\n  Next step: Test in-game effect:")
        print(f"    python -m src.bot.range_modifier apply --addr {best_addr['address']} -v 1200")
        print(f"    python -m src.bot.range_modifier monitor --addr {best_addr['address']} --reapply 1200")
    else:
        print(f"  [-] No persistent writes found ({total_verified} addresses tested)")
        print(f"  [-] The game may be resetting values each frame")
        print(f"\n  Next steps:")
        print(f"    1. Try monitor with reapply on the best write-OK address")
        print(f"    2. Run with sniffer to see if packet values change")
        print(f"    3. Consider position spoofing approach instead")

    # ---- Save ----
    _save(results)

    # Also save best addresses for range_modifier reuse
    if total_persisted > 0:
        confirmed: dict[str, int] = {}
        for gres in results["verification"]:
            for v in gres.get("verifications", []):
                if v["write_ok"] and v["persisted"]:
                    label = f"range_{v['original_value']}"
                    confirmed[label] = v["address_int"]
        if confirmed:
            save_addresses(confirmed)

    gp.close()
    print("\nDone.")


def _save(results: dict) -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(results, indent=2, default=str))
    print(f"\n[*] Results saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    # Allow passing specific values from CLI
    if "--values" in sys.argv:
        idx = sys.argv.index("--values")
        values = [float(v) for v in sys.argv[idx + 1:]]
        if values:
            print(f"Using specific values: {values}")
            # Patch into the module for discover() to use
            import src.bot.range_modifier as rm
            rm._pick_scan_values = lambda: values
    main()
