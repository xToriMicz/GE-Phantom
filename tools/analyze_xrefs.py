"""
GE_Phantom — Xref Log Analyzer (Phase 2)

Parses phantom_hook.log for xref scan results and extracts candidate
function addresses for GetPropertyNumber / SetPropertyNumber.

Looks for tolua++ registration pattern:
  PUSH string_addr    → the property/function name string
  PUSH func_ptr       → the actual C++ function address
  CALL register_func  → tolua++ registration call

Usage:
  python tools/analyze_xrefs.py                          # Auto-find log
  python tools/analyze_xrefs.py path/to/phantom_hook.log # Explicit path
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Known string addresses from phantom_hook.h
KNOWN_STRINGS = {
    0x00BAD84C: "SetPropertyNumber",
    0x00BE18C8: "GetPropertyNumber",
    0x00B9A564: "SplRange",
    0x00B80F70: "KeepRange",
}

# .text section range
TEXT_START = 0x00401000
TEXT_END   = 0x00B6B000


def parse_xref_log(log_path: str) -> dict:
    """Parse phantom_hook.log and extract xref scan results."""
    results = {
        "scan_found": False,
        "text_region": None,
        "xrefs": [],       # list of xref entries
        "candidates": {},  # label → list of candidate function addrs
    }

    with open(log_path, "r") as f:
        lines = f.readlines()

    in_scan = False
    current_xref = None

    for line in lines:
        line = line.strip()

        # Strip timestamp prefix: [XXXXXXXX]
        m = re.match(r"\[\d+\]\s*(.*)", line)
        if m:
            content = m.group(1)
        else:
            content = line

        # Detect scan start/end
        if "=== XREF SCAN START ===" in content:
            in_scan = True
            results["scan_found"] = True
            continue

        if "=== XREF SCAN DONE" in content:
            m2 = re.search(r"(\d+) total xrefs found", content)
            if m2:
                results["total_xrefs"] = int(m2.group(1))
            in_scan = False
            continue

        if not in_scan:
            continue

        # .text region info
        m = re.match(r'\.text region: base=(\w+) size=0x(\w+) state=0x(\w+) protect=0x(\w+)', content)
        if m:
            results["text_region"] = {
                "base": m.group(1),
                "size": m.group(2),
                "state": m.group(3),
                "protect": m.group(4),
            }
            continue

        # Scanning target line
        m = re.match(r'--- Scanning for "(\w+)" \(0x(\w+)\)', content)
        if m:
            continue

        # XREF hit
        m = re.match(r'XREF #(\d+): "(\w+)" at 0x(\w+) — (.+)', content)
        if m:
            current_xref = {
                "num": int(m.group(1)),
                "label": m.group(2),
                "address": int(m.group(3), 16),
                "instruction": m.group(4),
                "context": None,
                "prev_push": None,
                "next_push": None,
                "next_call": None,
            }
            results["xrefs"].append(current_xref)
            continue

        # Context bytes
        m = re.match(r'context: (.+)', content)
        if m and current_xref:
            current_xref["context"] = m.group(1)
            continue

        # Previous PUSH
        m = re.match(r'prev PUSH: 0x(\w+)', content)
        if m and current_xref:
            current_xref["prev_push"] = int(m.group(1), 16)
            continue

        # Next PUSH
        m = re.match(r'next PUSH: 0x(\w+)', content)
        if m and current_xref:
            current_xref["next_push"] = int(m.group(1), 16)
            continue

        # Next CALL
        m = re.match(r'next CALL: 0x(\w+)', content)
        if m and current_xref:
            current_xref["next_call"] = int(m.group(1), 16)
            continue

        # Found count
        m = re.match(r'Found (\d+) xrefs for "(\w+)"', content)
        if m:
            continue

    # Analyze candidates
    _analyze_candidates(results)
    return results


def _analyze_candidates(results: dict):
    """Extract candidate function addresses from xref patterns."""
    candidates = {}

    for xref in results["xrefs"]:
        label = xref["label"]
        if label not in candidates:
            candidates[label] = []

        entry = {
            "xref_addr": xref["address"],
            "instruction": xref["instruction"],
        }

        # For SetPropertyNumber/GetPropertyNumber string refs:
        # tolua++ pattern is: PUSH func_ptr → PUSH string_ptr → CALL register
        # So the prev_push before the string PUSH is the function pointer
        if label in ("SetPropertyNumber", "GetPropertyNumber"):
            if xref["instruction"] == "PUSH imm32" and xref["prev_push"]:
                func_addr = xref["prev_push"]
                if TEXT_START <= func_addr < TEXT_END:
                    entry["func_addr"] = func_addr
                    entry["confidence"] = "high"
                    entry["reason"] = "prev PUSH is in .text (tolua++ pattern: push func → push name → call reg)"
                else:
                    entry["func_addr"] = func_addr
                    entry["confidence"] = "low"
                    entry["reason"] = f"prev PUSH 0x{func_addr:08X} outside .text range"

            if xref["next_push"]:
                next_addr = xref["next_push"]
                if TEXT_START <= next_addr < TEXT_END:
                    entry["next_func_addr"] = next_addr
                    entry["next_reason"] = "next PUSH is in .text (alternative: push name → push func → call reg)"

            if xref["next_call"]:
                entry["register_call"] = xref["next_call"]

        # For SplRange/KeepRange string refs:
        # These show up in the code that USES the property, not registration
        # The containing function is what we want to understand the calling convention
        if label in ("SplRange", "KeepRange"):
            if xref["next_call"]:
                entry["usage_call"] = xref["next_call"]
                entry["reason"] = "call near the string ref — likely GetPropertyNumber/SetPropertyNumber"

        candidates[label].append(entry)

    results["candidates"] = candidates


def print_report(results: dict):
    """Print a human-readable analysis report."""
    if not results["scan_found"]:
        print("[!] No xref scan output found in log file.")
        print("    DLL may not have run the Phase 2 scan.")
        print("    Re-inject with the Phase 2 DLL or use 'scan' command.")
        return

    total = results.get("total_xrefs", 0)
    print(f"=== Xref Scan Analysis ===")
    print(f"Total xrefs found: {total}")
    print()

    if results["text_region"]:
        r = results["text_region"]
        print(f".text region: base={r['base']} size=0x{r['size']} protect=0x{r['protect']}")
        print()

    # Group xrefs by label
    by_label = {}
    for xref in results["xrefs"]:
        label = xref["label"]
        if label not in by_label:
            by_label[label] = []
        by_label[label].append(xref)

    for label, xrefs in by_label.items():
        print(f"--- {label} ({len(xrefs)} xrefs) ---")
        for xref in xrefs:
            print(f"  0x{xref['address']:08X}  {xref['instruction']}")
            if xref["context"]:
                # Truncate long context
                ctx = xref["context"]
                if len(ctx) > 100:
                    ctx = ctx[:100] + "..."
                print(f"    ctx: {ctx}")
            if xref["prev_push"]:
                in_text = TEXT_START <= xref["prev_push"] < TEXT_END
                marker = " *** IN .TEXT ***" if in_text else ""
                print(f"    prev PUSH: 0x{xref['prev_push']:08X}{marker}")
            if xref["next_push"]:
                in_text = TEXT_START <= xref["next_push"] < TEXT_END
                marker = " *** IN .TEXT ***" if in_text else ""
                print(f"    next PUSH: 0x{xref['next_push']:08X}{marker}")
            if xref["next_call"]:
                print(f"    next CALL: 0x{xref['next_call']:08X}")
        print()

    # Print candidate summary
    print("=== Candidate Function Addresses ===")
    print()

    candidates = results["candidates"]
    for label in ("GetPropertyNumber", "SetPropertyNumber"):
        if label not in candidates:
            print(f"  {label}: no xrefs found")
            continue

        entries = candidates[label]
        high_conf = [e for e in entries if e.get("confidence") == "high"]
        if high_conf:
            print(f"  {label} — HIGH CONFIDENCE candidates:")
            for e in high_conf:
                print(f"    0x{e['func_addr']:08X}  ({e['reason']})")
                if e.get("register_call"):
                    print(f"      register call: 0x{e['register_call']:08X}")
        else:
            print(f"  {label} — no high-confidence candidates found")
            for e in entries:
                if e.get("func_addr"):
                    print(f"    0x{e['func_addr']:08X}  [{e.get('confidence', '?')}] ({e.get('reason', '')})")

        # Also show alternative pattern hits
        alt = [e for e in entries if e.get("next_func_addr")]
        if alt:
            print(f"    Alternatives (next PUSH in .text):")
            for e in alt:
                print(f"      0x{e['next_func_addr']:08X}")

        print()

    # SplRange/KeepRange usage analysis
    for label in ("SplRange", "KeepRange"):
        if label not in candidates:
            continue
        entries = candidates[label]
        calls = [e for e in entries if e.get("usage_call")]
        if calls:
            print(f"  {label} — usage calls (likely Get/SetPropertyNumber):")
            for e in calls:
                print(f"    call 0x{e['usage_call']:08X} near xref at 0x{e['xref_addr']:08X}")
            print()

    # Print recommended commands
    print("=== Recommended Next Steps ===")
    get_candidates = [e.get("func_addr") for e in candidates.get("GetPropertyNumber", [])
                      if e.get("confidence") == "high"]
    set_candidates = [e.get("func_addr") for e in candidates.get("SetPropertyNumber", [])
                      if e.get("confidence") == "high"]

    if get_candidates:
        addr = get_candidates[0]
        print(f"  setaddr get 0x{addr:08X}")
    else:
        print("  # GetPropertyNumber: needs manual analysis")

    if set_candidates:
        addr = set_candidates[0]
        print(f"  setaddr set 0x{addr:08X}")
    else:
        print("  # SetPropertyNumber: needs manual analysis")

    print("  ping")
    print("  probe")


def main():
    # Find log file
    if len(sys.argv) > 1:
        log_path = sys.argv[1]
    else:
        # Default: look next to the DLL
        default = Path(__file__).parent / "phantom_hook" / "phantom_hook.log"
        if default.exists():
            log_path = str(default)
        else:
            print("[!] Log file not found. Pass path as argument.")
            return 1

    print(f"[*] Analyzing: {log_path}")
    print()

    results = parse_xref_log(log_path)
    print_report(results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
