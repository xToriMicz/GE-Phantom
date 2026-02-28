"""
GE Phantom — Bot System Test (Self-Contained)

Auto-elevates to admin, injects DLL if needed, then runs bot tests.
No manual steps required — just run it.

Usage:
    python tools/test_bot.py              # auto-discover, inject, test
    python tools/test_bot.py --pid 1234   # specific PID
    python tools/test_bot.py --live       # keep bot running after test
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

DLL_PATH = os.path.join(TOOLS_DIR, "phantom_hook", "phantom_hook.dll")

# How long to wait for ge.exe memory to stabilize before injecting (seconds)
GAME_SETTLE_TIME = 15


# ── Admin Elevation ──────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_and_rerun():
    """Re-launch this script as admin, passing through all CLI args."""
    args = " ".join(f'"{a}"' for a in [os.path.abspath(__file__)] + sys.argv[1:])
    print("[*] Not admin — elevating...")
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, args, os.getcwd(), 1
    )
    if ret <= 32:
        print(f"[!] Elevation failed (code {ret})")
        sys.exit(1)
    # The elevated process runs independently; this one exits.
    sys.exit(0)


# ── DLL Injection ────────────────────────────────────────────

def is_dll_injected(pid: int) -> bool:
    """Check if phantom_hook.dll is already loaded in the target process."""
    try:
        from dll_injector import list_modules
        for name, base, size in list_modules(pid):
            if "phantom_hook" in name.lower():
                return True
    except Exception:
        pass
    return False


def wait_for_game_stable(pid: int, settle_time: int = GAME_SETTLE_TIME):
    """Wait for ge.exe to finish loading — memory usage stabilizes.

    Polls working set size every 2s. Once it stops growing for
    `settle_time` seconds, the game is considered ready.
    """
    print(f"[*] Waiting for PID {pid} to stabilize...")

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", wt.DWORD),
            ("PageFaultCount", wt.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    hProc = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not hProc:
        # Can't query — just wait a flat duration
        print(f"  Cannot query process memory, waiting {settle_time}s flat...")
        time.sleep(settle_time)
        return

    try:
        pmc = PROCESS_MEMORY_COUNTERS()
        pmc.cb = ctypes.sizeof(pmc)
        last_ws = 0
        stable_since = None
        start = time.monotonic()
        max_wait = 120  # absolute max wait

        while time.monotonic() - start < max_wait:
            if psapi.GetProcessMemoryInfo(hProc, ctypes.byref(pmc), ctypes.sizeof(pmc)):
                ws_mb = pmc.WorkingSetSize / (1024 * 1024)
                delta = pmc.WorkingSetSize - last_ws if last_ws else 0
                delta_mb = delta / (1024 * 1024)

                if last_ws > 0 and abs(delta_mb) < 5:
                    # Memory stable (< 5MB change)
                    if stable_since is None:
                        stable_since = time.monotonic()
                    elapsed_stable = time.monotonic() - stable_since
                    print(f"  Memory: {ws_mb:.0f}MB (stable {elapsed_stable:.0f}s/{settle_time}s)")
                    if elapsed_stable >= settle_time:
                        print(f"[+] Game stable — ready to inject")
                        return
                else:
                    # Still loading
                    stable_since = None
                    print(f"  Memory: {ws_mb:.0f}MB (+{delta_mb:.0f}MB, loading...)")

                last_ws = pmc.WorkingSetSize
            time.sleep(2)

        print(f"[*] Max wait reached — proceeding anyway")
    finally:
        k32.CloseHandle(hProc)


def inject(pid: int) -> bool:
    """Inject phantom_hook.dll into the target PID."""
    from dll_injector import inject_dll
    print(f"\n[*] Injecting DLL into PID {pid}...")
    ok = inject_dll(pid, os.path.abspath(DLL_PATH))
    if ok:
        print(f"[+] Injection OK — waiting for DLL init...")
        time.sleep(3)
    else:
        print(f"[!] Injection FAILED")
    return ok


# ── Test Helpers ─────────────────────────────────────────────

class TestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, name: str, condition: bool, detail: str = ""):
        ok = bool(condition)
        tag = "PASS" if ok else "FAIL"
        msg = f"  [{tag}] {name}"
        if detail:
            msg += f" — {detail}"
        print(msg)
        if ok:
            self.passed += 1
        else:
            self.failed += 1

    def summary(self) -> bool:
        total = self.passed + self.failed
        print(f"\n{'=' * 50}")
        print(f"  Results: {self.passed}/{total} passed", end="")
        if self.failed:
            print(f"  ({self.failed} FAILED)")
        else:
            print("  — ALL GOOD")
        print(f"{'=' * 50}")
        return self.failed == 0


def parse_bot_info(info: str) -> dict:
    """Parse 'en=1 pick=1/500 atk=0/2000 skills=3 items=0'"""
    d = {}
    for part in info.split():
        if "=" not in part:
            continue
        key, val = part.split("=", 1)
        if "/" in val:
            on, interval = val.split("/", 1)
            d[key] = {"on": int(on), "interval": int(interval)}
        else:
            d[key] = int(val)
    return d


# ── Test Sequence ────────────────────────────────────────────

def run_tests(cmd, live: bool = False, safe: bool = False) -> bool:
    t = TestRunner()
    mode = "SAFE (protocol only)" if safe else "FULL (will send keys)"
    print(f"\nBot System Test [{mode}] — PID {cmd.pid}")
    print(f"  shmem: {cmd.shmem_name}")
    print("=" * 50)

    # 1. Ping
    print("\n[1] Ping DLL")
    ok = cmd.ping()
    t.check("Ping", ok)
    if not ok:
        print("\n  Cannot reach DLL — aborting.")
        t.summary()
        return False

    # 2. Initial status
    print("\n[2] Initial bot status")
    st = cmd.bot_status()
    t.check("Bot status readable", st is not None)
    if st:
        t.check("Bot starts disabled", not st["enabled"],
                f"enabled={st['enabled']}")
        print(f"       Raw: {st['info']}")

    # 3. Set timers FIRST (before enabling master — avoids firing keys prematurely)
    print("\n[3] Set timers (master still OFF)")
    ok = cmd.bot_set_timer(0, 800)
    t.check("Set pick interval 800ms", ok)
    ok = cmd.bot_set_timer(1, 3000)
    t.check("Set attack interval 3000ms", ok)
    ok = cmd.bot_set_skill(0, 0, 10000)
    t.check("PC1 Q = 10s", ok)
    ok = cmd.bot_set_skill(1, 0, 20000)
    t.check("PC2 A = 20s", ok)
    ok = cmd.bot_set_skill(2, 0, 30000)
    t.check("PC3 Z = 30s", ok)
    ok = cmd.bot_set_item(0, 60000)
    t.check("Item F1 = 60s", ok)

    # 4. Verify timers set (no features enabled yet)
    print("\n[4] Verify timer state")
    time.sleep(0.1)
    st = cmd.bot_status()
    t.check("Status readable", st is not None)
    if st:
        info = parse_bot_info(st.get("info", ""))
        print(f"       Raw: {st['info']}")
        t.check("Master still OFF", info.get("en") == 0)
        t.check("3 skills configured", info.get("skills") == 3, f"skills={info.get('skills')}")
        t.check("1 item configured", info.get("items") == 1, f"items={info.get('items')}")

    if safe:
        # Safe mode: test protocol only — don't enable bot (game may not be in-map)
        print("\n[5] Safe mode — clearing timers without enabling bot")
        cmd.bot_set_skill(0, 0, 0)
        cmd.bot_set_skill(1, 0, 0)
        cmd.bot_set_skill(2, 0, 0)
        cmd.bot_set_item(0, 0)
        cmd.bot_set_timer(0, 500)
        cmd.bot_set_timer(1, 2000)
        time.sleep(0.1)

        st = cmd.bot_status()
        if st:
            info = parse_bot_info(st.get("info", ""))
            t.check("Skills cleared", info.get("skills") == 0, f"skills={info.get('skills')}")
            t.check("Items cleared", info.get("items") == 0, f"items={info.get('items')}")
            print(f"       Raw: {st['info']}")

        print("\n  Safe test complete — bot NOT enabled.")
        print("  To test live: run again without --safe when character is in-map.")
        return t.summary()

    # 5. Enable features (FULL mode — character must be in-map!)
    print("\n[5] Enable bot features")
    ok = cmd.bot_toggle("pick", 1)
    t.check("Toggle pick ON", ok)
    ok = cmd.bot_toggle("attack", 1)
    t.check("Toggle attack ON", ok)

    # 6. Enable master LAST (this starts bot_tick firing keys)
    print("\n[6] Enable master (keys will fire!)")
    ok = cmd.bot_toggle("master", 1)
    t.check("Toggle master ON", ok)
    time.sleep(0.1)

    st = cmd.bot_status()
    if st:
        info = parse_bot_info(st.get("info", ""))
        print(f"       Raw: {st['info']}")
        t.check("Master ON", info.get("en") == 1)
        pick = info.get("pick", {})
        atk = info.get("atk", {})
        t.check("Pick ON", isinstance(pick, dict) and pick.get("on") == 1)
        t.check("Pick interval 800", isinstance(pick, dict) and pick.get("interval") == 800)
        t.check("Attack ON", isinstance(atk, dict) and atk.get("on") == 1)
        t.check("Attack interval 3000", isinstance(atk, dict) and atk.get("interval") == 3000)

    # 7. Let bot tick
    if not live:
        print("\n[7] Let bot tick for 2s (check DLL log for key sends)...")
        time.sleep(2.0)

    # 8. Cleanup (unless --live)
    if live:
        print("\n[8] --live mode: bot left RUNNING")
    else:
        print("\n[8] Cleanup — disable everything")
        cmd.bot_toggle("master", 0)
        cmd.bot_toggle("attack", 0)
        cmd.bot_toggle("pick", 0)
        cmd.bot_set_skill(0, 0, 0)
        cmd.bot_set_skill(1, 0, 0)
        cmd.bot_set_skill(2, 0, 0)
        cmd.bot_set_item(0, 0)
        time.sleep(0.1)

        st = cmd.bot_status()
        if st:
            info = parse_bot_info(st.get("info", ""))
            t.check("Master OFF after cleanup", not st["enabled"])
            t.check("Skills cleared", info.get("skills") == 0, f"skills={info.get('skills')}")
            t.check("Items cleared", info.get("items") == 0, f"items={info.get('items')}")
            print(f"       Raw: {st['info']}")

    return t.summary()


# ── Entry Point ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="GE Phantom Bot System Test")
    parser.add_argument("--pid", type=int, help="Target ge.exe PID")
    parser.add_argument("--live", action="store_true",
                        help="Keep bot running after test (skip cleanup)")
    parser.add_argument("--safe", action="store_true",
                        help="Safe mode: test protocol only, no master enable (works before login)")
    args = parser.parse_args()

    # Step 0: Ensure admin
    if not is_admin():
        elevate_and_rerun()
        # never reaches here

    print("[+] Running as Administrator")

    # Step 1: Find game
    from range_control import PhantomCmd, _get_ge_pids

    pids = _get_ge_pids()
    if not pids:
        print("[!] No ge.exe processes found.")
        input("Press Enter to exit...")
        return 1

    target_pid = args.pid if args.pid else pids[0]
    if target_pid not in pids:
        print(f"[!] PID {target_pid} not found in running ge.exe: {pids}")
        input("Press Enter to exit...")
        return 1

    print(f"[+] Target: ge.exe PID {target_pid}")

    # Step 2: Inject if needed
    if not is_dll_injected(target_pid):
        wait_for_game_stable(target_pid)
        if not inject(target_pid):
            input("Press Enter to exit...")
            return 1
    else:
        print(f"[+] DLL already loaded in PID {target_pid}")

    # Step 3: Connect and test
    try:
        cmd = PhantomCmd(pid=target_pid)
    except RuntimeError as e:
        print(f"[!] Connection failed: {e}")
        input("Press Enter to exit...")
        return 1

    try:
        ok = run_tests(cmd, live=args.live, safe=args.safe)
    finally:
        cmd.close()

    input("\nPress Enter to exit...")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
