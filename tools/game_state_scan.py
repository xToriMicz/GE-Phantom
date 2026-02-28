"""
GE Game State Scanner — detect which screen the game is on.

Polls ge.exe every 2 seconds and logs:
  - Memory (working set MB)
  - Window title
  - Network connections (TCP ESTABLISHED to game server)
  - Window dimensions

Run this while going through: launcher → login → char select → enter map
Then we'll know what changes between each state.

Usage:
    python tools/game_state_scan.py
    python tools/game_state_scan.py --pid 1234
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)


# ── Win32 helpers ────────────────────────────────────────────

class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD), ("PageFaultCount", wt.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
    ]

psapi = ctypes.WinDLL("psapi", use_last_error=True)
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
u32 = ctypes.WinDLL("user32", use_last_error=True)

WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def get_ge_pid(target_pid=None):
    """Find ge.exe PID."""
    r = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq ge.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True, creationflags=0x08000000
    )
    pids = []
    for line in r.stdout.strip().split("\n"):
        if "ge.exe" in line.lower():
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2:
                try:
                    pids.append(int(parts[1].strip('"')))
                except ValueError:
                    pass
    if target_pid and target_pid in pids:
        return target_pid
    return pids[0] if pids else None


def get_memory_mb(pid):
    """Get working set size in MB."""
    hProc = k32.OpenProcess(0x0400 | 0x0010, False, pid)
    if not hProc:
        return -1
    pmc = PROCESS_MEMORY_COUNTERS()
    pmc.cb = ctypes.sizeof(pmc)
    if psapi.GetProcessMemoryInfo(hProc, ctypes.byref(pmc), ctypes.sizeof(pmc)):
        k32.CloseHandle(hProc)
        return pmc.WorkingSetSize / (1024 * 1024)
    k32.CloseHandle(hProc)
    return -1


def get_windows(pid):
    """Get all visible windows for a PID: [(hwnd, title, x, y, w, h), ...]"""
    results = []

    def cb(hwnd, _):
        if not u32.IsWindowVisible(hwnd):
            return True
        p = wt.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid:
            buf = ctypes.create_unicode_buffer(256)
            u32.GetWindowTextW(hwnd, buf, 256)
            rect = wt.RECT()
            u32.GetWindowRect(hwnd, ctypes.byref(rect))
            w = rect.right - rect.left
            h = rect.bottom - rect.top
            results.append((hwnd, buf.value, rect.left, rect.top, w, h))
        return True

    u32.EnumWindows(WNDENUMPROC(cb), 0)
    return results


def get_net_connections(pid):
    """Get TCP connections for a PID via netstat."""
    try:
        r = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"],
            capture_output=True, text=True, timeout=5, creationflags=0x08000000
        )
        conns = []
        for line in r.stdout.strip().split("\n"):
            if str(pid) in line:
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "TCP":
                    conns.append({
                        "local": parts[1],
                        "remote": parts[2],
                        "state": parts[3],
                    })
        return conns
    except Exception:
        return []


def get_thread_count(pid):
    """Get thread count."""
    try:
        r = subprocess.run(
            ["wmic", "process", "where", "ProcessId=%d" % pid, "get", "ThreadCount", "/value"],
            capture_output=True, text=True, timeout=5, creationflags=0x08000000
        )
        for line in r.stdout.strip().split("\n"):
            if "ThreadCount=" in line:
                return int(line.split("=")[1].strip())
    except Exception:
        pass
    return -1


# ── Main Monitor ─────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="GE Game State Scanner")
    parser.add_argument("--pid", type=int, help="Target PID")
    args = parser.parse_args()

    pid = get_ge_pid(args.pid)
    if not pid:
        print("[!] No ge.exe running")
        return 1

    log_path = os.path.join(TOOLS_DIR, "game_state_log.txt")
    print("GE Game State Scanner — PID %d" % pid)
    print("Log: %s" % log_path)
    print("Go through: launcher -> login -> char select -> enter map")
    print("Press Ctrl+C to stop\n")

    header = "%-6s %7s %5s %3s %-30s %-20s %s" % (
        "Time", "Mem MB", "Thrd", "Net", "Title", "WinSize", "Connections"
    )
    print(header)
    print("-" * 110)

    prev_state = None
    tick = 0

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("GE Game State Scan — PID %d\n" % pid)
        f.write("=" * 80 + "\n\n")
        f.write(header + "\n")
        f.write("-" * 110 + "\n")

        try:
            while True:
                # Check alive
                check_pid = get_ge_pid(pid)
                if check_pid != pid:
                    msg = "[!] ge.exe PID %d gone!" % pid
                    print(msg)
                    f.write(msg + "\n")
                    break

                mem = get_memory_mb(pid)
                threads = get_thread_count(pid)
                windows = get_windows(pid)
                conns = get_net_connections(pid)

                # Main window info
                title = "?"
                win_size = "?"
                if windows:
                    hwnd, t, x, y, w, h = windows[0]
                    title = t[:30] if t else "(no title)"
                    win_size = "%dx%d" % (w, h)

                # Connection summary
                established = [c for c in conns if c["state"] == "ESTABLISHED"]
                conn_str = ""
                if established:
                    remotes = [c["remote"] for c in established]
                    conn_str = " ".join(remotes[:3])
                    if len(remotes) > 3:
                        conn_str += " +%d" % (len(remotes) - 3)

                # State detection
                state = "UNKNOWN"
                if mem < 100:
                    state = "STARTING"
                elif mem < 400:
                    state = "LAUNCHER"
                elif len(established) == 0:
                    state = "NO_NETWORK"
                elif mem < 800:
                    state = "LOGIN/SELECT"
                else:
                    state = "IN_MAP?"

                # Detect state change
                changed = ""
                if prev_state and state != prev_state:
                    changed = " *** STATE CHANGE: %s -> %s ***" % (prev_state, state)
                prev_state = state

                line = "%-6s %7.0f %5d %3d %-30s %-20s %s%s" % (
                    "%ds" % (tick * 2), mem, threads, len(established),
                    title, win_size, conn_str, changed
                )
                print(line)
                f.write(line + "\n")
                f.flush()

                tick += 1
                time.sleep(2)

        except KeyboardInterrupt:
            print("\n[*] Stopped by user")
            f.write("\n[*] Stopped by user\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
