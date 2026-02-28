"""
GE Phantom — Bot Control Panel (Tkinter UI)

Global UI for managing multiple GE game instances with phantom_hook DLL.
- Launch game + auto-inject DLL
- List running game instances with bot status
- Per-instance bot configuration (skills, items, auto-pick, auto-attack)
- Status monitoring

Usage:
    python tools/phantom_ui.py
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

# ── Import PhantomCmd from range_control ──────────────────────
TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from range_control import PhantomCmd, _get_ge_pids

# ── Constants ─────────────────────────────────────────────────

APP_NAME = "GE Phantom Control Panel"
APP_VERSION = "1.0.0"
PROJECT_DIR = os.path.dirname(TOOLS_DIR)  # D:/Project/GE_Phantom
DLL_PATH = os.path.join(TOOLS_DIR, "phantom_hook", "phantom_hook.dll")
INJECTOR_PATH = os.path.join(TOOLS_DIR, "dll_injector.py")

CONFIG_FILE = os.path.join(TOOLS_DIR, "phantom_ui_config.json")
DEFAULT_CONFIG = {
    "game": {
        "ge_dir": r"D:\Games\Granado Espada",
    },
}

SKILL_KEYS = [
    ["Q", "W", "E", "R", "T", "Y"],  # PC1
    ["A", "S", "D", "F", "G", "H"],  # PC2
    ["Z", "X", "C", "V", "B", "N"],  # PC3
]

TIMER_PRESETS = [0, 10000, 20000, 30000, 60000, 120000, 300000, 600000]
TIMER_LABELS = ["OFF", "10s", "20s", "30s", "60s", "2m", "5m", "10m"]


def load_config() -> dict:
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                for k, v in DEFAULT_CONFIG.items():
                    if k not in cfg:
                        cfg[k] = v
                return cfg
    except Exception:
        pass
    return DEFAULT_CONFIG.copy()


def save_config(cfg: dict):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4, ensure_ascii=False)
    except Exception:
        pass


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def run_as_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable,
        f'"{os.path.abspath(__file__)}"',
        os.getcwd(), 1
    )
    sys.exit(0)


def format_timer(ms: int) -> str:
    if ms == 0:
        return "OFF"
    if ms < 60000:
        return f"{ms // 1000}s"
    return f"{ms // 60000}m"


def get_window_title(pid: int) -> str:
    """Get the window title for a given PID."""
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    titles = []

    def enum_cb(hwnd, _):
        if not user32.IsWindowVisible(hwnd):
            return True
        p = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid:
            buf = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(hwnd, buf, 256)
            if buf.value:
                titles.append(buf.value)
        return True

    WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    user32.EnumWindows(WNDENUMPROC(enum_cb), 0)
    return titles[0] if titles else f"ge.exe (PID {pid})"


# ── Main Application ─────────────────────────────────────────

class PhantomUI:
    def __init__(self):
        self.config = load_config()
        self.instances: dict[int, PhantomCmd] = {}  # pid -> PhantomCmd

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("700x650")
        self.root.minsize(600, 500)
        self.root.configure(bg="#1a1a2e")

        self.C = {
            "bg": "#1a1a2e", "card": "#16213e", "accent": "#e94560",
            "accent2": "#0f3460", "text": "#eaeaea", "dim": "#a0a0b0",
            "green": "#00d672", "yellow": "#ffa502", "red": "#e94560",
            "dark": "#0d1117",
        }

        self.selected_pid = None
        self._build_ui()
        self._refresh_loop()

    # ── UI Construction ───────────────────────────────────

    def _build_ui(self):
        C = self.C

        # Title
        tk.Label(self.root, text=f"GE Phantom Control Panel",
                 font=("Segoe UI", 16, "bold"),
                 bg=C["bg"], fg=C["text"]).pack(padx=15, pady=(10, 5), anchor="w")

        # Top buttons
        btn_frame = tk.Frame(self.root, bg=C["bg"])
        btn_frame.pack(fill="x", padx=15, pady=5)

        self._btn(btn_frame, "Open Game", C["accent"], self._on_open_game).pack(
            side="left", padx=(0, 5))
        self._btn(btn_frame, "Inject All", C["accent2"], self._on_inject_all).pack(
            side="left", padx=(0, 5))
        self._btn(btn_frame, "Refresh", "#2a2a4a", self._on_refresh).pack(
            side="left", padx=(0, 5))

        # Instance list
        list_frame = tk.LabelFrame(self.root, text="Game Instances",
                                   font=("Segoe UI", 10, "bold"),
                                   bg=C["card"], fg=C["text"],
                                   highlightbackground="#2a2a4a", highlightthickness=1)
        list_frame.pack(fill="x", padx=15, pady=5)

        self.instance_list = tk.Listbox(list_frame, bg=C["dark"], fg=C["text"],
                                        font=("Consolas", 10), selectmode="single",
                                        relief="flat", height=4,
                                        selectbackground=C["accent2"])
        self.instance_list.pack(fill="x", padx=10, pady=8)
        self.instance_list.bind("<<ListboxSelect>>", self._on_select_instance)

        # Bot control panel
        self.bot_frame = tk.LabelFrame(self.root, text="Bot Control",
                                       font=("Segoe UI", 10, "bold"),
                                       bg=C["card"], fg=C["text"],
                                       highlightbackground="#2a2a4a", highlightthickness=1)
        self.bot_frame.pack(fill="both", expand=True, padx=15, pady=5)

        self._build_bot_panel()

        # Log
        log_frame = tk.Frame(self.root, bg=C["bg"])
        log_frame.pack(fill="x", padx=15, pady=(5, 10))

        self.log_text = tk.Text(log_frame, bg=C["dark"], fg="#c9d1d9",
                                font=("Consolas", 9), relief="flat",
                                height=6, padx=8, pady=5, wrap="word")
        scrollbar = tk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.log_text.pack(fill="x")

        self.log_text.tag_configure("ok", foreground="#00d672")
        self.log_text.tag_configure("err", foreground="#e94560")
        self.log_text.tag_configure("info", foreground="#58a6ff")

        self._log(f"{APP_NAME} v{APP_VERSION} started", "info")
        if not is_admin():
            self._log("WARNING: Not running as admin — injection may fail!", "err")

    def _build_bot_panel(self):
        C = self.C
        frame = self.bot_frame

        # Row 1: Master + Pick + Attack
        row1 = tk.Frame(frame, bg=C["card"])
        row1.pack(fill="x", padx=10, pady=(8, 4))

        self.bot_master_var = tk.BooleanVar(value=False)
        self.bot_pick_var = tk.BooleanVar(value=False)
        self.bot_attack_var = tk.BooleanVar(value=False)

        tk.Checkbutton(row1, text="Bot Master", variable=self.bot_master_var,
                       font=("Segoe UI", 10, "bold"), bg=C["card"], fg=C["green"],
                       selectcolor=C["dark"], activebackground=C["card"],
                       command=self._on_toggle_master).pack(side="left", padx=(0, 15))

        tk.Checkbutton(row1, text="Auto Pick", variable=self.bot_pick_var,
                       font=("Segoe UI", 10), bg=C["card"], fg=C["text"],
                       selectcolor=C["dark"], activebackground=C["card"],
                       command=self._on_toggle_pick).pack(side="left", padx=(0, 5))

        self.pick_interval_var = tk.StringVar(value="500")
        tk.Entry(row1, textvariable=self.pick_interval_var, width=6,
                 font=("Consolas", 9), bg=C["dark"], fg=C["text"],
                 insertbackground=C["text"], relief="flat").pack(side="left")
        tk.Label(row1, text="ms", font=("Segoe UI", 9), bg=C["card"],
                 fg=C["dim"]).pack(side="left", padx=(2, 15))

        tk.Checkbutton(row1, text="Auto Attack", variable=self.bot_attack_var,
                       font=("Segoe UI", 10), bg=C["card"], fg=C["text"],
                       selectcolor=C["dark"], activebackground=C["card"],
                       command=self._on_toggle_attack).pack(side="left", padx=(0, 5))

        self.attack_interval_var = tk.StringVar(value="2000")
        tk.Entry(row1, textvariable=self.attack_interval_var, width=6,
                 font=("Consolas", 9), bg=C["dark"], fg=C["text"],
                 insertbackground=C["text"], relief="flat").pack(side="left")
        tk.Label(row1, text="ms", font=("Segoe UI", 9), bg=C["card"],
                 fg=C["dim"]).pack(side="left")

        # Row 2-4: Skill timers (3 PCs × 6 skills)
        self.skill_vars: list[list[tk.StringVar]] = []
        for c in range(3):
            row = tk.Frame(frame, bg=C["card"])
            row.pack(fill="x", padx=10, pady=2)

            tk.Label(row, text=f"PC{c+1}:", font=("Segoe UI", 9, "bold"),
                     bg=C["card"], fg=C["text"], width=4).pack(side="left")

            skill_row = []
            for s in range(6):
                key = SKILL_KEYS[c][s]
                sv = tk.StringVar(value="OFF")
                skill_row.append(sv)

                sf = tk.Frame(row, bg=C["card"])
                sf.pack(side="left", padx=2)

                tk.Label(sf, text=key, font=("Consolas", 9, "bold"),
                         bg=C["card"], fg=C["yellow"], width=2).pack(side="left")

                cb = ttk.Combobox(sf, textvariable=sv, values=TIMER_LABELS,
                                  font=("Consolas", 8), width=4, state="readonly")
                cb.pack(side="left")
                cb.bind("<<ComboboxSelected>>",
                        lambda e, ci=c, si=s: self._on_skill_change(ci, si))

            self.skill_vars.append(skill_row)

        # Row 5: Item timers
        item_row = tk.Frame(frame, bg=C["card"])
        item_row.pack(fill="x", padx=10, pady=(4, 8))

        tk.Label(item_row, text="Items:", font=("Segoe UI", 9, "bold"),
                 bg=C["card"], fg=C["text"], width=5).pack(side="left")

        self.item_vars: list[tk.StringVar] = []
        for i in range(12):
            iv = tk.StringVar(value="OFF")
            self.item_vars.append(iv)

            sf = tk.Frame(item_row, bg=C["card"])
            sf.pack(side="left", padx=1)

            tk.Label(sf, text=f"F{i+1}", font=("Consolas", 8),
                     bg=C["card"], fg=C["dim"], width=3).pack(side="left")

            cb = ttk.Combobox(sf, textvariable=iv, values=TIMER_LABELS,
                              font=("Consolas", 8), width=4, state="readonly")
            cb.pack(side="left")
            cb.bind("<<ComboboxSelected>>",
                    lambda e, slot=i: self._on_item_change(slot))

        # Apply button
        tk.Button(frame, text="Apply Intervals", font=("Segoe UI", 9),
                  bg=C["accent2"], fg="white", relief="flat", pady=4,
                  command=self._on_apply_intervals).pack(padx=10, pady=(0, 8))

    def _btn(self, parent, text, bg, command):
        return tk.Button(parent, text=text, font=("Segoe UI", 10, "bold"),
                         bg=bg, fg="white", relief="flat", padx=12, pady=6,
                         activebackground=bg, cursor="hand2", command=command)

    def _log(self, msg: str, tag: str | None = None):
        self.log_text.insert("end", msg + "\n", tag)
        self.log_text.see("end")

    def _tlog(self, msg: str, tag: str | None = None):
        self.root.after(0, lambda: self._log(msg, tag))

    # ── Instance Management ───────────────────────────────

    def _refresh_instances(self):
        """Scan for running ge.exe processes and update the list."""
        self.instance_list.delete(0, "end")
        pids = _get_ge_pids()

        # Close stale connections
        for pid in list(self.instances.keys()):
            if pid not in pids:
                try:
                    self.instances[pid].close()
                except Exception:
                    pass
                del self.instances[pid]

        for pid in pids:
            # Try connecting
            connected = False
            if pid in self.instances:
                try:
                    connected = self.instances[pid].ping()
                except Exception:
                    connected = False

            if not connected and pid not in self.instances:
                try:
                    cmd = PhantomCmd(pid=pid)
                    if cmd.ping():
                        self.instances[pid] = cmd
                        connected = True
                    else:
                        cmd.close()
                except Exception:
                    pass

            status = "HOOK" if connected else "----"
            title = get_window_title(pid)
            # Truncate title
            if len(title) > 30:
                title = title[:27] + "..."
            self.instance_list.insert("end", f"  PID {pid:>5}  |  {title:<30}  |  {status}")

        count = len(pids)
        hooked = len(self.instances)
        self.root.title(f"[{count} game / {hooked} hooked] {APP_NAME}")

    def _refresh_loop(self):
        self._refresh_instances()
        self.root.after(5000, self._refresh_loop)

    def _get_selected_cmd(self) -> PhantomCmd | None:
        """Get PhantomCmd for the selected instance."""
        sel = self.instance_list.curselection()
        if not sel:
            return None
        line = self.instance_list.get(sel[0])
        # Parse PID from "  PID  1234  | ..."
        try:
            pid = int(line.split("|")[0].strip().replace("PID", "").strip())
        except (ValueError, IndexError):
            return None
        return self.instances.get(pid)

    # ── Actions ───────────────────────────────────────────

    def _on_open_game(self):
        """Launch game and auto-inject DLL."""
        ge_dir = self.config.get("game", {}).get("ge_dir", "")
        ge_exe = os.path.join(ge_dir, "ge.exe")

        if not os.path.exists(ge_exe):
            self._log(f"[!] ge.exe not found at {ge_exe}", "err")
            messagebox.showerror("Error", f"ge.exe not found!\nPath: {ge_exe}")
            return

        def do_launch():
            # Close mutexes for existing clients
            pids_before = set(_get_ge_pids())
            if pids_before:
                self._tlog("[*] Closing mutexes for existing clients...", "info")
                try:
                    # Use GE_MultiClient's mutex closing if available
                    mc_path = os.path.join(os.path.dirname(PROJECT_DIR), "GE_MultiClient", "ge_multi.py")
                    if os.path.exists(mc_path):
                        sys.path.insert(0, os.path.dirname(mc_path))
                        from ge_multi import close_all_mutexes
                        n = close_all_mutexes(log=lambda m: self._tlog(f"  {m}"))
                        self._tlog(f"[+] Closed {n} mutex(es)", "ok")
                    else:
                        self._tlog("[*] GE_MultiClient not found, skipping mutex close", "info")
                except Exception as e:
                    self._tlog(f"[!] Mutex close error: {e}", "err")
                time.sleep(0.5)

            self._tlog("[*] Launching game...", "info")
            try:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", ge_exe, None, ge_dir, 1)
                self._tlog("[+] Game launched!", "ok")
            except Exception as e:
                self._tlog(f"[!] Launch failed: {e}", "err")
                return

            # Wait for new PID and auto-inject
            self._tlog("[*] Waiting for new game process...", "info")
            for _ in range(30):  # 15 seconds
                time.sleep(0.5)
                pids_now = set(_get_ge_pids())
                new_pids = pids_now - pids_before
                if new_pids:
                    new_pid = new_pids.pop()
                    self._tlog(f"[+] New game PID: {new_pid}", "ok")
                    time.sleep(2)  # Let game initialize
                    self._inject_dll(new_pid)
                    self.root.after(1000, self._refresh_instances)
                    return
            self._tlog("[!] Timeout waiting for game process", "err")

        threading.Thread(target=do_launch, daemon=True).start()

    def _inject_dll(self, pid: int):
        """Inject phantom_hook.dll into a specific PID."""
        if not os.path.exists(DLL_PATH):
            self._tlog(f"[!] DLL not found: {DLL_PATH}", "err")
            return

        self._tlog(f"[*] Injecting DLL into PID {pid}...", "info")
        try:
            result = subprocess.run(
                [sys.executable, INJECTOR_PATH, "inject", "--pid", str(pid),
                 "--dll", DLL_PATH],
                capture_output=True, text=True, timeout=30,
                creationflags=0x08000000  # CREATE_NO_WINDOW
            )
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    self._tlog(f"  {line.strip()}", "ok" if "OK" in line or "success" in line.lower() else "info")
            if result.returncode == 0:
                self._tlog(f"[+] DLL injected into PID {pid}", "ok")
            else:
                self._tlog(f"[!] Injection failed (rc={result.returncode})", "err")
                if result.stderr:
                    self._tlog(f"  {result.stderr.strip()}", "err")
        except Exception as e:
            self._tlog(f"[!] Injection error: {e}", "err")

    def _on_inject_all(self):
        """Inject DLL into all running ge.exe that don't have it yet."""
        def do_inject():
            pids = _get_ge_pids()
            if not pids:
                self._tlog("[!] No ge.exe processes found", "err")
                return

            for pid in pids:
                if pid in self.instances:
                    self._tlog(f"[*] PID {pid} already hooked, skipping", "info")
                    continue
                self._inject_dll(pid)
                time.sleep(1)

            self.root.after(2000, self._refresh_instances)

        threading.Thread(target=do_inject, daemon=True).start()

    def _on_refresh(self):
        self._refresh_instances()
        self._log("[+] Refreshed", "ok")

    def _on_select_instance(self, event=None):
        cmd = self._get_selected_cmd()
        if cmd:
            self._update_bot_panel(cmd)

    def _update_bot_panel(self, cmd: PhantomCmd):
        """Refresh bot panel with current state from DLL."""
        try:
            result = cmd.bot_status()
            if result:
                self.bot_master_var.set(result["enabled"])
                # Parse info string: "en=1 pick=1/500 atk=0/2000 skills=3 items=0"
                info = result.get("info", "")
                for part in info.split():
                    if part.startswith("pick="):
                        vals = part[5:].split("/")
                        if len(vals) == 2:
                            self.bot_pick_var.set(vals[0] == "1")
                            self.pick_interval_var.set(vals[1])
                    elif part.startswith("atk="):
                        vals = part[4:].split("/")
                        if len(vals) == 2:
                            self.bot_attack_var.set(vals[0] == "1")
                            self.attack_interval_var.set(vals[1])
        except Exception as e:
            self._log(f"[!] Failed to read bot status: {e}", "err")

    # ── Bot Control Callbacks ─────────────────────────────

    def _on_toggle_master(self):
        cmd = self._get_selected_cmd()
        if not cmd:
            self._log("[!] No instance selected", "err")
            return
        val = 1 if self.bot_master_var.get() else 0
        if cmd.bot_toggle("master", val):
            self._log(f"[+] Bot master: {'ON' if val else 'OFF'}", "ok")
        else:
            self._log("[!] Failed to toggle master", "err")

    def _on_toggle_pick(self):
        cmd = self._get_selected_cmd()
        if not cmd:
            return
        val = 1 if self.bot_pick_var.get() else 0
        cmd.bot_toggle("pick", val)

    def _on_toggle_attack(self):
        cmd = self._get_selected_cmd()
        if not cmd:
            return
        val = 1 if self.bot_attack_var.get() else 0
        cmd.bot_toggle("attack", val)

    def _on_skill_change(self, char_idx: int, skill_idx: int):
        cmd = self._get_selected_cmd()
        if not cmd:
            return
        label = self.skill_vars[char_idx][skill_idx].get()
        idx = TIMER_LABELS.index(label) if label in TIMER_LABELS else 0
        ms = TIMER_PRESETS[idx]
        cmd.bot_set_skill(char_idx, skill_idx, ms)
        self._log(f"[+] PC{char_idx+1} {SKILL_KEYS[char_idx][skill_idx]}: {label}", "ok")

    def _on_item_change(self, slot: int):
        cmd = self._get_selected_cmd()
        if not cmd:
            return
        label = self.item_vars[slot].get()
        idx = TIMER_LABELS.index(label) if label in TIMER_LABELS else 0
        ms = TIMER_PRESETS[idx]
        cmd.bot_set_item(slot, ms)
        self._log(f"[+] Item F{slot+1}: {label}", "ok")

    def _on_apply_intervals(self):
        """Apply pick/attack interval values from text entries."""
        cmd = self._get_selected_cmd()
        if not cmd:
            self._log("[!] No instance selected", "err")
            return

        try:
            pick_ms = int(self.pick_interval_var.get())
            atk_ms = int(self.attack_interval_var.get())
        except ValueError:
            self._log("[!] Invalid interval value", "err")
            return

        cmd.bot_set_timer(0, pick_ms)  # pick interval
        cmd.bot_set_timer(1, atk_ms)   # attack interval
        self._log(f"[+] Intervals: pick={pick_ms}ms attack={atk_ms}ms", "ok")

    def run(self):
        self.root.mainloop()
        # Cleanup
        for cmd in self.instances.values():
            try:
                cmd.close()
            except Exception:
                pass


# ── Entry Point ───────────────────────────────────────────────

if __name__ == "__main__":
    if not is_admin():
        print("Requesting Administrator privileges...")
        run_as_admin()
    else:
        app = PhantomUI()
        app.run()
