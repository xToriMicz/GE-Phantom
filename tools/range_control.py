"""
GE_Phantom — Range Control (Phase 2)

Interactive controller for the phantom_hook DLL's command interface.
Communicates via shared memory to trigger xref scans, read/write
IES properties (GetPropertyNumber / SetPropertyNumber).

Usage:
  python tools/range_control.py              # Interactive mode
  python tools/range_control.py ping         # Ping DLL
  python tools/range_control.py scan         # Trigger xref scan
  python tools/range_control.py get <prop>   # Get property value
  python tools/range_control.py set <prop> <value>  # Set property value

Requires: phantom_hook.dll injected into ge.exe (via dll_injector.py)
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import mmap
import struct
import sys
import time

# ── Shared Memory Layout (must match phantom_hook.h) ──────────

SHMEM_NAME_LEGACY = "Local\\ge_phantom_cmd"       # old (non-PID)
SHMEM_NAME_FMT    = "Local\\ge_phantom_cmd_%u"    # new (per-PID)
SHMEM_SIZE = 256

# Offsets
OFF_COMMAND     = 0x00
OFF_STATUS      = 0x01
OFF_PARAM1      = 0x04
OFF_PARAM2      = 0x08
OFF_RESULT_I32  = 0x0C
OFF_RESULT_F32  = 0x10
OFF_RESULT_F64  = 0x14
OFF_CMD_SEQ     = 0x02
OFF_ACK_SEQ     = 0x03
OFF_STR_PARAM   = 0x20
OFF_STR_PARAM2  = 0x60
OFF_STR_RESULT  = 0xA0

# Commands
CMD_NOP         = 0x00
CMD_SCAN        = 0x01
CMD_GET_PROP    = 0x02
CMD_SET_PROP    = 0x03
CMD_READ_ADDR       = 0x10
CMD_SET_FUNC_ADDR   = 0x11
CMD_FIND_STRING     = 0x12
CMD_HOOK_GETPROP    = 0x20
CMD_UNHOOK_GETPROP  = 0x21
CMD_HOOK_SETPROP    = 0x22
CMD_UNHOOK_SETPROP  = 0x23
CMD_VTABLE_SPY          = 0x30
CMD_HOOK_VTABLE_GET     = 0x31
CMD_UNHOOK_VTABLE_GET   = 0x32
CMD_SET_VTGET_OVERRIDE  = 0x33
CMD_VTGET_STATUS        = 0x34
CMD_CHAT            = 0x40   # ⚠ UNSAFE: causes disconnect! Requires param1=0xCAFE
CMD_SYSMSG          = 0x41
CMD_UPDATE_ITEM_TABLE = 0x42
CMD_SEND_KEY        = 0x43
CMD_SEND_KEYS       = 0x44
CMD_KEY_COMBO       = 0x45   # KeyCombo: param1=VK, param2=modifier bitmask
CMD_DUMP_MEM        = 0x50
CMD_SCAN_XREF_STR   = 0x51
CMD_HOOK_WNDPROC    = 0x60   # Install WndProc subclass to log keyboard msgs
CMD_UNHOOK_WNDPROC  = 0x61   # Remove WndProc subclass
CMD_CHECK_RAW_INPUT = 0x62   # Check if game imports Raw Input API
CMD_WNDPROC_STATUS  = 0x63   # Read WndProc message counters
CMD_KB_DIAG         = 0x64   # Keyboard input diagnostic

# Bot Control
CMD_BOT_STATUS      = 0x70   # Get bot status → str_result
CMD_BOT_TOGGLE      = 0x71   # Toggle feature: param1=feature, param2=value
CMD_BOT_SET_TIMER   = 0x72   # Set timer: param1=timer_id, param2=interval_ms

CMD_PING            = 0xFE

# Status
STATUS_IDLE     = 0x00
STATUS_BUSY     = 0x01
STATUS_DONE     = 0x02
STATUS_ERROR    = 0xFF

# Known properties
KNOWN_PROPS = [
    "SplRange",
    "KeepRange",
    "ViewRange",
    "AiRange",
    "MaxLinkRange",
]

# ── Win32 API ─────────────────────────────────────────────────

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Set correct return types for 64-bit Python (default c_int truncates pointers)
kernel32.OpenFileMappingA.restype = wt.HANDLE
kernel32.MapViewOfFile.restype = ctypes.c_void_p
kernel32.MapViewOfFile.argtypes = [
    wt.HANDLE, wt.DWORD, wt.DWORD, wt.DWORD, ctypes.c_size_t
]
kernel32.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
kernel32.UnmapViewOfFile.restype = wt.BOOL

FILE_MAP_ALL_ACCESS = 0x000F001F


def open_shmem(name: str = SHMEM_NAME_LEGACY) -> tuple | None:
    """Open the shared memory created by phantom_hook DLL."""
    handle = kernel32.OpenFileMappingA(
        FILE_MAP_ALL_ACCESS,
        False,
        name.encode("ascii"),
    )
    if not handle:
        return None

    ptr = kernel32.MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, SHMEM_SIZE)
    if not ptr:
        kernel32.CloseHandle(handle)
        return None

    buf = (ctypes.c_char * SHMEM_SIZE).from_address(ptr)
    return handle, ptr, buf


def _get_ge_pids() -> list[int]:
    """Get all ge.exe PIDs via tasklist."""
    import subprocess
    try:
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq ge.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, creationflags=0x08000000  # CREATE_NO_WINDOW
        )
        pids = []
        for line in result.stdout.strip().split("\n"):
            if line.strip() and "ge.exe" in line.lower():
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 2:
                    try:
                        pids.append(int(parts[1].strip('"')))
                    except ValueError:
                        pass
        return pids
    except Exception:
        return []


class PhantomCmd:
    """Interface to phantom_hook DLL command shared memory.

    Usage:
        cmd = PhantomCmd()           # auto-discover first available
        cmd = PhantomCmd(pid=1234)   # connect to specific PID
    """

    def __init__(self, pid: int | None = None):
        self._pid = pid
        self._shmem_name = None

        if pid is not None:
            # Try per-PID name first, fall back to legacy
            name = SHMEM_NAME_FMT % pid
            result = open_shmem(name)
            if result is None:
                result = open_shmem(SHMEM_NAME_LEGACY)
                name = SHMEM_NAME_LEGACY
            self._shmem_name = name
        else:
            # Auto-discover: try all ge.exe PIDs, then legacy
            for p in _get_ge_pids():
                name = SHMEM_NAME_FMT % p
                result = open_shmem(name)
                if result is not None:
                    self._pid = p
                    self._shmem_name = name
                    break
            else:
                # Fall back to legacy (old DLL without per-PID naming)
                result = open_shmem(SHMEM_NAME_LEGACY)
                self._shmem_name = SHMEM_NAME_LEGACY

        if result is None:
            raise RuntimeError(
                "Cannot open shared memory. Is phantom_hook.dll injected?\n"
                f"  Tried: per-PID shmem + legacy ({SHMEM_NAME_LEGACY})"
            )
        self._handle, self._ptr, self._buf = result
        self._seq = 0

    @property
    def pid(self) -> int | None:
        return self._pid

    @property
    def shmem_name(self) -> str | None:
        return self._shmem_name

    @staticmethod
    def discover() -> list[dict]:
        """Scan for all ge.exe processes with phantom_hook shmem.
        Returns list of {pid, shmem_name} for connected instances."""
        found = []
        for pid in _get_ge_pids():
            name = SHMEM_NAME_FMT % pid
            result = open_shmem(name)
            if result is not None:
                handle, ptr, buf = result
                kernel32.UnmapViewOfFile(ptr)
                kernel32.CloseHandle(handle)
                found.append({"pid": pid, "shmem_name": name})
        # Also check legacy
        result = open_shmem(SHMEM_NAME_LEGACY)
        if result is not None:
            handle, ptr, buf = result
            kernel32.UnmapViewOfFile(ptr)
            kernel32.CloseHandle(handle)
            if not any(f["shmem_name"] == SHMEM_NAME_LEGACY for f in found):
                found.append({"pid": None, "shmem_name": SHMEM_NAME_LEGACY})
        return found

    def close(self):
        if self._ptr:
            kernel32.UnmapViewOfFile(self._ptr)
            self._ptr = None
        if self._handle:
            kernel32.CloseHandle(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _read_byte(self, offset: int) -> int:
        return self._buf[offset][0]

    def _write_byte(self, offset: int, value: int):
        self._buf[offset] = bytes([value])

    def _read_u32(self, offset: int) -> int:
        return struct.unpack_from("<I", bytes(self._buf[offset:offset+4]))[0]

    def _write_u32(self, offset: int, value: int):
        data = struct.pack("<I", value)
        for i, b in enumerate(data):
            self._buf[offset + i] = bytes([b])

    def _read_f64(self, offset: int) -> float:
        return struct.unpack_from("<d", bytes(self._buf[offset:offset+8]))[0]

    def _write_f64(self, offset: int, value: float):
        data = struct.pack("<d", value)
        for i, b in enumerate(data):
            self._buf[offset + i] = bytes([b])

    def _write_str(self, offset: int, s: str, max_len: int = 64):
        encoded = s.encode("ascii", errors="replace")[:max_len - 1] + b"\x00"
        padded = encoded.ljust(max_len, b"\x00")
        for i, b in enumerate(padded):
            self._buf[offset + i] = bytes([b])

    def _read_str(self, offset: int, max_len: int = 96) -> str:
        raw = bytes(self._buf[offset:offset + max_len])
        end = raw.find(b"\x00")
        if end >= 0:
            raw = raw[:end]
        return raw.decode("ascii", errors="replace")

    def _send_cmd(self, cmd: int, timeout: float = 5.0) -> int:
        """Send a command and wait for completion. Returns status code.

        Uses a sequence counter handshake: Python writes cmd_seq, DLL echoes
        it to ack_seq. This detects stale DLLs that process the command but
        don't know the current protocol (they won't echo the seq).
        """
        # Wait for any previous command to finish (avoid stale status reads)
        for _ in range(20):
            prev_cmd = self._read_byte(OFF_COMMAND)
            if prev_cmd == CMD_NOP:
                break
            time.sleep(0.05)

        # Increment sequence counter (wraps at 255)
        self._seq = (self._seq + 1) & 0xFF
        if self._seq == 0:
            self._seq = 1  # avoid 0 — indistinguishable from uninitialized
        self._write_byte(OFF_CMD_SEQ, self._seq)

        # Clear ack and status, then write command
        self._write_byte(OFF_ACK_SEQ, 0)
        self._write_byte(OFF_STATUS, STATUS_IDLE)
        self._write_byte(OFF_COMMAND, cmd)

        # Poll for completion
        start = time.monotonic()
        while True:
            status = self._read_byte(OFF_STATUS)
            if status == STATUS_DONE or status == STATUS_ERROR:
                # Verify this response is from OUR DLL (seq handshake)
                ack = self._read_byte(OFF_ACK_SEQ)
                if ack == self._seq:
                    return status
                # Wrong ack — a stale DLL handled it, not ours.
                # If status is ERROR with wrong ack, it's likely a stale
                # DLL that doesn't know this command. Keep waiting in case
                # our DLL hasn't polled yet, but the command byte may
                # already be cleared by the stale DLL.
                cmd_now = self._read_byte(OFF_COMMAND)
                if cmd_now == CMD_NOP and status == STATUS_ERROR:
                    # Stale DLL ate our command. Return a distinct code.
                    return -2  # stale DLL conflict
            if time.monotonic() - start > timeout:
                return -1  # timeout
            time.sleep(0.05)

    def ping(self) -> bool:
        """Ping the DLL. Returns True if it responds."""
        status = self._send_cmd(CMD_PING)
        if status == -2:
            return False  # stale DLL conflict
        if status == STATUS_DONE:
            val = self._read_u32(OFF_RESULT_I32)
            return val == 0xDEADBEEF
        return False

    @property
    def last_status_was_stale(self) -> bool:
        """Check if the last _send_cmd returned -2 (stale DLL conflict)."""
        # Caller can check ack mismatch after any command
        ack = self._read_byte(OFF_ACK_SEQ)
        return ack != self._seq

    def scan(self) -> bool:
        """Trigger xref scan. Results are written to phantom_hook.log."""
        status = self._send_cmd(CMD_SCAN, timeout=30.0)
        return status == STATUS_DONE

    def get_property(self, prop_name: str, id_space: int = 0,
                     obj_name: str = "") -> float | None:
        """Read a property value via GetPropertyNumber."""
        self._write_u32(OFF_PARAM1, id_space)
        self._write_str(OFF_STR_PARAM, prop_name)
        self._write_str(OFF_STR_PARAM2, obj_name)

        status = self._send_cmd(CMD_GET_PROP)
        if status == STATUS_DONE:
            return self._read_f64(OFF_RESULT_F64)
        return None

    def set_property(self, prop_name: str, value: float, id_space: int = 0,
                     obj_name: str = "") -> bool:
        """Write a property value via SetPropertyNumber."""
        self._write_u32(OFF_PARAM1, id_space)
        self._write_str(OFF_STR_PARAM, prop_name)
        self._write_str(OFF_STR_PARAM2, obj_name)
        self._write_f64(OFF_RESULT_F64, value)

        status = self._send_cmd(CMD_SET_PROP)
        return status == STATUS_DONE

    def read_addr(self, address: int) -> int | None:
        """Read 4 bytes from an address in ge.exe memory."""
        self._write_u32(OFF_PARAM1, address)
        status = self._send_cmd(CMD_READ_ADDR)
        if status == STATUS_DONE:
            return self._read_u32(OFF_RESULT_I32)
        return None

    def set_func_addr(self, which: int, address: int) -> bool:
        """Set a function address in the DLL. which: 0=GetPropertyNumber, 1=SetPropertyNumber."""
        self._write_u32(OFF_PARAM1, address)
        self._write_u32(OFF_PARAM2, which)
        status = self._send_cmd(CMD_SET_FUNC_ADDR)
        return status == STATUS_DONE

    def hook_getprop(self) -> bool:
        """Install logging hook on GetPropertyNumber. Logs all game calls to phantom_hook.log."""
        status = self._send_cmd(CMD_HOOK_GETPROP)
        return status == STATUS_DONE

    def unhook_getprop(self) -> int:
        """Remove logging hook. Returns total number of calls logged."""
        status = self._send_cmd(CMD_UNHOOK_GETPROP)
        if status == STATUS_DONE:
            return self._read_u32(OFF_RESULT_I32)
        return -1

    def hook_setprop(self) -> bool:
        """Install logging hook on SetPropertyNumber."""
        status = self._send_cmd(CMD_HOOK_SETPROP)
        return status == STATUS_DONE

    def unhook_setprop(self) -> int:
        """Remove SetPropertyNumber hook. Returns total calls logged."""
        status = self._send_cmd(CMD_UNHOOK_SETPROP)
        if status == STATUS_DONE:
            return self._read_u32(OFF_RESULT_I32)
        return -1

    def find_string(self, needle: str, start: int = 0, nth: int = 0) -> tuple[int, int]:
        """Find a string in ge.exe memory. Returns (address, total_matches) or (0, 0) on failure."""
        self._write_u32(OFF_PARAM1, start)
        self._write_u32(OFF_PARAM2, nth)
        self._write_str(OFF_STR_PARAM, needle)
        status = self._send_cmd(CMD_FIND_STRING, timeout=30.0)
        if status == STATUS_DONE:
            addr = self._read_u32(OFF_RESULT_I32)
            count = self._read_u32(OFF_PARAM2)
            return addr, count
        return 0, 0

    # ── Phase 3: VTable Spy & Hook ─────────────────────────────

    def vtable_spy(self, site: int = 1) -> dict | None:
        """Install one-shot vtable spy. Waits up to 30s for trigger.
        site=1: xref #1 (getter, 0x004FEA4B) — original behavior
        site=2: xref #2 (setter, 0x0050A942) — captures double value being SET
        Returns dict with obj_ptr, vtable_get, vtable_set, info, and set_value (site 2)."""
        self._write_u32(OFF_PARAM1, site)
        status = self._send_cmd(CMD_VTABLE_SPY, timeout=35.0)
        if status == STATUS_DONE:
            result = {
                "obj_ptr": self._read_u32(OFF_RESULT_I32),
                "vtable_get": self._read_u32(OFF_PARAM1),
                "vtable_set": self._read_u32(OFF_PARAM2),
                "info": self._read_str(OFF_STR_RESULT),
            }
            if site == 2:
                result["set_value"] = self._read_f64(OFF_RESULT_F64)
            return result
        return None

    def hook_vtable_get(self) -> bool:
        """Install persistent hook on KeepRange vtable GET call site."""
        status = self._send_cmd(CMD_HOOK_VTABLE_GET)
        return status == STATUS_DONE

    def unhook_vtable_get(self) -> int:
        """Remove vtable GET hook. Returns total intercepted calls."""
        status = self._send_cmd(CMD_UNHOOK_VTABLE_GET)
        if status == STATUS_DONE:
            return self._read_u32(OFF_RESULT_I32)
        return -1

    def set_vtget_override(self, active: bool, value: float = 0.0) -> bool:
        """Set/clear override value for vtable GET hook."""
        self._write_u32(OFF_PARAM1, 1 if active else 0)
        self._write_f64(OFF_RESULT_F64, value)
        status = self._send_cmd(CMD_SET_VTGET_OVERRIDE)
        return status == STATUS_DONE

    def vtget_status(self) -> dict | None:
        """Read vtable GET hook stats."""
        status = self._send_cmd(CMD_VTGET_STATUS)
        if status == STATUS_DONE:
            return {
                "count": self._read_u32(OFF_RESULT_I32),
                "last_value": self._read_f64(OFF_RESULT_F64),
                "last_obj": self._read_u32(OFF_PARAM1),
                "override_active": self._read_u32(OFF_PARAM2) != 0,
                "info": self._read_str(OFF_STR_RESULT),
            }
        return None

    # ── Phase 4: Chat / SysMsg ────────────────────────────────

    def chat(self, message: str, confirm: bool = False) -> bool:
        """Send a chat message via Chat_internal.
        ⚠ UNSAFE: causes server disconnect! Requires confirm=True."""
        if not confirm:
            return False
        self._write_u32(OFF_PARAM1, 0xCAFE)  # safety confirmation code
        self._write_str(OFF_STR_PARAM, message)
        status = self._send_cmd(CMD_CHAT)
        return status == STATUS_DONE

    def sysmsg(self, message: str) -> bool:
        """Display a local system message via SysMsg_internal."""
        self._write_str(OFF_STR_PARAM, message)
        status = self._send_cmd(CMD_SYSMSG)
        return status == STATUS_DONE

    def update_item_table(self) -> bool:
        """Call UpdateItemTable() to flush IES cache. Must set address first via set_func_addr(2, addr)."""
        status = self._send_cmd(CMD_UPDATE_ITEM_TABLE)
        return status == STATUS_DONE

    def dump_mem(self, address: int, count: int = 32) -> str | None:
        """Dump N bytes from address as hex string."""
        self._write_u32(OFF_PARAM1, address)
        self._write_u32(OFF_PARAM2, count)
        status = self._send_cmd(CMD_DUMP_MEM)
        if status == STATUS_DONE:
            return self._read_str(OFF_STR_RESULT)
        return None

    def scan_xref_str(self, name: str) -> dict | None:
        """Find string in .rdata and scan .text for xrefs.
        Returns dict with string_addr, first_xref, first_callback, info."""
        self._write_str(OFF_STR_PARAM, name)
        status = self._send_cmd(CMD_SCAN_XREF_STR, timeout=30.0)
        if status == STATUS_DONE:
            return {
                "string_addr": self._read_u32(OFF_RESULT_I32),
                "first_xref": self._read_u32(OFF_PARAM1),
                "first_callback": self._read_u32(OFF_PARAM2),
                "info": self._read_str(OFF_STR_RESULT),
            }
        return None

    def sysmsg_prop(self, prop_name: str, id_space: int = 0,
                    obj_name: str = "") -> bool:
        """Debug helper: read a property and display its value via SysMsg."""
        val = self.get_property(prop_name, id_space, obj_name)
        if val is not None:
            msg = f"{prop_name}={val:.2f}"
            return self.sysmsg(msg)
        return self.sysmsg(f"{prop_name}=ERROR")

    # ── Phase 5: Keyboard Input ───────────────────────────────

    # Common VK codes for convenience
    VK_MAP = {
        "space": 0x20, "enter": 0x0D, "return": 0x0D, "tab": 0x09,
        "esc": 0x1B, "escape": 0x1B, "backspace": 0x08,
        "shift": 0x10, "ctrl": 0x11, "alt": 0x12,
        "up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27,
        "f1": 0x70, "f2": 0x71, "f3": 0x72, "f4": 0x73,
        "f5": 0x74, "f6": 0x75, "f7": 0x76, "f8": 0x77,
        "f9": 0x78, "f10": 0x79, "f11": 0x7A, "f12": 0x7B,
        "insert": 0x2D, "delete": 0x2E, "home": 0x24, "end": 0x23,
        "pageup": 0x21, "pagedown": 0x22,
    }

    def send_key(self, key: str | int, flags: int = 0) -> bool:
        """Send a single keypress to the game window.
        key: VK code (int), single char ('q'), or name ('f1', 'space', 'enter')
        flags: 0=tap (down+up), 1=down only, 2=up only"""
        if isinstance(key, int):
            vk = key
        elif len(key) == 1:
            vk = ord(key.upper())
        else:
            vk = self.VK_MAP.get(key.lower(), 0)
            if vk == 0:
                return False

        self._write_u32(OFF_PARAM1, vk)
        self._write_u32(OFF_PARAM2, flags)
        status = self._send_cmd(CMD_SEND_KEY)
        return status == STATUS_DONE

    def send_keys(self, sequence: str, delay_ms: int = 80) -> int:
        """Send a sequence of key taps. Returns number of keys sent.
        sequence: string of characters to type (e.g. 'qwerty')
        delay_ms: milliseconds between each key (default 80)"""
        self._write_str(OFF_STR_PARAM, sequence)
        self._write_u32(OFF_PARAM1, delay_ms)
        status = self._send_cmd(CMD_SEND_KEYS, timeout=len(sequence) * (delay_ms + 50) / 1000 + 5)
        if status == STATUS_DONE:
            return self._read_u32(OFF_RESULT_I32)
        return 0

    def key_combo(self, key: str | int, ctrl: bool = False,
                  shift: bool = False, alt: bool = False) -> bool:
        """Send a key combo (modifiers + key) via keybd_event.
        Example: key_combo('q', ctrl=True) → Ctrl+Q"""
        if isinstance(key, int):
            vk = key
        elif len(key) == 1:
            vk = ord(key.upper())
        else:
            vk = self.VK_MAP.get(key.lower(), 0)
            if vk == 0:
                return False

        mods = (1 if ctrl else 0) | (2 if shift else 0) | (4 if alt else 0)
        self._write_u32(OFF_PARAM1, vk)
        self._write_u32(OFF_PARAM2, mods)
        status = self._send_cmd(CMD_KEY_COMBO)
        return status == STATUS_DONE

    # ── Bot Control ──────────────────────────────────────────

    def bot_status(self) -> dict | None:
        """Get current bot state. Returns dict with enabled, pick, attack, skills, items."""
        status = self._send_cmd(CMD_BOT_STATUS)
        if status == STATUS_DONE:
            return {
                "enabled": self._read_u32(OFF_RESULT_I32) != 0,
                "info": self._read_str(OFF_STR_RESULT),
            }
        return None

    def bot_toggle(self, feature: str, value: int = -1) -> bool:
        """Toggle a bot feature.
        feature: 'master', 'pick', 'attack'
        value: 0=off, 1=on, -1=toggle"""
        feature_map = {"master": 0, "pick": 1, "attack": 2}
        fid = feature_map.get(feature)
        if fid is None:
            return False
        self._write_u32(OFF_PARAM1, fid)
        self._write_u32(OFF_PARAM2, value & 0xFFFFFFFF)
        status = self._send_cmd(CMD_BOT_TOGGLE)
        return status == STATUS_DONE

    def bot_set_timer(self, timer_id: int, interval_ms: int) -> bool:
        """Set a bot timer interval.
        Timer IDs:
          0 = pick_interval, 1 = attack_interval
          0x10-0x15 = PC1 skills, 0x20-0x25 = PC2, 0x30-0x35 = PC3
          0x40-0x4B = items F1-F12
        interval_ms: 0 = disable"""
        self._write_u32(OFF_PARAM1, timer_id)
        self._write_u32(OFF_PARAM2, interval_ms)
        status = self._send_cmd(CMD_BOT_SET_TIMER)
        return status == STATUS_DONE

    def bot_set_skill(self, char_idx: int, skill_idx: int, interval_ms: int) -> bool:
        """Set skill timer. char_idx: 0=PC1, 1=PC2, 2=PC3. skill_idx: 0-5."""
        timer_id = ((char_idx + 1) << 4) | skill_idx
        return self.bot_set_timer(timer_id, interval_ms)

    def bot_set_item(self, slot: int, interval_ms: int) -> bool:
        """Set item timer. slot: 0-11 (F1-F12)."""
        return self.bot_set_timer(0x40 + slot, interval_ms)

    # ── Phase 6: Keyboard Input Discovery ─────────────────────

    def hook_wndproc(self) -> bool:
        """Install WndProc subclass to log all keyboard messages.
        Deferred to main game thread — may take a moment."""
        status = self._send_cmd(CMD_HOOK_WNDPROC, timeout=10.0)
        return status == STATUS_DONE

    def unhook_wndproc(self) -> bool:
        """Remove WndProc subclass, restore original.
        Deferred to main game thread."""
        status = self._send_cmd(CMD_UNHOOK_WNDPROC, timeout=10.0)
        return status == STATUS_DONE

    def check_raw_input(self) -> tuple[int, str]:
        """Check if ge.exe imports Raw Input API functions.
        Returns (count_found, details_string)."""
        status = self._send_cmd(CMD_CHECK_RAW_INPUT, timeout=10.0)
        if status == STATUS_DONE:
            count = self._read_u32(OFF_RESULT_I32)
            details = self._read_str(OFF_STR_RESULT)
            return count, details
        return -1, "error"

    def kb_diag(self) -> tuple[int, str]:
        """Full keyboard input diagnostic.
        Checks dinput8.dll, installs API hooks, reports call counts.
        Returns (dinput8_loaded, details_string)."""
        status = self._send_cmd(CMD_KB_DIAG, timeout=10.0)
        if status == STATUS_DONE:
            di8 = self._read_u32(OFF_RESULT_I32)
            info = self._read_str(OFF_STR_RESULT)
            return di8, info
        return -1, "error"

    def wndproc_status(self) -> tuple[int, str]:
        """Read WndProc hook message counters.
        Returns (total_count, status_string)."""
        status = self._send_cmd(CMD_WNDPROC_STATUS)
        if status == STATUS_DONE:
            total = self._read_u32(OFF_RESULT_I32)
            info = self._read_str(OFF_STR_RESULT)
            return total, info
        return -1, "error"


# ── CLI Commands ──────────────────────────────────────────────

def cmd_ping(args):
    with PhantomCmd() as cmd:
        if cmd.ping():
            print("[+] DLL responded: 0xDEADBEEF — alive!")
            return 0
        else:
            print("[!] DLL did not respond")
            return 1


def cmd_scan(args):
    print("[*] Triggering xref scan...")
    with PhantomCmd() as cmd:
        if cmd.scan():
            print("[+] Scan complete — check phantom_hook.log for results")
            return 0
        else:
            print("[!] Scan failed or timed out")
            return 1


def cmd_get(args):
    prop = args.property
    id_space = args.id_space
    obj = args.obj or ""

    with PhantomCmd() as cmd:
        print(f"[*] GetPropertyNumber(idSpace={id_space}, obj=\"{obj}\", prop=\"{prop}\")")
        val = cmd.get_property(prop, id_space, obj)
        if val is not None:
            print(f"[+] {prop} = {val}")
            return 0
        else:
            print(f"[!] Failed to get {prop}")
            return 1


def cmd_set(args):
    prop = args.property
    value = args.value
    id_space = args.id_space
    obj = args.obj or ""

    with PhantomCmd() as cmd:
        print(f"[*] SetPropertyNumber(idSpace={id_space}, obj=\"{obj}\", prop=\"{prop}\", val={value})")
        if cmd.set_property(prop, value, id_space, obj):
            print(f"[+] {prop} set to {value}")
            return 0
        else:
            print(f"[!] Failed to set {prop}")
            return 1


def cmd_read(args):
    addr = int(args.address, 16) if args.address.startswith("0x") else int(args.address)
    with PhantomCmd() as cmd:
        val = cmd.read_addr(addr)
        if val is not None:
            print(f"[+] [0x{addr:08X}] = 0x{val:08X} ({val})")
            return 0
        else:
            print(f"[!] Failed to read 0x{addr:08X}")
            return 1


def cmd_setaddr(args):
    which = {"get": 0, "set": 1, "update": 2}[args.which]
    names = {0: "GetPropertyNumber", 1: "SetPropertyNumber", 2: "UpdateItemTable"}
    name = names[which]
    addr_str = args.address
    addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)

    with PhantomCmd() as cmd:
        print(f"[*] Setting {name} = 0x{addr:08X}")
        if cmd.set_func_addr(which, addr):
            print(f"[+] {name} address set successfully")
            return 0
        else:
            print(f"[!] Failed to set {name} address")
            return 1


def cmd_probe(args):
    """Probe all known range properties."""
    id_space = args.id_space
    obj = args.obj or ""

    with PhantomCmd() as cmd:
        if not cmd.ping():
            print("[!] DLL not responding")
            return 1

        print(f"[*] Probing range properties (idSpace={id_space}, obj=\"{obj}\"):\n")

        for prop in KNOWN_PROPS:
            val = cmd.get_property(prop, id_space, obj)
            if val is not None:
                print(f"  {prop:20s} = {val}")
            else:
                print(f"  {prop:20s} = (error)")

        return 0


def cmd_interactive(args):
    """Interactive command loop."""
    pid = getattr(args, "pid", None)
    try:
        cmd = PhantomCmd(pid=pid)
    except RuntimeError as e:
        print(f"[!] {e}")
        return 1

    if not cmd.ping():
        print("[!] DLL not responding to ping")
        cmd.close()
        return 1

    pid_str = f" (PID {cmd.pid})" if cmd.pid else ""
    print(f"[+] Connected to phantom_hook DLL{pid_str} via {cmd.shmem_name}")
    print()
    print("Commands:")
    print("  ping                 — Ping DLL")
    print("  scan                 — Trigger xref scan (results in log)")
    print("  get <prop> [id] [obj] — Get property value")
    print("  set <prop> <val> [id] [obj] — Set property value")
    print("  read <hex_addr>      — Read 4 bytes from address")
    print("  setaddr get|set|update <hex> — Set function address")
    print("  find <string> [start_hex] — Find string in memory")
    print("  probe [id] [obj]     — Probe all known range properties")
    print("  hook                 — Hook GetPropertyNumber (log all game calls)")
    print("  unhook               — Remove GetPropertyNumber hook")
    print("  hookset              — Hook SetPropertyNumber (log all game calls)")
    print("  unhookset            — Remove SetPropertyNumber hook")
    print("  --- Phase 4: Chat/SysMsg ---")
    print("  chat <message>           — Send chat (⚠ UNSAFE: disconnects!)")
    print("  chat! <message>          — Send chat with confirmation")
    print("  sysmsg <message>         — Display local system message")
    print("  --- Phase 5: Investigation ---")
    print("  dump <hex_addr> [count]  — Dump N bytes as hex (for disassembly)")
    print("  findxref <string>        — Find string + scan xrefs in .text")
    print("  updateitem               — Call UpdateItemTable() (set addr first!)")
    print("  debugprop <prop> [id]    — Get property + show via SysMsg in-game")
    print("  --- Phase 5: Keyboard Input ---")
    print("  key <key>                — Tap a key (q, w, e, r, f1, space, etc.)")
    print("  keydown <key>            — Hold key down")
    print("  keyup <key>              — Release key")
    print("  keys <sequence> [delay]  — Type a sequence (e.g., keys qwerty 100)")
    print("  combo <key> [ctrl] [shift] [alt] — Key combo (e.g., combo space ctrl)")
    print("  --- Bot Control ---")
    print("  bot                      — Show bot status")
    print("  bot on/off               — Master bot toggle")
    print("  bot pick on/off          — Auto pick toggle")
    print("  bot attack on/off        — Auto attack toggle")
    print("  bot skill <c> <s> <ms>   — Set skill timer (char 0-2, skill 0-5, ms)")
    print("  bot item <slot> <ms>     — Set item timer (slot 0-11, ms)")
    print("  discover                 — Scan for all injected game instances")
    print("  --- Phase 6: KB Input Discovery ---")
    print("  hookwnd                  — Hook WndProc to log ALL keyboard messages")
    print("  unhookwnd                — Remove WndProc hook")
    print("  wndstatus                — Show keyboard message counters")
    print("  rawinput                 — Check if game imports Raw Input API")
    print("  --- Phase 3: VTable ---")
    print("  spy                  — One-shot vtable spy at xref #1 (getter)")
    print("  spy2                 — One-shot vtable spy at xref #2 (SETTER site)")
    print("  hookvt               — Hook vtable GET at KeepRange call site")
    print("  unhookvt             — Remove vtable GET hook")
    print("  override <value>     — Set override value for KeepRange GET")
    print("  nooverride           — Clear KeepRange GET override")
    print("  vtstatus             — Read vtable GET hook stats")
    print("  --- Maintenance ---")
    print("  clean                — Eject ALL phantom_hook DLLs (run as admin)")
    print("  quit                 — Exit")
    print()

    while True:
        try:
            line = input("phantom> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line:
            continue

        parts = line.split()
        verb = parts[0].lower()

        try:
            if verb == "quit" or verb == "exit" or verb == "q":
                break

            elif verb == "ping":
                if cmd.ping():
                    print("[+] alive!")
                else:
                    print("[!] no response")

            elif verb == "scan":
                print("[*] Scanning...")
                if cmd.scan():
                    print("[+] Done — check phantom_hook.log")
                else:
                    print("[!] Failed")

            elif verb == "get":
                if len(parts) < 2:
                    print("Usage: get <prop> [id_space] [obj_name]")
                    continue
                prop = parts[1]
                id_s = int(parts[2]) if len(parts) > 2 else 0
                obj = parts[3] if len(parts) > 3 else ""
                val = cmd.get_property(prop, id_s, obj)
                if val is not None:
                    print(f"  {prop} = {val}")
                else:
                    print(f"  (error)")

            elif verb == "set":
                if len(parts) < 3:
                    print("Usage: set <prop> <value> [id_space] [obj_name]")
                    continue
                prop = parts[1]
                val = float(parts[2])
                id_s = int(parts[3]) if len(parts) > 3 else 0
                obj = parts[4] if len(parts) > 4 else ""
                if cmd.set_property(prop, val, id_s, obj):
                    print(f"  OK")
                else:
                    print(f"  (error)")

            elif verb == "read":
                if len(parts) < 2:
                    print("Usage: read <hex_address>")
                    continue
                addr_str = parts[1]
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                val = cmd.read_addr(addr)
                if val is not None:
                    # Also show as ASCII if printable
                    ascii_chars = ""
                    for shift in range(4):
                        b = (val >> (shift * 8)) & 0xFF
                        ascii_chars += chr(b) if 32 <= b < 127 else "."
                    print(f"  [0x{addr:08X}] = 0x{val:08X}  {ascii_chars}")
                else:
                    print(f"  (error reading 0x{addr:08X})")

            elif verb == "find":
                if len(parts) < 2:
                    print("Usage: find <string> [start_hex]")
                    continue
                needle = parts[1]
                start = int(parts[2], 16) if len(parts) > 2 and parts[2].startswith("0x") else 0
                addr, count = cmd.find_string(needle, start)
                if addr:
                    print(f"  \"{needle}\" found at 0x{addr:08X} ({count} total matches)")
                else:
                    print(f"  \"{needle}\" not found")

            elif verb == "setaddr":
                if len(parts) < 3:
                    print("Usage: setaddr get|set|update <hex_address>")
                    continue
                which_str = parts[1].lower()
                addr_str = parts[2]
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                if which_str == "get":
                    which = 0
                elif which_str == "set":
                    which = 1
                elif which_str == "update":
                    which = 2
                else:
                    print("Usage: setaddr get|set|update <hex_address>")
                    continue
                names = {0: "GetPropertyNumber", 1: "SetPropertyNumber", 2: "UpdateItemTable"}
                name = names[which]
                if cmd.set_func_addr(which, addr):
                    print(f"  {name} = 0x{addr:08X}")
                else:
                    print(f"  (error setting {name})")

            elif verb == "hook":
                if cmd.hook_getprop():
                    print("[+] GetPropertyNumber hook INSTALLED — check phantom_hook.log")
                    print("    Play the game normally, then 'unhook' to stop logging")
                else:
                    print("[!] Failed to install hook")

            elif verb == "unhook":
                count = cmd.unhook_getprop()
                if count >= 0:
                    print(f"[+] GetProp hook removed — logged {count} calls total")
                else:
                    print("[!] Failed to remove hook")

            elif verb == "hookset":
                if cmd.hook_setprop():
                    print("[+] SetPropertyNumber hook INSTALLED — check phantom_hook.log")
                else:
                    print("[!] Failed to install SetProp hook")

            elif verb == "unhookset":
                count = cmd.unhook_setprop()
                if count >= 0:
                    print(f"[+] SetProp hook removed — logged {count} calls total")
                else:
                    print("[!] Failed to remove hook")

            elif verb == "probe":
                id_s = int(parts[1]) if len(parts) > 1 else 0
                obj = parts[2] if len(parts) > 2 else ""
                print(f"  Probing (idSpace={id_s}, obj=\"{obj}\"):")
                for prop in KNOWN_PROPS:
                    val = cmd.get_property(prop, id_s, obj)
                    if val is not None:
                        print(f"    {prop:20s} = {val}")
                    else:
                        print(f"    {prop:20s} = (error)")

            # ── Phase 4: Chat/SysMsg commands ────────────────

            elif verb == "chat":
                if len(parts) < 2:
                    print("Usage: chat <message>  (⚠ blocked by default)")
                    print("       chat! <message> (sends with confirmation)")
                    continue
                message = " ".join(parts[1:])
                print(f"[!] Chat is DISABLED (causes server disconnect)")
                print(f"    Use 'chat! {message}' to force-send with confirmation")

            elif verb == "chat!":
                if len(parts) < 2:
                    print("Usage: chat! <message>")
                    continue
                message = " ".join(parts[1:])
                print(f"[*] Chat (CONFIRMED): \"{message}\"")
                print(f"    ⚠ This WILL send to server and may cause disconnect!")
                if cmd.chat(message, confirm=True):
                    print("[+] Chat sent")
                else:
                    print("[!] Chat failed")

            elif verb == "sysmsg":
                if len(parts) < 2:
                    print("Usage: sysmsg <message>")
                    continue
                message = " ".join(parts[1:])
                print(f"[*] SysMsg: \"{message}\"")
                if cmd.sysmsg(message):
                    print("[+] SysMsg displayed")
                else:
                    print("[!] SysMsg failed")

            # ── Phase 5: Investigation commands ───────────────

            elif verb == "dump":
                if len(parts) < 2:
                    print("Usage: dump <hex_addr> [count]")
                    continue
                addr_str = parts[1]
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                count = int(parts[2]) if len(parts) > 2 else 32
                hex_str = cmd.dump_mem(addr, count)
                if hex_str:
                    print(f"  [0x{addr:08X}] {hex_str}")
                    # Also attempt basic x86 disassembly hint for common prologue
                    clean = hex_str.replace(" ", "")
                    if clean.startswith("558BEC"):
                        print(f"    ^ push ebp; mov ebp, esp (standard function prologue)")
                else:
                    print(f"  (error reading 0x{addr:08X})")

            elif verb == "findxref":
                if len(parts) < 2:
                    print("Usage: findxref <string>  (e.g., findxref UpdateItemTable)")
                    continue
                name = parts[1]
                print(f"[*] Scanning for \"{name}\" in .rdata + xrefs in .text...")
                result = cmd.scan_xref_str(name)
                if result:
                    print(f"[+] {result['info']}")
                    print(f"    String addr:    0x{result['string_addr']:08X}")
                    if result['first_xref']:
                        print(f"    First xref:     0x{result['first_xref']:08X}")
                    if result['first_callback']:
                        print(f"    First callback: 0x{result['first_callback']:08X}")
                        print(f"    → Use 'setaddr update 0x{result['first_callback']:08X}' to set as UpdateItemTable")
                else:
                    print(f"[!] \"{name}\" not found or no xrefs")

            elif verb == "updateitem":
                print("[*] Calling UpdateItemTable()...")
                if cmd.update_item_table():
                    print("[+] UpdateItemTable OK — IES cache flushed")
                else:
                    print("[!] Failed (is the address set? Use 'findxref UpdateItemTable' first)")

            elif verb == "debugprop":
                if len(parts) < 2:
                    print("Usage: debugprop <prop> [id_space] [obj]")
                    continue
                prop = parts[1]
                id_s = int(parts[2]) if len(parts) > 2 else 0
                obj = parts[3] if len(parts) > 3 else ""
                val = cmd.get_property(prop, id_s, obj)
                if val is not None:
                    print(f"  {prop} = {val}")
                    msg = f"{prop}={val:.2f}"
                    if cmd.sysmsg(msg):
                        print(f"  → displayed in-game: \"{msg}\"")
                    else:
                        print(f"  → SysMsg failed")
                else:
                    print(f"  (error reading {prop})")

            # ── Phase 5: Keyboard Input commands ──────────────

            elif verb == "key":
                if len(parts) < 2:
                    print("Usage: key <key>  (q, w, e, r, f1, space, enter, etc.)")
                    print("       key 0x51   (raw VK code in hex)")
                    continue
                key_str = parts[1]
                if key_str.startswith("0x"):
                    key_arg = int(key_str, 16)
                else:
                    key_arg = key_str
                if cmd.send_key(key_arg):
                    print(f"  [+] key '{key_str}' tapped")
                elif cmd.last_status_was_stale:
                    print(f"  [!] STALE DLL CONFLICT — another phantom_hook DLL ate the command")
                    print(f"      Run 'clean' to eject all, then re-inject v8 only")
                else:
                    print(f"  [!] failed (unknown key or window not found)")

            elif verb == "keydown":
                if len(parts) < 2:
                    print("Usage: keydown <key>")
                    continue
                key_str = parts[1]
                if key_str.startswith("0x"):
                    key_arg = int(key_str, 16)
                else:
                    key_arg = key_str
                if cmd.send_key(key_arg, flags=1):
                    print(f"  [+] key '{key_str}' DOWN")
                else:
                    print(f"  [!] failed")

            elif verb == "keyup":
                if len(parts) < 2:
                    print("Usage: keyup <key>")
                    continue
                key_str = parts[1]
                if key_str.startswith("0x"):
                    key_arg = int(key_str, 16)
                else:
                    key_arg = key_str
                if cmd.send_key(key_arg, flags=2):
                    print(f"  [+] key '{key_str}' UP")
                else:
                    print(f"  [!] failed")

            elif verb == "postkey":
                # PostMessageW with correct lParam (scan code + repeat)
                if len(parts) < 2:
                    print("Usage: postkey <key>  — PostMessage with correct lParam")
                    continue
                key_str = parts[1]
                if key_str.startswith("0x"):
                    key_arg = int(key_str, 16)
                else:
                    key_arg = key_str
                print(f"[*] PostMessageW with scan code: '{key_str}'")
                if cmd.send_key(key_arg, flags=6):
                    print(f"  [+] postkey '{key_str}' sent (no focus needed)")
                else:
                    print(f"  [!] failed")

            elif verb == "sendkey":
                # SendMessageW with correct lParam (sync)
                if len(parts) < 2:
                    print("Usage: sendkey <key>  — SendMessage with correct lParam")
                    continue
                key_str = parts[1]
                if key_str.startswith("0x"):
                    key_arg = int(key_str, 16)
                else:
                    key_arg = key_str
                print(f"[*] SendMessageW with scan code: '{key_str}'")
                if cmd.send_key(key_arg, flags=7):
                    print(f"  [+] sendkey '{key_str}' sent (sync, no focus)")
                else:
                    print(f"  [!] failed")

            elif verb == "keys":
                if len(parts) < 2:
                    print("Usage: keys <sequence> [delay_ms]")
                    print("  e.g.: keys qwerty 100")
                    continue
                sequence = parts[1]
                delay = int(parts[2]) if len(parts) > 2 else 80
                print(f"[*] Sending keys: \"{sequence}\" (delay={delay}ms)")
                sent = cmd.send_keys(sequence, delay)
                if sent > 0:
                    print(f"  [+] sent {sent} keys")
                else:
                    print(f"  [!] failed")

            elif verb == "combo":
                if len(parts) < 2:
                    print("Usage: combo <key> [ctrl] [shift] [alt]")
                    print("  e.g.: combo space ctrl   → Ctrl+Space")
                    print("  e.g.: combo q ctrl shift → Ctrl+Shift+Q")
                    continue
                key_arg = parts[1]
                mods = [m.lower() for m in parts[2:]]
                if cmd.key_combo(key_arg, ctrl="ctrl" in mods, shift="shift" in mods, alt="alt" in mods):
                    print(f"  [+] combo sent")
                else:
                    print(f"  [!] failed")

            # ── Bot Control ───────────────────────────────────

            elif verb == "bot":
                if len(parts) == 1:
                    # bot status
                    result = cmd.bot_status()
                    if result:
                        print(f"  Bot: {'ON' if result['enabled'] else 'OFF'}")
                        print(f"  {result['info']}")
                    else:
                        print("  [!] failed")
                elif parts[1].lower() in ("on", "off"):
                    val = 1 if parts[1].lower() == "on" else 0
                    if cmd.bot_toggle("master", val):
                        print(f"  [+] Bot master: {'ON' if val else 'OFF'}")
                    else:
                        print("  [!] failed")
                elif parts[1].lower() == "pick":
                    if len(parts) < 3:
                        cmd.bot_toggle("pick", -1)  # toggle
                    else:
                        val = 1 if parts[2].lower() == "on" else 0
                        cmd.bot_toggle("pick", val)
                    print("  [+] pick toggled")
                elif parts[1].lower() == "attack":
                    if len(parts) < 3:
                        cmd.bot_toggle("attack", -1)
                    else:
                        val = 1 if parts[2].lower() == "on" else 0
                        cmd.bot_toggle("attack", val)
                    print("  [+] attack toggled")
                elif parts[1].lower() == "skill":
                    if len(parts) < 5:
                        print("Usage: bot skill <char 0-2> <skill 0-5> <interval_ms>")
                        continue
                    c, s, ms = int(parts[2]), int(parts[3]), int(parts[4])
                    if cmd.bot_set_skill(c, s, ms):
                        print(f"  [+] PC{c+1} skill{s+1}: {ms}ms")
                    else:
                        print("  [!] failed")
                elif parts[1].lower() == "item":
                    if len(parts) < 4:
                        print("Usage: bot item <slot 0-11> <interval_ms>")
                        continue
                    slot, ms = int(parts[2]), int(parts[3])
                    if cmd.bot_set_item(slot, ms):
                        print(f"  [+] item F{slot+1}: {ms}ms")
                    else:
                        print("  [!] failed")
                else:
                    print("Usage: bot [on|off|pick|attack|skill|item]")

            elif verb == "discover":
                instances = PhantomCmd.discover()
                if instances:
                    print(f"[+] Found {len(instances)} injected instance(s):")
                    for inst in instances:
                        pid_str = str(inst["pid"]) if inst["pid"] else "legacy"
                        print(f"  PID {pid_str} — {inst['shmem_name']}")
                else:
                    print("[!] No injected instances found")

            # ── Phase 6: Keyboard Input Discovery ─────────────

            elif verb == "hookwnd":
                print("[*] Installing WndProc hook (deferred to main thread)...")
                print("    This intercepts ALL keyboard messages to the game window.")
                if cmd.hook_wndproc():
                    print("[+] WndProc hook INSTALLED — press keys in-game, then 'wndstatus'")
                else:
                    print("[!] Failed to install WndProc hook (check log)")

            elif verb == "unhookwnd":
                print("[*] Removing WndProc hook...")
                if cmd.unhook_wndproc():
                    print("[+] WndProc hook removed — original WndProc restored")
                else:
                    print("[!] Failed to remove WndProc hook")

            elif verb == "rawinput":
                print("[*] Checking ge.exe IAT for Raw Input API imports...")
                count, details = cmd.check_raw_input()
                if count > 0:
                    print(f"[+] Found {count} Raw Input import(s)! ({details})")
                    print("    Game likely uses WM_INPUT for keyboard — check log for details")
                elif count == 0:
                    print(f"[-] No Raw Input imports in IAT ({details})")
                    print("    Game does NOT use RegisterRawInputDevices/GetRawInputData")
                    print("    Check phantom_hook.log for full user32 import list")
                else:
                    print(f"[!] Check failed: {details}")

            elif verb == "kbdiag":
                print("[*] Running full keyboard input diagnostic...")
                di8, info = cmd.kb_diag()
                print(f"[+] {info}")
                if di8 == 1:
                    print("    !! dinput8.dll is LOADED — game likely uses DirectInput for keyboard!")
                    print("    Background keys need DI device hook, not message-based approach")
                elif di8 == 0:
                    print("    dinput8.dll NOT loaded — game uses Win32 API for keyboard")
                print("    GKS = GetKeyState calls (faked/total)")
                print("    GAKS = GetAsyncKeyState calls (faked/total)")
                print("    Run 'postkey q', then 'kbdiag' again to see if counts change")
                print("    Check phantom_hook log for full details")

            elif verb == "wndstatus":
                total, info = cmd.wndproc_status()
                if total >= 0:
                    print(f"[+] WndProc status: {info}")
                    print(f"    Total keyboard messages: {total}")
                    print("    Legend: KD=KEYDOWN KU=KEYUP CH=CHAR SKD=SYSKEYDOWN")
                    print("            SKU=SYSKEYUP IN=WM_INPUT HK=HOTKEY OT=other")
                    print("    Check phantom_hook.log for per-message details")
                else:
                    print(f"[!] Status read failed: {info}")

            # ── Phase 3: VTable commands ──────────────────────

            elif verb == "spy":
                print("[*] Installing vtable spy at xref #1 (getter)...")
                print("    Waiting up to 30s for KeepRange read.")
                print("    Play the game, move characters, or open skill info to trigger it.")
                result = cmd.vtable_spy(site=1)
                if result:
                    print(f"[+] VTable spy captured!")
                    print(f"    Object ptr:  0x{result['obj_ptr']:08X}")
                    print(f"    VTable GET:  0x{result['vtable_get']:08X}")
                    print(f"    VTable SET:  0x{result['vtable_set']:08X}")
                    print(f"    Info: {result['info']}")
                else:
                    print("[!] Spy timed out — game didn't read KeepRange")

            elif verb == "spy2":
                print("[*] Installing vtable spy at xref #2 (SETTER site, 0x0050A942)...")
                print("    Waiting up to 30s for KeepRange WRITE.")
                print("    Try: change stance, equip weapon, enter combat, use skill.")
                result = cmd.vtable_spy(site=2)
                if result:
                    print(f"[+] VTable spy2 captured!")
                    print(f"    Object ptr:  0x{result['obj_ptr']:08X}")
                    print(f"    VTable GET:  0x{result['vtable_get']:08X}")
                    print(f"    VTable SET:  0x{result['vtable_set']:08X}")
                    print(f"    Set value:   {result.get('set_value', 'N/A')}")
                    print(f"    Info: {result['info']}")
                else:
                    print("[!] Spy2 timed out — game didn't write KeepRange via xref #2")

            elif verb == "hookvt":
                if cmd.hook_vtable_get():
                    print("[+] VTable GET hook INSTALLED at KeepRange call site")
                    print("    Every KeepRange read is now intercepted.")
                    print("    Use 'vtstatus' to check, 'override <val>' to modify.")
                else:
                    print("[!] Failed to install vtable GET hook")

            elif verb == "unhookvt":
                count = cmd.unhook_vtable_get()
                if count >= 0:
                    print(f"[+] VTable GET hook removed — intercepted {count} calls")
                else:
                    print("[!] Failed to remove hook")

            elif verb == "override":
                if len(parts) < 2:
                    print("Usage: override <value>  (e.g., override 50.0)")
                    continue
                val = float(parts[1])
                if cmd.set_vtget_override(True, val):
                    print(f"[+] Override ACTIVE — KeepRange will return {val}")
                else:
                    print("[!] Failed to set override")

            elif verb == "nooverride":
                if cmd.set_vtget_override(False):
                    print("[+] Override CLEARED — KeepRange returns real value")
                else:
                    print("[!] Failed to clear override")

            elif verb == "vtstatus":
                result = cmd.vtget_status()
                if result:
                    print(f"  Calls intercepted: {result['count']}")
                    print(f"  Last object:       0x{result['last_obj']:08X}")
                    print(f"  Last value:        {result['last_value']}")
                    print(f"  Override:          {'ON' if result['override_active'] else 'OFF'}")
                else:
                    print("[!] Failed to read status (hook not installed?)")

            # ── Maintenance commands ─────────────────────────

            elif verb == "clean":
                print("[*] Ejecting ALL phantom_hook DLLs from ge.exe...")
                print("    (requires admin — run dll_injector.py clean if this fails)")
                try:
                    import subprocess
                    result = subprocess.run(
                        [sys.executable, "tools/dll_injector.py", "clean"],
                        capture_output=True, text=True, timeout=30
                    )
                    print(result.stdout)
                    if result.stderr:
                        print(result.stderr)
                except Exception as e:
                    print(f"[!] {e}")
                    print("    Run manually: python tools/dll_injector.py clean")

            else:
                print(f"Unknown command: {verb}")

        except Exception as e:
            print(f"[!] Error: {e}")

    cmd.close()
    print("[*] Goodbye")
    return 0


# ── Main ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="GE_Phantom Range Control — Phase 2 command interface"
    )
    parser.add_argument("--pid", type=int, default=None,
                        help="Target ge.exe PID (auto-discovers if not specified)")
    sub = parser.add_subparsers(dest="command")

    # ping
    sub.add_parser("ping", help="Ping the DLL")

    # scan
    sub.add_parser("scan", help="Trigger xref scan")

    # get
    p_get = sub.add_parser("get", help="Get property value")
    p_get.add_argument("property", help="Property name (e.g. SplRange)")
    p_get.add_argument("--id-space", type=int, default=0, help="ID space (default: 0)")
    p_get.add_argument("--obj", default="", help="Object name")
    p_get.set_defaults(func=cmd_get)

    # set
    p_set = sub.add_parser("set", help="Set property value")
    p_set.add_argument("property", help="Property name")
    p_set.add_argument("value", type=float, help="Value to set")
    p_set.add_argument("--id-space", type=int, default=0, help="ID space (default: 0)")
    p_set.add_argument("--obj", default="", help="Object name")
    p_set.set_defaults(func=cmd_set)

    # read
    p_read = sub.add_parser("read", help="Read memory address")
    p_read.add_argument("address", help="Address (hex with 0x prefix)")
    p_read.set_defaults(func=cmd_read)

    # setaddr
    p_setaddr = sub.add_parser("setaddr", help="Set function address in DLL")
    p_setaddr.add_argument("which", choices=["get", "set", "update"],
                           help="Which function: get=GetPropNum, set=SetPropNum, update=UpdateItemTable")
    p_setaddr.add_argument("address", help="Function address (hex with 0x prefix)")
    p_setaddr.set_defaults(func=cmd_setaddr)

    # probe
    p_probe = sub.add_parser("probe", help="Probe all known range properties")
    p_probe.add_argument("--id-space", type=int, default=0, help="ID space")
    p_probe.add_argument("--obj", default="", help="Object name")
    p_probe.set_defaults(func=cmd_probe)

    # interactive (default)
    sub.add_parser("interactive", help="Interactive command loop")

    args = parser.parse_args()

    if not args.command or args.command == "interactive":
        return cmd_interactive(args)

    if args.command == "ping":
        return cmd_ping(args)
    if args.command == "scan":
        return cmd_scan(args)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
