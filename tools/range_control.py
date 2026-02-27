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

SHMEM_NAME = "Local\\ge_phantom_cmd"
SHMEM_SIZE = 256

# Offsets
OFF_COMMAND     = 0x00
OFF_STATUS      = 0x01
OFF_PARAM1      = 0x04
OFF_PARAM2      = 0x08
OFF_RESULT_I32  = 0x0C
OFF_RESULT_F32  = 0x10
OFF_RESULT_F64  = 0x14
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
CMD_CHAT            = 0x40
CMD_SYSMSG          = 0x41
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


def open_shmem() -> tuple | None:
    """Open the shared memory created by phantom_hook DLL."""
    # Use Win32 OpenFileMappingA to get handle
    handle = kernel32.OpenFileMappingA(
        FILE_MAP_ALL_ACCESS,
        False,
        SHMEM_NAME.encode("ascii"),
    )
    if not handle:
        return None

    # Map the view
    ptr = kernel32.MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, SHMEM_SIZE)
    if not ptr:
        kernel32.CloseHandle(handle)
        return None

    # Wrap in a ctypes buffer we can read/write
    buf = (ctypes.c_char * SHMEM_SIZE).from_address(ptr)
    return handle, ptr, buf


class PhantomCmd:
    """Interface to phantom_hook DLL command shared memory."""

    def __init__(self):
        result = open_shmem()
        if result is None:
            raise RuntimeError(
                "Cannot open shared memory. Is phantom_hook.dll injected?\n"
                f"  Shared memory name: {SHMEM_NAME}"
            )
        self._handle, self._ptr, self._buf = result

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
        """Send a command and wait for completion. Returns status code."""
        # Clear status
        self._write_byte(OFF_STATUS, STATUS_IDLE)
        # Write command
        self._write_byte(OFF_COMMAND, cmd)

        # Poll for completion
        start = time.monotonic()
        while True:
            status = self._read_byte(OFF_STATUS)
            if status == STATUS_DONE or status == STATUS_ERROR:
                return status
            if time.monotonic() - start > timeout:
                return -1  # timeout
            time.sleep(0.05)

    def ping(self) -> bool:
        """Ping the DLL. Returns True if it responds."""
        status = self._send_cmd(CMD_PING)
        if status == STATUS_DONE:
            val = self._read_u32(OFF_RESULT_I32)
            return val == 0xDEADBEEF
        return False

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

    def chat(self, message: str) -> bool:
        """Send a chat message via Chat_internal (sends to server + local display)."""
        self._write_str(OFF_STR_PARAM, message)
        status = self._send_cmd(CMD_CHAT)
        return status == STATUS_DONE

    def sysmsg(self, message: str) -> bool:
        """Display a local system message via SysMsg_internal."""
        self._write_str(OFF_STR_PARAM, message)
        status = self._send_cmd(CMD_SYSMSG)
        return status == STATUS_DONE


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
    which = 0 if args.which == "get" else 1
    name = "GetPropertyNumber" if which == 0 else "SetPropertyNumber"
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
    try:
        cmd = PhantomCmd()
    except RuntimeError as e:
        print(f"[!] {e}")
        return 1

    if not cmd.ping():
        print("[!] DLL not responding to ping")
        cmd.close()
        return 1

    print("[+] Connected to phantom_hook DLL")
    print()
    print("Commands:")
    print("  ping                 — Ping DLL")
    print("  scan                 — Trigger xref scan (results in log)")
    print("  get <prop> [id] [obj] — Get property value")
    print("  set <prop> <val> [id] [obj] — Set property value")
    print("  read <hex_addr>      — Read 4 bytes from address")
    print("  setaddr get <hex>    — Set GetPropertyNumber address")
    print("  setaddr set <hex>    — Set SetPropertyNumber address")
    print("  find <string> [start_hex] — Find string in memory")
    print("  probe [id] [obj]     — Probe all known range properties")
    print("  hook                 — Hook GetPropertyNumber (log all game calls)")
    print("  unhook               — Remove GetPropertyNumber hook")
    print("  hookset              — Hook SetPropertyNumber (log all game calls)")
    print("  unhookset            — Remove SetPropertyNumber hook")
    print("  --- Phase 4: Chat/SysMsg ---")
    print("  chat <message>           — Send chat message (server + local)")
    print("  sysmsg <message>         — Display local system message")
    print("  --- Phase 3: VTable ---")
    print("  spy                  — One-shot vtable spy at xref #1 (getter)")
    print("  spy2                 — One-shot vtable spy at xref #2 (SETTER site)")
    print("  hookvt               — Hook vtable GET at KeepRange call site")
    print("  unhookvt             — Remove vtable GET hook")
    print("  override <value>     — Set override value for KeepRange GET")
    print("  nooverride           — Clear KeepRange GET override")
    print("  vtstatus             — Read vtable GET hook stats")
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
                    print("Usage: setaddr get|set <hex_address>")
                    continue
                which_str = parts[1].lower()
                addr_str = parts[2]
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                if which_str == "get":
                    which = 0
                elif which_str == "set":
                    which = 1
                else:
                    print("Usage: setaddr get|set <hex_address>")
                    continue
                name = "GetPropertyNumber" if which == 0 else "SetPropertyNumber"
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
                    print("Usage: chat <message>")
                    continue
                message = " ".join(parts[1:])
                print(f"[*] Chat: \"{message}\"")
                if cmd.chat(message):
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
    p_setaddr.add_argument("which", choices=["get", "set"],
                           help="Which function: get=GetPropertyNumber, set=SetPropertyNumber")
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
