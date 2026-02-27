"""
GE_Phantom — Process Memory Primitives

Windows process memory access for ge.exe: read, write, scan.
Built on ctypes (stdlib only, no external deps).

Must run as Administrator!

Usage:
    with GameProcess() as gp:
        hits = gp.scan_f32(803.0)
        for addr in hits:
            print(f"0x{addr:016X} = {gp.read_f32(addr)}")
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import subprocess
from dataclasses import dataclass

# ---- Windows API constants ----

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000

READABLE_PROTECTIONS = {
    0x02,  # PAGE_READONLY
    0x04,  # PAGE_READWRITE
    0x08,  # PAGE_WRITECOPY
    0x20,  # PAGE_EXECUTE_READ
    0x40,  # PAGE_EXECUTE_READWRITE
    0x80,  # PAGE_EXECUTE_WRITECOPY
}

WRITABLE_PROTECTIONS = {
    0x04,  # PAGE_READWRITE
    0x40,  # PAGE_EXECUTE_READWRITE
}

ALL_ACCESS = (
    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
    | PROCESS_QUERY_INFORMATION
)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# ---- Address space limit (x64 user-mode) ----
MAX_ADDRESS = 0x7FFFFFFFFFFF


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


@dataclass
class MemoryRegion:
    """Cached description of a committed memory region."""
    base: int
    size: int
    protect: int

    @property
    def writable(self) -> bool:
        return self.protect in WRITABLE_PROTECTIONS


class MemoryError(Exception):
    """Raised when a memory operation fails."""


class GameProcess:
    """Windows process memory access for ge.exe.

    Usage:
        with GameProcess() as gp:
            hits = gp.scan_f32(803.0)
    """

    def __init__(self, pid: int | None = None, process_name: str = "ge"):
        self._pid: int = pid or self._find_pid(process_name)
        self._handle: int = 0
        self._regions: list[MemoryRegion] | None = None  # cached

    # ---- Context manager ----

    def __enter__(self) -> GameProcess:
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- Process lifecycle ----

    @staticmethod
    def _find_pid(name: str = "ge") -> int:
        """Find process PID via PowerShell."""
        result = subprocess.run(
            [
                "powershell", "-Command",
                f'Get-Process -Name "{name}" -ErrorAction SilentlyContinue '
                '| Select-Object -ExpandProperty Id',
            ],
            capture_output=True, text=True,
        )
        pids = result.stdout.strip().split()
        if not pids:
            raise MemoryError(f"{name}.exe not found — is the game running?")
        return int(pids[0])

    def open(self, access: int = ALL_ACCESS) -> None:
        """Open process handle."""
        if self._handle:
            return
        h = kernel32.OpenProcess(access, False, self._pid)
        if not h:
            err = ctypes.get_last_error()
            if err == 5:
                raise MemoryError("Access denied — run as Administrator!")
            raise MemoryError(f"OpenProcess failed: error {err}")
        self._handle = h

    def close(self) -> None:
        """Close process handle."""
        if self._handle:
            kernel32.CloseHandle(self._handle)
            self._handle = 0

    @property
    def pid(self) -> int:
        return self._pid

    # ---- Memory region enumeration (cached) ----

    def _ensure_regions(self) -> list[MemoryRegion]:
        """Enumerate and cache committed memory regions."""
        if self._regions is not None:
            return self._regions

        regions: list[MemoryRegion] = []
        mbi = MEMORY_BASIC_INFORMATION()
        address = 0

        while address < MAX_ADDRESS:
            result = kernel32.VirtualQueryEx(
                self._handle, ctypes.c_void_p(address),
                ctypes.byref(mbi), ctypes.sizeof(mbi),
            )
            if result == 0:
                break

            if (mbi.State == MEM_COMMIT
                    and mbi.Protect in READABLE_PROTECTIONS
                    and mbi.RegionSize < 100_000_000):
                regions.append(MemoryRegion(
                    base=mbi.BaseAddress,
                    size=mbi.RegionSize,
                    protect=mbi.Protect,
                ))

            address = (mbi.BaseAddress or 0) + mbi.RegionSize

        self._regions = regions
        return regions

    def invalidate_cache(self) -> None:
        """Force re-enumeration of memory regions on next scan."""
        self._regions = None

    # ---- Read methods ----

    def read_bytes(self, addr: int, size: int) -> bytes:
        """Read raw bytes from process memory."""
        buf = ctypes.create_string_buffer(size)
        n_read = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            self._handle, ctypes.c_void_p(addr),
            buf, size, ctypes.byref(n_read),
        )
        if not ok or n_read.value != size:
            raise MemoryError(f"ReadProcessMemory failed at 0x{addr:X} (size={size})")
        return buf.raw

    def read_f32(self, addr: int) -> float:
        """Read a little-endian float32."""
        return struct.unpack("<f", self.read_bytes(addr, 4))[0]

    def read_i32(self, addr: int) -> int:
        """Read a little-endian int32."""
        return struct.unpack("<i", self.read_bytes(addr, 4))[0]

    def read_u32(self, addr: int) -> int:
        """Read a little-endian uint32."""
        return struct.unpack("<I", self.read_bytes(addr, 4))[0]

    def read_struct(self, addr: int, fmt: str) -> tuple:
        """Read an arbitrary struct (e.g. '<2if' for 2 ints + 1 float)."""
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, self.read_bytes(addr, size))

    # ---- Write methods ----

    def write_bytes(self, addr: int, data: bytes) -> None:
        """Write raw bytes to process memory."""
        n_written = ctypes.c_size_t(0)
        ok = kernel32.WriteProcessMemory(
            self._handle, ctypes.c_void_p(addr),
            data, len(data), ctypes.byref(n_written),
        )
        if not ok or n_written.value != len(data):
            raise MemoryError(f"WriteProcessMemory failed at 0x{addr:X}")

    def write_f32(self, addr: int, value: float) -> None:
        """Write a little-endian float32."""
        self.write_bytes(addr, struct.pack("<f", value))

    # ---- Scan methods ----

    def scan_f32(
        self,
        value: float,
        *,
        writable_only: bool = False,
        epsilon: float = 0.001,
    ) -> list[int]:
        """Scan all committed memory for a float32 value.

        Args:
            value: Target float to find.
            writable_only: If True, only return addresses in writable regions.
            epsilon: Tolerance for float comparison (exact byte match is used
                     for the initial scan; epsilon is for verification).

        Returns:
            List of addresses where the value was found.
        """
        target = struct.pack("<f", value)
        return self._scan_pattern(target, writable_only=writable_only)

    def scan_f32_range(
        self,
        min_val: float,
        max_val: float,
        *,
        writable_only: bool = False,
    ) -> list[tuple[int, float]]:
        """Scan memory for any f32 in [min_val, max_val].

        Returns:
            List of (address, value) tuples.
        """
        results: list[tuple[int, float]] = []

        for region in self._ensure_regions():
            if writable_only and not region.writable:
                continue
            try:
                data = self._read_region(region)
            except MemoryError:
                continue

            # Walk every 4-byte-aligned offset
            for off in range(0, len(data) - 3, 4):
                val = struct.unpack_from("<f", data, off)[0]
                if min_val <= val <= max_val:
                    results.append((region.base + off, val))

        return results

    def scan_bytes(
        self,
        pattern: bytes,
        *,
        writable_only: bool = False,
    ) -> list[int]:
        """Scan memory for a byte pattern."""
        return self._scan_pattern(pattern, writable_only=writable_only)

    def _scan_pattern(
        self,
        pattern: bytes,
        *,
        writable_only: bool = False,
    ) -> list[int]:
        """Core scanner: find all occurrences of a byte pattern."""
        found: list[int] = []

        for region in self._ensure_regions():
            if writable_only and not region.writable:
                continue
            try:
                data = self._read_region(region)
            except MemoryError:
                continue

            pos = 0
            while True:
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                found.append(region.base + pos)
                pos += len(pattern)

        return found

    def _read_region(self, region: MemoryRegion) -> bytes:
        """Read an entire memory region (best-effort)."""
        buf = ctypes.create_string_buffer(region.size)
        n_read = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            self._handle, ctypes.c_void_p(region.base),
            buf, region.size, ctypes.byref(n_read),
        )
        if not ok:
            raise MemoryError(f"Failed to read region at 0x{region.base:X}")
        return buf.raw[:n_read.value]

    # ---- Smart scan methods ----

    def scan_nearby(
        self,
        base_addr: int,
        radius: int = 512,
        fmt: str = "<f",
    ) -> list[tuple[int, tuple]]:
        """Read memory around an address and unpack at every aligned offset.

        Args:
            base_addr: Center address.
            radius: Bytes to read on each side.
            fmt: struct format string for each sample.

        Returns:
            List of (address, unpacked_values) tuples.
        """
        step = struct.calcsize(fmt)
        start = max(0, base_addr - radius)
        total = radius * 2

        try:
            data = self.read_bytes(start, total)
        except MemoryError:
            return []

        results: list[tuple[int, tuple]] = []
        for off in range(0, len(data) - step + 1, step):
            vals = struct.unpack_from(fmt, data, off)
            results.append((start + off, vals))
        return results

    def correlate_scan(
        self,
        values: list[float],
        *,
        max_gap: int = 256,
        writable_only: bool = True,
    ) -> list[dict]:
        """Find addresses where multiple f32 values are close together.

        This is the key insight: if we know several attack_range values that
        should exist in a struct array (e.g. party members), we scan for each
        value and then find groups where 2+ values appear within max_gap bytes
        of each other — a strong indicator of the character struct array.

        Args:
            values: List of f32 values to search for.
            max_gap: Maximum byte distance between two values to consider
                     them part of the same struct/array.
            writable_only: Only consider writable memory regions.

        Returns:
            List of dicts with keys:
                - matches: list of (address, value) tuples in the group
                - span: byte distance from first to last match
                - base: lowest address in the group
        """
        if len(values) < 2:
            raise ValueError("correlate_scan needs at least 2 values")

        # Scan for each value
        all_hits: list[tuple[int, float]] = []
        for v in values:
            addrs = self.scan_f32(v, writable_only=writable_only)
            for a in addrs:
                all_hits.append((a, v))

        if not all_hits:
            return []

        # Sort by address
        all_hits.sort(key=lambda x: x[0])

        # Group: sliding window — addresses within max_gap of each other
        groups: list[dict] = []
        i = 0
        while i < len(all_hits):
            group = [all_hits[i]]
            j = i + 1
            while j < len(all_hits):
                if all_hits[j][0] - group[-1][0] <= max_gap:
                    group.append(all_hits[j])
                    j += 1
                else:
                    break

            # Only keep groups with 2+ distinct values
            distinct = {v for _, v in group}
            if len(distinct) >= 2:
                groups.append({
                    "matches": group,
                    "span": group[-1][0] - group[0][0],
                    "base": group[0][0],
                    "distinct_values": len(distinct),
                })

            i = j if j > i + 1 else i + 1

        # Sort by number of distinct values (most = best), then by span (tightest)
        groups.sort(key=lambda g: (-g["distinct_values"], g["span"]))
        return groups

    # ---- Utility ----

    def dump_hex(self, addr: int, size: int = 256) -> str:
        """Hex dump of memory region (for visual inspection)."""
        try:
            data = self.read_bytes(addr, size)
        except MemoryError:
            return f"<unreadable at 0x{addr:X}>"

        lines: list[str] = []
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"  0x{addr + off:012X}  {hex_part:<48s}  {ascii_part}")
        return "\n".join(lines)

    @staticmethod
    def is_admin() -> bool:
        """Check if the current process is running as Administrator."""
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
