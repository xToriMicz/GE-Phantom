"""
GE_Phantom — Win32 Input Controller

Sends keyboard and mouse input to the Granado Espada game window.

Keyboard: PostMessage(hwnd, WM_KEYDOWN/WM_KEYUP) — sends directly to game
  window handle, doesn't require focus. Works with GE game client.
  (keybd_event only worked for the patcher/login, not in-game.)

Mouse: SetCursorPos + mouse_event — confirmed working with GE.

Requirements: Run as Administrator.

Usage:
    from src.bot.input import GEInput, VK
    inp = GEInput()
    inp.auto_attack()                       # press SPACE
    inp.key_combo(VK.A, ctrl=True)          # press Ctrl+A
    inp.click_relative(400, 300)            # click at window-relative coords
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import time
from dataclasses import dataclass
from enum import IntEnum

# ---- Win32 constants ----

# Window messages for keyboard
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_CHAR = 0x0102

# Mouse event flags
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004

SM_CXSCREEN = 0
SM_CYSCREEN = 1


class VK(IntEnum):
    """Virtual key codes used by Granado Espada."""
    # Modifiers
    SHIFT = 0x10
    CTRL = 0x11
    ALT = 0x12

    # Control
    ESCAPE = 0x1B
    SPACE = 0x20
    TAB = 0x09

    # Function keys
    F1 = 0x70
    F2 = 0x71
    F3 = 0x72
    F4 = 0x73
    F5 = 0x74
    F6 = 0x75
    F7 = 0x76
    F8 = 0x77
    F9 = 0x78
    F10 = 0x79
    F11 = 0x7A
    F12 = 0x7B

    # Letters (skill slots: Q-M row 1, A-K row 2, Z-COMMA row 3)
    A = 0x41
    B = 0x42
    C = 0x43
    D = 0x44
    E = 0x45
    F = 0x46
    G = 0x47
    H = 0x48
    I = 0x49
    J = 0x4A
    K = 0x4B
    L = 0x4C
    M = 0x4D
    N = 0x4E
    O = 0x4F
    Q = 0x51
    R = 0x52
    S = 0x53
    T = 0x54
    U = 0x55
    V = 0x56
    W = 0x57
    X = 0x58
    Y = 0x59
    Z = 0x5A

    # Numpad
    NUM0 = 0x60
    NUM1 = 0x61
    NUM2 = 0x62
    NUM3 = 0x63
    NUM4 = 0x64
    NUM5 = 0x65
    NUM6 = 0x66
    NUM7 = 0x67
    NUM8 = 0x68
    NUM9 = 0x69

    # Navigation
    PRIOR = 0x21  # Page Up
    NEXT = 0x22   # Page Down

    # OEM
    COMMA = 0xBC


# Scan code table for common keys (used in WM_KEYDOWN lParam)
_SCAN_CODES: dict[int, int] = {
    VK.SPACE: 0x39,
    VK.ESCAPE: 0x01,
    VK.TAB: 0x0F,
    VK.CTRL: 0x1D,
    VK.SHIFT: 0x2A,
    VK.ALT: 0x38,
    VK.F1: 0x3B, VK.F2: 0x3C, VK.F3: 0x3D, VK.F4: 0x3E,
    VK.F5: 0x3F, VK.F6: 0x40, VK.F7: 0x41, VK.F8: 0x42,
    VK.F9: 0x43, VK.F10: 0x44, VK.F11: 0x57, VK.F12: 0x58,
    VK.A: 0x1E, VK.B: 0x30, VK.C: 0x2E, VK.D: 0x20,
    VK.E: 0x12, VK.F: 0x21, VK.G: 0x22, VK.H: 0x23,
    VK.I: 0x17, VK.J: 0x24, VK.K: 0x25, VK.L: 0x26,
    VK.M: 0x32, VK.N: 0x31, VK.O: 0x18,
    VK.Q: 0x10, VK.R: 0x13, VK.S: 0x1F, VK.T: 0x14,
    VK.U: 0x16, VK.V: 0x2F, VK.W: 0x11, VK.X: 0x2D,
    VK.Y: 0x15, VK.Z: 0x2C,
    VK.COMMA: 0x33,
}


def _make_lparam(vk: int, up: bool = False) -> int:
    """Build lParam for WM_KEYDOWN/WM_KEYUP message.

    Bits 0-15:  repeat count (1)
    Bits 16-23: scan code
    Bit 24:     extended key flag
    Bit 29:     context code (0)
    Bit 30:     previous key state (0 for down, 1 for up)
    Bit 31:     transition state (0 for down, 1 for up)
    """
    scan = _SCAN_CODES.get(vk, 0)
    lparam = 1 | (scan << 16)
    if up:
        lparam |= (1 << 30) | (1 << 31)
    return lparam


# ---- Win32 API bindings ----

user32 = ctypes.windll.user32

# Window management
FindWindowW = user32.FindWindowW
FindWindowW.argtypes = [wt.LPCWSTR, wt.LPCWSTR]
FindWindowW.restype = wt.HWND

GetWindowRect = user32.GetWindowRect
GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
GetWindowRect.restype = wt.BOOL

SetForegroundWindow = user32.SetForegroundWindow
SetForegroundWindow.argtypes = [wt.HWND]
SetForegroundWindow.restype = wt.BOOL

GetForegroundWindow = user32.GetForegroundWindow
GetForegroundWindow.restype = wt.HWND

GetSystemMetrics = user32.GetSystemMetrics
GetSystemMetrics.argtypes = [ctypes.c_int]
GetSystemMetrics.restype = ctypes.c_int

# Keyboard — PostMessage sends directly to window handle (no focus needed)
PostMessageW = user32.PostMessageW
PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
PostMessageW.restype = wt.BOOL

MapVirtualKeyW = user32.MapVirtualKeyW
MapVirtualKeyW.argtypes = [wt.UINT, wt.UINT]
MapVirtualKeyW.restype = wt.UINT

# Mouse — mouse_event (confirmed working with GE game client)
mouse_event = user32.mouse_event
mouse_event.argtypes = [wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, ctypes.POINTER(wt.ULONG)]
mouse_event.restype = None

SetCursorPos = user32.SetCursorPos
SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
SetCursorPos.restype = wt.BOOL

IsUserAnAdmin = ctypes.windll.shell32.IsUserAnAdmin
IsUserAnAdmin.restype = wt.BOOL


# ---- Game Window ----

GE_WINDOW_CLASS = "Granado Espada"
GE_WINDOW_TITLES = ["Granado Espada", "GE"]


@dataclass
class WindowRect:
    """Screen coordinates of a window."""
    left: int
    top: int
    right: int
    bottom: int

    @property
    def width(self) -> int:
        return self.right - self.left

    @property
    def height(self) -> int:
        return self.bottom - self.top

    @property
    def center_x(self) -> int:
        return (self.left + self.right) // 2

    @property
    def center_y(self) -> int:
        return (self.top + self.bottom) // 2


class GameWindow:
    """Finds and tracks the GE game window."""

    def __init__(self, hwnd: int = 0):
        self._hwnd: int = hwnd

    @property
    def hwnd(self) -> int:
        return self._hwnd

    @property
    def found(self) -> bool:
        return self._hwnd != 0

    def find(self) -> bool:
        """Find the GE game window. Returns True if found."""
        h = FindWindowW(GE_WINDOW_CLASS, None)
        if h:
            self._hwnd = h
            return True
        for title in GE_WINDOW_TITLES:
            h = FindWindowW(None, title)
            if h:
                self._hwnd = h
                return True
        self._hwnd = 0
        return False

    def get_rect(self) -> WindowRect | None:
        """Get window screen coordinates."""
        if not self._hwnd:
            return None
        rect = wt.RECT()
        if GetWindowRect(self._hwnd, ctypes.byref(rect)):
            return WindowRect(
                left=rect.left, top=rect.top,
                right=rect.right, bottom=rect.bottom,
            )
        return None

    def is_foreground(self) -> bool:
        return self._hwnd != 0 and GetForegroundWindow() == self._hwnd

    def activate(self) -> bool:
        if not self._hwnd:
            return False
        return bool(SetForegroundWindow(self._hwnd))


# ---- Input Controller ----

class InputController:
    """Sends keyboard and mouse input to the GE game window.

    Keyboard: PostMessage(hwnd, WM_KEYDOWN/WM_KEYUP) — sends directly to
      window handle, no focus required. Works with GE game client.
    Mouse: SetCursorPos + mouse_event — confirmed working.
    Requires Administrator privileges.
    """

    KEY_PRESS_DELAY = 0.05
    MOD_DELAY = 0.03
    CLICK_DELAY = 0.05

    def __init__(self, window: GameWindow | None = None):
        self.window = window or GameWindow()
        self._screen_w = GetSystemMetrics(SM_CXSCREEN)
        self._screen_h = GetSystemMetrics(SM_CYSCREEN)

    @staticmethod
    def is_admin() -> bool:
        return bool(IsUserAnAdmin())

    def ensure_window(self) -> bool:
        if self.window.found:
            return True
        return self.window.find()

    # ---- Keyboard (PostMessage to hwnd) ----

    def _post_key(self, msg: int, vk: int, lparam: int) -> None:
        """Post a keyboard message to the game window."""
        if self.window.hwnd:
            PostMessageW(self.window.hwnd, msg, vk, lparam)

    def key_down(self, vk: int) -> None:
        """Press a key down via PostMessage."""
        self._post_key(WM_KEYDOWN, vk, _make_lparam(vk, up=False))
        time.sleep(0.02)

    def key_up(self, vk: int) -> None:
        """Release a key via PostMessage."""
        self._post_key(WM_KEYUP, vk, _make_lparam(vk, up=True))
        time.sleep(0.02)

    def send_key(self, vk: int, hold: float = 0.0) -> None:
        """Press and release a single key.

        Args:
            vk: Virtual key code (use VK enum).
            hold: Optional hold time in seconds between down and up.
        """
        self.key_down(vk)
        if hold > 0:
            time.sleep(hold)
        self.key_up(vk)
        time.sleep(self.KEY_PRESS_DELAY)

    def key_combo(
        self, vk: int, *, ctrl: bool = False, alt: bool = False, shift: bool = False,
    ) -> None:
        """Press a key combination (e.g., Ctrl+A)."""
        mods: list[int] = []
        if ctrl:
            mods.append(VK.CTRL)
        if alt:
            mods.append(VK.ALT)
        if shift:
            mods.append(VK.SHIFT)

        for mod in mods:
            self.key_down(mod)
        time.sleep(self.MOD_DELAY)

        self.send_key(vk)

        time.sleep(self.MOD_DELAY)
        for mod in reversed(mods):
            self.key_up(mod)

    # ---- Mouse (SetCursorPos + mouse_event) ----

    def click_at(self, screen_x: int, screen_y: int) -> None:
        """Click at absolute screen coordinates."""
        SetCursorPos(screen_x, screen_y)
        time.sleep(0.01)
        mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, None)
        time.sleep(self.CLICK_DELAY)
        mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, None)

    def click_relative(self, win_x: int, win_y: int) -> None:
        """Click at coordinates relative to the game window's top-left corner."""
        rect = self.window.get_rect()
        if not rect:
            return
        self.click_at(rect.left + win_x, rect.top + win_y)

    def click_center(self) -> None:
        """Click at the center of the game window."""
        rect = self.window.get_rect()
        if not rect:
            return
        self.click_at(rect.center_x, rect.center_y)

    def click_direction(self, angle_rad: float, radius_px: int = 200) -> None:
        """Click in a direction from the center of the game window.

        Args:
            angle_rad: Angle in radians (0 = right, pi/2 = down, pi = left).
            radius_px: Distance from center in pixels to click.
        """
        import math
        rect = self.window.get_rect()
        if not rect:
            return
        sx = rect.center_x + int(math.cos(angle_rad) * radius_px)
        sy = rect.center_y + int(math.sin(angle_rad) * radius_px)
        sx = max(0, min(sx, self._screen_w - 1))
        sy = max(0, min(sy, self._screen_h - 1))
        self.click_at(sx, sy)


# ---- GE-specific hotkey helpers ----

SKILL_KEYS: list[int] = [
    VK.Q, VK.W, VK.E, VK.R, VK.T, VK.Y, VK.U, VK.I,      # slots 0-7
    VK.A, VK.S, VK.D, VK.F, VK.G, VK.H, VK.J, VK.K,      # slots 8-15
    VK.Z, VK.X, VK.C, VK.V, VK.B, VK.N, VK.M, VK.COMMA,  # slots 16-23
]


class GEInput(InputController):
    """GE-specific input actions built on top of InputController."""

    def auto_attack(self) -> None:
        """Press SPACE — triggers auto-attack on nearest enemy."""
        self.send_key(VK.SPACE)

    def attack_all(self) -> None:
        """Press Ctrl+A — attack all visible enemies."""
        self.key_combo(VK.A, ctrl=True)

    def select_char(self, index: int) -> None:
        """Select character by index (1=F1, 2=F2, 3=F3)."""
        fkeys = {1: VK.F1, 2: VK.F2, 3: VK.F3}
        vk = fkeys.get(index)
        if vk:
            self.send_key(vk)

    def use_skill(self, slot: int) -> None:
        """Activate a skill by slot number (0-23)."""
        if 0 <= slot < len(SKILL_KEYS):
            self.send_key(SKILL_KEYS[slot])

    def use_item_slot(self, slot: int) -> None:
        """Use item from quickslot (NUM1-NUM3 for char 1-3, NUM4-NUM9 shared)."""
        numkeys = {
            1: VK.NUM1, 2: VK.NUM2, 3: VK.NUM3,
            4: VK.NUM4, 5: VK.NUM5, 6: VK.NUM6,
            7: VK.NUM7, 8: VK.NUM8, 9: VK.NUM9, 0: VK.NUM0,
        }
        vk = numkeys.get(slot)
        if vk:
            self.send_key(vk)
