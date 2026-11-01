"""Thin ctypes wrappers around the few Windows API calls Gatekeeper needs."""

import ctypes
from ctypes import Structure, byref, sizeof, wintypes


class _LastInputInfo(Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]


def idle_seconds() -> float:
    """Seconds since the last keyboard or mouse input in this session."""
    info = _LastInputInfo(sizeof(_LastInputInfo), 0)
    if not ctypes.windll.user32.GetLastInputInfo(byref(info)):
        raise ctypes.WinError()
    ticks = ctypes.windll.kernel32.GetTickCount()
    return ((ticks - info.dwTime) & 0xFFFFFFFF) / 1000.0  # mask handles the 49-day tick wrap


def session_locked() -> bool:
    """Is the Windows lock screen (or another secure desktop) showing instead of the user's desktop?

    While it is, this session can't open or switch to the input desktop. False on other systems."""
    try:
        user32 = ctypes.windll.user32
    except AttributeError:
        return False
    user32.OpenInputDesktop.restype = wintypes.HANDLE
    desktop = user32.OpenInputDesktop(0, False, 0x0100)  # DESKTOP_SWITCHDESKTOP
    if not desktop:
        return True  # the input desktop belongs to Winlogon: locked (or a UAC prompt is up)
    try:
        return not user32.SwitchDesktop(desktop)
    finally:
        user32.CloseDesktop(desktop)


def lock_workstation() -> bool:
    """Locks the Windows session (unlock = the Windows account password, not Gatekeeper's)."""
    return bool(ctypes.windll.user32.LockWorkStation())


def is_admin() -> bool:
    """Is this process elevated (needed to change the USB policy)?"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # not Windows
        return False


def enable_dpi_awareness() -> None:
    """Crisp text on high-DPI screens. Harmless if unavailable."""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # 1 = system DPI aware
    except Exception:
        pass


def relaunch_elevated(args: list) -> bool:
    """Start this program again with a UAC prompt. False if the user declined or it failed."""
    import subprocess
    import sys
    # A frozen build IS the program; from source, sys.executable is python.exe and needs "-m gatekeeper".
    params = list(args) if getattr(sys, "frozen", False) else ["-m", "gatekeeper"] + list(args)
    try:
        # "runas" = show the UAC prompt; ShellExecute returns a value > 32 on success.
        return ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                                   subprocess.list2cmdline(params), None, 1) > 32
    except Exception:
        return False


def virtual_screen() -> tuple:
    """(x, y, width, height) of the rectangle covering every monitor. Falls back to the primary one."""
    try:
        user32 = ctypes.windll.user32
        x, y = user32.GetSystemMetrics(76), user32.GetSystemMetrics(77)        # SM_X/YVIRTUALSCREEN
        w, h = user32.GetSystemMetrics(78), user32.GetSystemMetrics(79)        # SM_CX/CYVIRTUALSCREEN
        if w > 0 and h > 0:
            return x, y, w, h
        return 0, 0, user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
    except Exception:
        return 0, 0, 1280, 720


def _top_level(widget_id: int) -> int:
    """Tk's winfo_id() is an inner child window; Win32 calls need the real top-level window."""
    return ctypes.windll.user32.GetAncestor(widget_id, 2) or widget_id         # GA_ROOT


def force_foreground(widget_id: int) -> None:
    """Bring a Tk window to the front and give it keyboard focus. Windows normally refuses focus
    changes from a background process; tapping Alt first makes it allow SetForegroundWindow."""
    try:
        user32 = ctypes.windll.user32
        user32.keybd_event(0x12, 0, 0, 0)  # VK_MENU (Alt) down
        user32.keybd_event(0x12, 0, 2, 0)  # Alt up (KEYEVENTF_KEYUP)
        user32.SetForegroundWindow(_top_level(widget_id))
    except Exception:
        pass


def make_click_through(widget_id: int) -> None:
    """Let mouse clicks fall through a (fading) window to whatever is underneath."""
    try:
        user32 = ctypes.windll.user32
        hwnd = _top_level(widget_id)
        style = user32.GetWindowLongW(hwnd, -20)                                # GWL_EXSTYLE
        user32.SetWindowLongW(hwnd, -20, style | 0x80000 | 0x20)               # LAYERED | TRANSPARENT
    except Exception:
        pass
