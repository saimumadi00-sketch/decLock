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
    """Is this Windows session locked (lock screen showing)?

    Asks Remote Desktop Services for the session's lock flag (WTSSessionInfoEx). Unlike checking
    whether the input desktop is reachable, this is NOT fooled by a UAC prompt or the Ctrl+Alt+Del
    screen, which would otherwise re-lock open apps every time an admin prompt appears.
    Returns False when the answer is unavailable (other systems, or the call fails), so a failure
    only means "no re-lock on Windows lock"; the idle re-lock still works."""
    try:
        wtsapi32 = ctypes.windll.wtsapi32
    except (AttributeError, OSError):
        return False
    buffer, size = ctypes.c_void_p(), wintypes.DWORD()
    # (server = WTS_CURRENT_SERVER_HANDLE, session = WTS_CURRENT_SESSION, class 25 = WTSSessionInfoEx)
    wtsapi32.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
                                                    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    if not wtsapi32.WTSQuerySessionInformationW(None, 0xFFFFFFFF, 25, ctypes.byref(buffer), ctypes.byref(size)):
        return False
    try:
        if size.value < 20:
            return False
        # WTSINFOEXW: DWORD Level; then (8-byte aligned) WTSINFOEX_LEVEL1_W: ULONG SessionId,
        # WTS_CONNECTSTATE_CLASS SessionState, LONG SessionFlags -> SessionFlags sits at byte 16.
        level = ctypes.c_uint32.from_address(buffer.value).value
        flags = ctypes.c_int32.from_address(buffer.value + 16).value
        return level == 1 and flags == 0  # WTS_SESSIONSTATE_LOCK = 0, UNLOCK = 1, UNKNOWN = -1
    finally:
        wtsapi32.WTSFreeMemory(buffer)


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
