import ctypes
from ctypes import Structure, byref, sizeof, wintypes


class _LastInputInfo(Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]


def idle_seconds() -> float:
    info = _LastInputInfo(sizeof(_LastInputInfo), 0)
    if not ctypes.windll.user32.GetLastInputInfo(byref(info)):
        raise ctypes.WinError()
    ticks = ctypes.windll.kernel32.GetTickCount()
    return ((ticks - info.dwTime) & 0xFFFFFFFF) / 1000.0  # mask handles the 49-day tick wrap


def lock_workstation() -> bool:
    """Locks the Windows session (unlock = the Windows account password, not Gatekeeper's)."""
    return bool(ctypes.windll.user32.LockWorkStation())


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # not Windows
        return False


def enable_dpi_awareness() -> None:
    """Crisp text on high-DPI screens. Harmless if unavailable."""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


def relaunch_elevated(args: list) -> bool:
    """Start this program again with a UAC prompt. False if the user declined or it failed."""
    import subprocess
    import sys
    params = list(args) if getattr(sys, "frozen", False) else ["-m", "gatekeeper"] + list(args)
    try:
        return ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                                   subprocess.list2cmdline(params), None, 1) > 32
    except Exception:
        return False
