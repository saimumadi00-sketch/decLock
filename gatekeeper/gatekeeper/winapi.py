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
