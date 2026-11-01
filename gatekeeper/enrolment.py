"""Remember, outside the user's own folder, that this Windows user already set up Gatekeeper.

Everything else Gatekeeper keeps lives in %APPDATA%\\Gatekeeper, which the user (and anyone at
their unlocked PC) can delete. Without this module, deleting that folder brought back the
first-run "choose a password" screen, so whoever deleted it could pick their own password.

The installer creates %ProgramData%\\Gatekeeper\\enrolled with an access list that lets ordinary
users ADD files but not change or delete them (see installer.iss). When a user sets their first
password, an empty marker file named after their Windows SID is added there. From then on:

  * the password store present  -> normal
  * the password store missing  -> first-run setup is refused; an administrator must delete the
                                   marker to allow a fresh start (README: Recovery)

A marker carries no secret and is never trusted for anything else: anyone may ADD a marker (which
can only make setup stricter), but a standard user cannot remove one.

The check only runs in the installed (frozen) build and only when the installer made the folder,
so development checkouts and tests are unaffected unless they pass a folder explicitly.
"""

import ctypes
import logging
import os
import sys
from pathlib import Path

log = logging.getLogger("gatekeeper.enrolment")

BLOCKED_MESSAGE = ("Gatekeeper was already set up for this Windows user, but its data is missing "
                   "(deleted or replaced). Setting a new password is blocked. An administrator must "
                   "reset it: see Recovery in the README.")


def _program_data() -> Path:
    """%ProgramData% from the known-folder API: unlike the environment variable, a user can't redirect it."""
    try:
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("a", wintypes.DWORD), ("b", wintypes.WORD), ("c", wintypes.WORD), ("d", ctypes.c_ubyte * 8)]

        # FOLDERID_ProgramData {62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}
        folder = GUID(0x62AB5D82, 0xFDC1, 0x4DC3, (ctypes.c_ubyte * 8)(0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97))
        out = ctypes.c_wchar_p()
        shell32, ole32 = ctypes.windll.shell32, ctypes.windll.ole32
        if shell32.SHGetKnownFolderPath(ctypes.byref(folder), 0, None, ctypes.byref(out)) != 0:
            raise OSError("SHGetKnownFolderPath failed")
        try:
            return Path(out.value)
        finally:
            ole32.CoTaskMemFree(out)
    except (AttributeError, OSError):  # not Windows
        return Path(os.environ.get("ProgramData", "/var/lib"))


def default_folder() -> Path:
    return _program_data() / "Gatekeeper" / "enrolled"


def current_sid() -> str:
    """The current Windows user's SID string (S-1-5-21-...); on other systems a uid stand-in."""
    try:
        from ctypes import wintypes
        advapi32, kernel32 = ctypes.windll.advapi32, ctypes.windll.kernel32
    except AttributeError:
        return f"uid-{os.getuid()}" if hasattr(os, "getuid") else "unknown"
    token = wintypes.HANDLE()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
        raise ctypes.WinError()
    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser: ask for the size
        buf = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
            raise ctypes.WinError()
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]  # TOKEN_USER.User.Sid
        text = ctypes.c_wchar_p()
        if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(sid_ptr), ctypes.byref(text)):
            raise ctypes.WinError()
        try:
            return text.value
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.CloseHandle(token)


class Enrolment:
    """`folder=None` uses the installer's folder, and only in an installed (frozen) build."""

    def __init__(self, folder=None, sid=None, frozen=None):
        frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
        if folder is None:
            folder = default_folder() if frozen else None
        self.folder = Path(folder) if folder else None
        self._sid = sid

    @property
    def active(self) -> bool:
        """Only when the installer created the folder: otherwise there is nowhere safe to keep a marker."""
        return self.folder is not None and self.folder.is_dir()

    @property
    def sid(self) -> str:
        if self._sid is None:
            self._sid = current_sid()
        return self._sid

    def _marker(self) -> Path:
        return self.folder / self.sid

    def enrolled(self) -> bool:
        return self.active and self._marker().exists()

    def mark(self) -> bool:
        """Add this user's marker (once). True if it exists afterwards. Never raises."""
        if not self.active:
            return False
        try:
            if not self._marker().exists():
                fd = os.open(self._marker(), os.O_CREAT | os.O_EXCL | os.O_WRONLY)  # add-file only, no edits
                os.close(fd)
        except FileExistsError:
            pass
        except OSError as exc:
            log.warning("could not record enrolment in %s: %s", self.folder, exc)
        return self._marker().exists()


def setup_blocked(db, enrolment: Enrolment = None) -> bool:
    """True when no password is stored, yet this user was set up before: the data was removed."""
    from . import auth
    if auth.has_password(db):
        return False
    enrolment = enrolment or Enrolment()
    return enrolment.enrolled()


def sync(db, enrolment: Enrolment = None) -> None:
    """Make sure a user who has a password also has a marker (covers installs made before markers)."""
    from . import auth
    if auth.has_password(db):
        (enrolment or Enrolment()).mark()
