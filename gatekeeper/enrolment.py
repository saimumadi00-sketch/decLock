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
import uuid
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


_DLLS = {}


def _api():
    """Private kernel32/advapi32 handles with every prototype declared.

    Private, because ctypes.windll.<dll> is shared by the whole process: other modules set their own
    argtypes on it (crypto.py declares LocalFree), and calls without argtypes pass 64-bit handles as
    32-bit ints. GetCurrentProcess() returns -1 as a handle, which overflowed, so current_sid()
    failed on every call. That silently disabled the watchdog (is_system() was always False), the
    enrolment markers and the log checkpoints."""
    if not _DLLS:
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        k32.GetCurrentProcess.argtypes, k32.GetCurrentProcess.restype = [], wintypes.HANDLE
        k32.CloseHandle.argtypes, k32.CloseHandle.restype = [wintypes.HANDLE], wintypes.BOOL
        k32.LocalFree.argtypes, k32.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
        adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        adv.OpenProcessToken.restype = wintypes.BOOL
        adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD)]
        adv.GetTokenInformation.restype = wintypes.BOOL
        adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        adv.ConvertSidToStringSidW.restype = wintypes.BOOL
        adv.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
                                              ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_void_p,
                                              ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        adv.GetNamedSecurityInfoW.restype = wintypes.DWORD
        _DLLS.update(kernel32=k32, advapi32=adv)
    return _DLLS["kernel32"], _DLLS["advapi32"]


def sid_string(psid) -> str:
    """A SID pointer -> 'S-1-5-...'."""
    kernel32, advapi32 = _api()
    text = ctypes.c_void_p()
    if not advapi32.ConvertSidToStringSidW(psid, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.wstring_at(text.value)
    finally:
        kernel32.LocalFree(text)


def token_user_sid(token) -> str:
    """The user SID string of an access token (TokenUser)."""
    from ctypes import wintypes
    _kernel32, advapi32 = _api()
    size = wintypes.DWORD()
    advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # ask for the size first
    buf = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    return sid_string(ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0])  # TOKEN_USER.User.Sid


def current_sid() -> str:
    """The current Windows user's SID string (S-1-5-21-...); on other systems a uid stand-in."""
    if not hasattr(ctypes, "WinDLL"):
        return f"uid-{os.getuid()}" if hasattr(os, "getuid") else "unknown"
    from ctypes import wintypes
    kernel32, advapi32 = _api()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return token_user_sid(token)
    finally:
        kernel32.CloseHandle(token)


ADMINS, SYSTEM = "S-1-5-32-544", "S-1-5-18"


def file_owner_sid(path):
    """The SID string of a file's owner, or None when it can't be read (or not on Windows).

    In the add-only folder the owner is whoever created the file, and a standard user cannot make
    a file owned by someone else, so the owner says who really wrote a marker or checkpoint."""
    if not hasattr(ctypes, "WinDLL"):
        return None
    kernel32, advapi32 = _api()
    owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    # SE_FILE_OBJECT = 1, OWNER_SECURITY_INFORMATION = 1
    if advapi32.GetNamedSecurityInfoW(str(path), 1, 1, ctypes.byref(owner), None, None, None,
                                      ctypes.byref(descriptor)) != 0:
        return None
    try:
        return sid_string(owner)
    except OSError:
        return None
    finally:
        kernel32.LocalFree(descriptor)


class Enrolment:
    """`folder=None` uses the installer's folder, and only in an installed (frozen) build.

    `owner_fn(path) -> SID or None` checks who created a file. It defaults to the real owner lookup
    in the installed build only (development checkouts and tests use made-up SIDs)."""

    def __init__(self, folder=None, sid=None, frozen=None, owner_fn=None):
        frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
        self.owner_fn = owner_fn if owner_fn is not None else (file_owner_sid if frozen else None)
        if folder is None and frozen:
            try:
                folder = default_folder()
            except Exception:
                log.warning("could not find the ProgramData folder; enrolment markers are off", exc_info=True)
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

    def trusted(self, path) -> bool:
        """Was `path` written by this user (or an administrator / SYSTEM)? Anyone may ADD files to the
        folder, so a file named after this user's SID proves nothing unless they own it."""
        if self.owner_fn is None:
            return True
        try:
            owner = self.owner_fn(path)
        except Exception:
            log.warning("could not read the owner of %s", path, exc_info=True)
            return False
        return owner in (self.sid, ADMINS, SYSTEM)

    def _markers(self) -> list:
        """This user's markers: <SID> and <SID>.marker.<random> (the second form exists because
        someone else may have created a file called <SID> first, to squat the name)."""
        prefix = self.sid + ".marker."
        names = [self.sid] + [n for n in os.listdir(self.folder) if n.startswith(prefix)]
        return [self.folder / n for n in names if (self.folder / n).is_file()]

    # Every public method below is fail-safe: any error (an unexpected Windows API result, a
    # permissions surprise) is logged and treated as "no marker". The marker is an extra safeguard;
    # it must never stop Gatekeeper from starting or the owner from using it.

    def enrolled(self) -> bool:
        try:
            return self.active and any(self.trusted(m) for m in self._markers())
        except Exception:
            log.warning("could not check the enrolment marker", exc_info=True)
            return False

    def mark(self) -> bool:
        """Add this user's marker (once). True if it exists afterwards. Never raises."""
        try:
            if not self.active:
                return False
            if not self.enrolled():
                try:
                    fd = os.open(self._marker(), os.O_CREAT | os.O_EXCL | os.O_WRONLY)  # add-file only
                except FileExistsError:  # <SID> exists but isn't ours: someone squatted the name
                    log.warning("enrolment marker %s was created by someone else", self._marker())
                    fd = os.open(self.folder / f"{self.sid}.marker.{uuid.uuid4().hex}",
                                 os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
        except Exception:
            log.warning("could not record enrolment in %s", self.folder, exc_info=True)
            return False
        return self.enrolled()


def setup_blocked(db, enrolment: Enrolment = None) -> bool:
    """True when no password is stored, yet this user was set up before: the data was removed."""
    from . import auth
    if auth.has_password(db):
        return False
    try:
        enrolment = enrolment or Enrolment()
    except Exception:
        log.warning("enrolment check unavailable", exc_info=True)
        return False
    return enrolment.enrolled()


def sync(db, enrolment: Enrolment = None) -> None:
    """Make sure a user who has a password also has a marker (covers installs made before markers)."""
    from . import auth
    try:
        if auth.has_password(db):
            (enrolment or Enrolment()).mark()
    except Exception:
        log.warning("could not sync the enrolment marker", exc_info=True)
