"""Recognise locked apps that were renamed or copied, so `chrome.exe` saved as `notes.exe` stays locked.

The guard first matches processes by executable name. When the name is not locked, it looks at
the program file itself:

  1. Its OriginalFilename, from the version information Windows programs carry. Renaming or
     copying the file does not change it, and neither do app updates.
  2. Its SHA-256 fingerprint, for programs without version information. Fingerprints are learned
     from the real app: whenever a process with a locked name runs, or when an app is locked by
     browsing to its .exe.

Programs inside the Windows folder are skipped: a standard user cannot put files there, so a
renamed copy cannot hide there, and skipping them keeps the guard cheap.

Remaining gap (see docs/LIMITATIONS.md): someone who edits the program file itself, changing both
its version information and its bytes, is still not recognised.
"""

import ctypes
import hashlib
import logging
import os
from ctypes import wintypes

log = logging.getLogger("gatekeeper.identity")

MAX_HASH_BYTES = 256 * 1024 * 1024  # bigger programs are only checked by OriginalFilename (hashing is slow)
_CHUNK = 1024 * 1024


def _normalize(name: str) -> str:
    """'CHROME.EXE' -> 'chrome.exe'. Windows' own programs say e.g. 'PING.EXE.MUI'; drop the '.mui'."""
    name = (name or "").strip().strip("\x00").lower()
    return name[:-4] if name.endswith(".mui") else name


def original_filename(path: str) -> str:
    """The OriginalFilename stored in a program's version information, normalized ('' if none)."""
    try:
        version = ctypes.windll.version
    except (AttributeError, OSError):  # not Windows
        return ""
    version.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    version.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    version.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(wintypes.UINT)]
    size = version.GetFileVersionInfoSizeW(path, None)
    if not size:
        return ""  # the file has no version information
    data = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(path, 0, size, data):
        return ""
    pointer, length = ctypes.c_void_p(), wintypes.UINT()
    # The strings are stored per language/code page; the Translation table lists which ones exist.
    languages = []
    if version.VerQueryValueW(data, r"\VarFileInfo\Translation", ctypes.byref(pointer), ctypes.byref(length)) \
            and length.value >= 4:
        words = (wintypes.WORD * (length.value // 2)).from_address(pointer.value)
        languages = list(zip(words[0::2], words[1::2]))
    for lang, codepage in languages + [(0x0409, 0x04B0), (0x0409, 0x04E4)]:  # + US English fallbacks
        key = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\OriginalFilename"
        if version.VerQueryValueW(data, key, ctypes.byref(pointer), ctypes.byref(length)) and length.value:
            return _normalize(ctypes.wstring_at(pointer.value, length.value))
    return ""


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):  # in pieces, so big files don't fill memory
            digest.update(chunk)
    return digest.hexdigest()


def _system_dir() -> str:
    root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    return os.path.normcase(os.path.abspath(root)) + os.sep


class Identifier:
    """Works out which locked app (if any) a program file really is. Results are cached per file."""

    def __init__(self, db, system_dir=None, max_hash_bytes: int = MAX_HASH_BYTES):
        self.db, self.max_hash_bytes = db, max_hash_bytes
        system_dir = system_dir if system_dir is not None else _system_dir()
        # normcase lower-cases on Windows, so "C:\Windows" and "c:\windows" compare equal.
        self.system_dir = os.path.normcase(system_dir.rstrip("\\/")) + os.sep if system_dir else ""
        # (path, size, mtime) -> (sha256 or None, original filename). Size and mtime are part of the
        # key, so a file that is replaced (e.g. by an update) is looked at again.
        self._cache = {}
        self._learned = set()  # (sha256, name) already stored, to avoid a db write per process start

    def _info(self, path: str):
        stat = os.stat(path)
        key = (os.path.normcase(path), stat.st_size, stat.st_mtime_ns)
        if key not in self._cache:
            sha = sha256_file(path) if stat.st_size <= self.max_hash_bytes else None
            self._cache[key] = (sha, original_filename(path))
        return self._cache[key]

    def is_system(self, path: str) -> bool:
        return bool(self.system_dir) and os.path.normcase(os.path.abspath(path)).startswith(self.system_dir)

    def learn(self, name: str, path) -> None:
        """Remember the fingerprint of `path` as being the locked app `name`."""
        if not path:
            return
        try:
            sha, _original = self._info(path)
        except OSError:  # gone or unreadable: nothing to learn
            return
        if sha and (sha, name) not in self._learned:
            self.db.add_fingerprint(sha, name)
            self._learned.add((sha, name))

    def match(self, path, apps) -> str:
        """The locked app name that the program at `path` really is, or None."""
        if not path or self.is_system(path):
            return None
        try:
            sha, original = self._info(path)
        except OSError:
            return None
        if original in apps:
            return original
        if sha:
            name = self.db.fingerprint_name(sha)
            if name in apps:
                return name
        return None


def learn_from_running(db, names) -> None:
    """Fingerprint the given locked apps if they are running right now (used when an app is locked)."""
    import psutil
    wanted, identifier = set(names), Identifier(db)
    for proc in psutil.process_iter(["name", "exe"]):
        try:
            name = (proc.info["name"] or "").lower()
            if name in wanted:
                identifier.learn(name, proc.info["exe"])
        except psutil.Error:
            continue
