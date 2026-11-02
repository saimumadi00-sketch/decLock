"""Folder lock: a locked folder can't be opened, listed, read, changed or deleted until it is
unlocked from Gatekeeper (behind its password).

How: a "deny" entry for Everyone (S-1-1-0) is added to the folder's permissions with icacls and
inherited by everything inside it. Windows then refuses access to every program, Explorer included.
Unlocking removes exactly that entry. Locked folders are locked again when Windows locks or the PC
is idle (with the apps), and a lock that was removed behind Gatekeeper's back is put back.

Limits (docs/LIMITATIONS.md): the folder's owner, an administrator, or anyone in your session can
still change the folder's permissions by hand, the same way they could stop Gatekeeper. Windows
can't show a password prompt when a locked folder is opened (that needs a file-system driver), so
folders are unlocked from the dashboard. Locking a very large folder takes a while, because
Windows writes the permission onto every file inside it.

Recovery without Gatekeeper, for one folder:
    icacls "D:\\Private" /remove:d *S-1-1-0
"""

import json
import logging
import os
import subprocess
import sys
import threading
from pathlib import Path

log = logging.getLogger("gatekeeper.folders")

SETTING = "locked_folders"  # JSON: [{"path": "...", "locked": true}]
EVERYONE = "*S-1-1-0"       # by SID: account names are translated on non-English Windows
# Denied: list folder / read file, traverse / run, create files and folders / write, delete.
# Reading attributes and permissions stays allowed, so the folder still shows in Explorer and
# its owner can always unlock it.
DENY = "(OI)(CI)(RD,X,WD,AD,DE,DC)"


def _icacls(*args) -> subprocess.CompletedProcess:
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")
    return subprocess.run([exe, *args], capture_output=True, text=True, timeout=600,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


class IcaclsBackend:
    """The real thing. Tests use a fake with the same three methods."""

    def lock(self, path: str) -> None:
        result = _icacls(path, "/deny", f"{EVERYONE}:{DENY}", "/c")
        if result.returncode != 0:
            raise OSError(f"Could not lock the folder: {(result.stderr or result.stdout).strip()[-300:]}")

    def unlock(self, path: str) -> None:
        # Only the folder carries the entry; what's inside inherits it and loses it with the folder's.
        result = _icacls(path, "/remove:d", EVERYONE)
        if result.returncode != 0:
            raise OSError(f"Could not unlock the folder: {(result.stderr or result.stdout).strip()[-300:]}")

    def is_locked(self, path: str) -> bool:
        """Locked = we ourselves can't list it (the deny entry covers this process too)."""
        try:
            with os.scandir(path):
                return False
        except PermissionError:
            return True
        except OSError:
            return False  # gone or unreachable: not something to repair


def _known_roots() -> list:
    """Folders that must never be locked themselves (their subfolders are fine)."""
    home = Path.home()
    env = os.environ
    roots = [home, home / "Desktop", home / "Documents", home / "Downloads", home / "Pictures",
             home / "Music", home / "Videos", home / "OneDrive", home / "AppData"]
    for var in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "ProgramW6432", "OneDrive"):
        if env.get(var):
            roots.append(Path(env[var]))
    return roots


def _no_go_trees() -> list:
    """Folders whose WHOLE tree is off limits (system files, programs, app data)."""
    env = os.environ
    trees = [Path.home() / "AppData"]
    for var in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "ProgramW6432"):
        if env.get(var):
            trees.append(Path(env[var]))
    return trees


def _norm(path) -> str:
    return os.path.normcase(os.path.abspath(str(path))).rstrip("\\/")


def validate(path, data_dir=None) -> tuple:
    """(normalized path, "") or ("", reason it can't be locked)."""
    raw = str(path or "").strip().strip('"')
    if not raw:
        return "", "Choose a folder."
    p = Path(raw)
    if not p.is_dir():
        return "", "That folder doesn't exist."
    resolved = os.path.abspath(raw)
    if os.path.ismount(resolved) or Path(resolved).parent == Path(resolved):
        return "", "A whole drive can't be locked. Choose a folder on it."
    try:
        if p.is_symlink() or (sys.platform == "win32" and os.path.islink(resolved)):
            return "", "That is a link to another folder. Lock the real folder instead."
    except OSError:
        pass
    target = _norm(resolved)
    if any(target == _norm(r) for r in _known_roots()):
        return "", "That is a Windows or user system folder. Lock a folder inside it instead."
    for tree in _no_go_trees() + ([Path(data_dir)] if data_dir else []):
        t = _norm(tree)
        if target == t or target.startswith(t + os.sep):
            return "", "Folders that Windows, programs or Gatekeeper itself need can't be locked."
        if t.startswith(target + os.sep):
            return "", "That folder contains files Windows, programs or Gatekeeper need. Choose another one."
    here = _norm(Path(sys.executable).parent)
    if here == target or here.startswith(target + os.sep):
        return "", "That folder contains Gatekeeper itself."
    return resolved, ""


class FolderLocker:
    def __init__(self, ctx, backend=None):
        self.ctx = ctx
        self.backend = backend or IcaclsBackend()
        self._lock = threading.RLock()  # the guard thread and the dashboard both use this

    # -- stored list ----------------------------------------------------------------------------
    def entries(self) -> list:
        try:
            items = json.loads(self.ctx.db.get_setting(SETTING, "[]"))
        except (TypeError, ValueError):
            return []
        return [i for i in items if isinstance(i, dict) and i.get("path")]

    def _save(self, items) -> None:
        self.ctx.db.set_setting(SETTING, json.dumps(items))

    def _find(self, items, path):
        key = _norm(path)
        return next((i for i in items if _norm(i["path"]) == key), None)

    # -- actions --------------------------------------------------------------------------------
    def add(self, path) -> str:
        """Start protecting a folder and lock it now. Returns the stored path; ValueError if refused."""
        resolved, error = validate(path, self.ctx.directory)
        if error:
            raise ValueError(error)
        with self._lock:
            items = self.entries()
            for other in items:
                a, b = _norm(other["path"]), _norm(resolved)
                if a == b:
                    raise ValueError("That folder is already locked.")
                if b.startswith(a + os.sep) or a.startswith(b + os.sep):
                    raise ValueError("That folder is inside (or contains) a folder that is already locked.")
            self._apply(resolved, True)
            items.append({"path": resolved, "locked": True})
            self._save(items)
        self.ctx.audit.record("folder_added", resolved)
        return resolved

    def remove(self, path) -> None:
        """Stop protecting a folder (it is unlocked first)."""
        with self._lock:
            items = self.entries()
            item = self._find(items, path)
            if item is None:
                return
            self._apply(item["path"], False)
            items.remove(item)
            self._save(items)
        self.ctx.audit.record("folder_removed", item["path"])

    def set_locked(self, path, locked: bool) -> None:
        with self._lock:
            items = self.entries()
            item = self._find(items, path)
            if item is None:
                raise ValueError("That folder is not in the list.")
            self._apply(item["path"], locked)
            item["locked"] = locked
            self._save(items)
        self.ctx.audit.record("folder_locked" if locked else "folder_unlocked", item["path"])

    def relock_all(self, reason: str = "") -> int:
        """Lock every unlocked folder again (Windows locked, idle). Returns how many."""
        count = 0
        for item in self.entries():
            if not item.get("locked"):
                try:
                    self.set_locked(item["path"], True)
                    count += 1
                except (OSError, ValueError) as exc:
                    log.warning("could not re-lock %s: %s", item["path"], exc)
        if count:
            self.ctx.audit.record("folders_relocked", f"{count} folder(s){': ' + reason if reason else ''}")
        return count

    def enforce(self) -> int:
        """Put back locks removed behind Gatekeeper's back. Returns how many were repaired."""
        if self.ctx.dev:
            return 0
        repaired = 0
        for item in self.entries():
            if item.get("locked") and os.path.isdir(item["path"]) and not self.backend.is_locked(item["path"]):
                try:
                    with self._lock:
                        self.backend.lock(item["path"])
                    repaired += 1
                    self.ctx.audit.record("folder_lock_restored", item["path"])
                except OSError as exc:
                    log.warning("could not restore the lock on %s: %s", item["path"], exc)
        return repaired

    def status(self) -> list:
        """[(path, state)] for the dashboard: locked / unlocked / missing."""
        # Reading a locked folder's attributes is still allowed, so exists() works on locked folders.
        return [(i["path"], "missing" if not os.path.exists(i["path"]) else "locked" if i.get("locked") else "unlocked")
                for i in self.entries()]

    def _apply(self, path: str, lock: bool) -> None:
        if self.ctx.dev:
            log.info("[DEV] would %s folder %s; permissions untouched", "lock" if lock else "unlock", path)
            return
        (self.backend.lock if lock else self.backend.unlock)(path)


def release_everywhere(dirs, backend=None) -> int:
    """Uninstaller: unlock every folder any user locked (runs as Administrator)."""
    from .db import Database
    backend = backend or IcaclsBackend()
    released = 0
    for d in dirs:
        db = Database(Path(d) / "gatekeeper.db")
        try:
            try:
                items = json.loads(db.get_setting(SETTING, "[]"))
            except (TypeError, ValueError):
                items = []
            for item in items:
                if isinstance(item, dict) and item.get("path") and os.path.isdir(item["path"]):
                    try:
                        backend.unlock(item["path"])
                        released += 1
                    except OSError as exc:
                        log.warning("could not unlock %s: %s", item["path"], exc)
        finally:
            db.close()
    return released
