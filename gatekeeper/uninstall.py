"""Password check run by the uninstaller (`gatekeeper confirm-uninstall`).

The uninstaller runs elevated, and Inno Setup cannot run a program as the original (non-admin)
user during uninstall. So the check cannot rely on %APPDATA% pointing at the right profile: it
looks for a Gatekeeper data folder in every Windows profile.

Uninstalling removes protection for EVERY user on the PC, so it needs the Gatekeeper password of
every user who set one (one prompt per user). Accepting any one of them would let a second user
set up their own Gatekeeper, then use that password to remove everyone's protection.
If nobody set a password, there is nothing to protect and uninstall is allowed.
"""

import os
from pathlib import Path

from . import auth
from .audit import AuditLog
from .config import APP_NAME, data_dir
from .db import Database

DB_NAME = "gatekeeper.db"


def candidate_dirs(own: Path = None, users_root: Path = None) -> list:
    """This user's data folder plus %USERPROFILE%\\AppData\\Roaming\\Gatekeeper of every profile."""
    users_root = users_root or Path(os.environ.get("SystemDrive", "C:") + "\\", "Users")
    found = [own] if own else []
    if users_root.is_dir():
        found += [p.parent for p in users_root.glob(f"*/AppData/Roaming/{APP_NAME}/{DB_NAME}")]
    unique = []
    for d in found:  # the same folder can show up twice (own folder is also under Users)
        if d and (d / DB_NAME).is_file() and all(d.resolve() != u.resolve() for u in unique):
            unique.append(d)
    return unique


def _owner(directory: Path) -> str:
    """The Windows user a data folder belongs to: ...\\Users\\<name>\\AppData\\Roaming\\Gatekeeper."""
    parts = Path(directory).parts
    try:
        return parts[-4]
    except IndexError:
        return "this user"


class UserGate:
    """One protected user's password check (what each uninstall prompt verifies against)."""

    def __init__(self, owner: str, db, audit):
        self.owner, self.db, self.audit = owner, db, audit

    def verify(self, password: str) -> bool:
        return auth.check_password(self.db, password, self.audit)  # shares that user's lockout

    def lockout(self) -> float:
        return auth.lockout_remaining(self.db)

    def record(self, event: str, detail: str = "") -> None:
        self.audit.record(event, detail)


class UninstallGate:
    """Every protected Gatekeeper install found on this PC."""

    def __init__(self, dirs):
        self.users = []  # UserGate for each folder whose owner set a password
        self._open = []
        for d in dirs:
            db = Database(d / DB_NAME)
            self._open.append(db)
            if auth.has_password(db):
                self.users.append(UserGate(_owner(d), db, AuditLog(db, d / "audit.head")))

    @property
    def protected(self) -> bool:
        return bool(self.users)

    def record(self, event: str, detail: str = "") -> None:
        for user in self.users:
            user.record(event, detail)

    def close(self) -> None:
        for db in self._open:
            db.close()


def confirm_uninstall(ask) -> bool:
    """True when uninstalling may go ahead. `ask(user_gate)` shows one prompt and returns its answer;
    it is called once per protected user and every one must succeed."""
    gate = UninstallGate(candidate_dirs(data_dir()))
    try:
        if not gate.protected:
            return True
        for user in gate.users:
            if not ask(user):
                gate.record("uninstall_refused", f"password for {user.owner} not confirmed")
                return False
        gate.record("uninstall_allowed", f"{len(gate.users)} user(s) confirmed")
        return True
    finally:
        gate.close()
