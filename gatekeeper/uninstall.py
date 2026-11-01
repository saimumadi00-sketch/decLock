"""Password check run by the uninstaller (`gatekeeper confirm-uninstall`).

The uninstaller runs elevated, and Inno Setup cannot run a program as the original (non-admin)
user during uninstall. So the check cannot rely on %APPDATA% pointing at the right profile: it
looks for a Gatekeeper data folder in every Windows profile and accepts the password of any
user who set one. If nobody set a password, there is nothing to protect and uninstall is allowed.
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


class UninstallGate:
    """Checks a password against every protected Gatekeeper install found on this PC."""

    def __init__(self, dirs):
        self.stores = []  # (db, audit) for each folder whose owner set a password
        for d in dirs:
            db = Database(d / DB_NAME)
            if auth.has_password(db):
                self.stores.append((db, AuditLog(db, d / "audit.head")))
            else:
                db.close()

    @property
    def protected(self) -> bool:
        return bool(self.stores)

    def lockout(self) -> float:
        """Seconds to wait: only while EVERY store is locked out (any open one may be tried)."""
        return min((auth.lockout_remaining(db) for db, _ in self.stores), default=0.0)

    def verify(self, password: str) -> bool:
        open_stores = [(db, a) for db, a in self.stores if auth.lockout_remaining(db) <= 0]
        for db, audit in open_stores:
            if auth.verify_password(db, password):
                return auth.check_password(db, password, audit)  # resets that store's failure count
        for db, audit in open_stores:  # wrong for everyone: count the failure everywhere (throttling)
            auth.check_password(db, password, audit)
        return False

    def record(self, event: str, detail: str = "") -> None:
        for _, audit in self.stores:
            audit.record(event, detail)

    def close(self) -> None:
        for db, _ in self.stores:
            db.close()


def confirm_uninstall(ask) -> bool:
    """True when uninstalling may go ahead. `ask(gate)` shows the prompt and returns its answer."""
    gate = UninstallGate(candidate_dirs(data_dir()))
    try:
        if not gate.protected:
            return True
        allowed = ask(gate)
        gate.record("uninstall_allowed" if allowed else "uninstall_refused")
        return allowed
    finally:
        gate.close()
