import base64
import hashlib
import time

import bcrypt

from .config import MIN_PASSWORD_LEN
from .db import Database

KEY = "password_hash"


def _prep(password: str) -> bytes:
    # bcrypt only uses the first 72 bytes; pre-hashing lets any length work.
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def has_password(db: Database) -> bool:
    return db.get_setting(KEY) is not None


def set_password(db: Database, password: str) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    db.set_setting(KEY, bcrypt.hashpw(_prep(password), bcrypt.gensalt(rounds=12)).decode("ascii"))


FREE_FAILURES = 5     # wrong passwords allowed before the first lockout
BASE_LOCK = 30        # seconds; doubles with every further failure
MAX_LOCK = 900


def lockout_remaining(db: Database, clock=time.time) -> float:
    return max(0.0, float(db.get_setting("locked_until", 0)) - clock())


def check_password(db: Database, password: str, audit=None, clock=time.time) -> bool:
    """verify_password plus persistent brute-force throttling (survives restarts).
    While locked out the password is not even checked, so guessing gains nothing."""
    if lockout_remaining(db, clock) > 0:
        return False
    if verify_password(db, password):
        db.set_setting("fail_count", 0)
        db.set_setting("locked_until", 0)
        return True
    failures = int(db.get_setting("fail_count", 0)) + 1
    db.set_setting("fail_count", failures)
    if failures >= FREE_FAILURES:
        seconds = min(BASE_LOCK * 2 ** (failures - FREE_FAILURES), MAX_LOCK)
        db.set_setting("locked_until", clock() + seconds)
        if audit:
            audit.record("lockout", f"{failures} failures, locked {seconds}s")
    return False


def verify_password(db: Database, password: str) -> bool:
    stored = db.get_setting(KEY)
    if stored is None:
        return False
    try:
        return bcrypt.checkpw(_prep(password), stored.encode("ascii"))
    except ValueError:
        return False
