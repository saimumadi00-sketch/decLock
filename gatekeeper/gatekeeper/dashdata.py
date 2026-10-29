"""Tk-free logic behind the desktop dashboard, so it can be unit-tested without a display.

Everything the GUI changes goes through here (or through the same db/auth/audit objects the CLI
uses), so the CLI and the dashboard always agree on rules, limits and audit entries.
"""

import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psutil

from . import auth
from .config import PROTECTED_PROCESSES
from .matcher import THRESHOLD_RANGE, face_unlock_enabled, get_threshold, get_timeout
from .usb import UsbPolicy

AUTOLOCK_KEY = "ui_autolock_minutes"
DEFAULT_AUTOLOCK = 5.0

# -- app names -----------------------------------------------------------------------------


def normalize_exe(name: str) -> str:
    """'C:\\Apps\\Chrome.EXE' -> 'chrome.exe'; 'notepad' -> 'notepad.exe'."""
    name = os.path.basename(name.strip().strip('"').replace("\\", "/")).lower()
    if not name:
        return ""
    return name if "." in name else name + ".exe"


def validate_app(name: str):
    """Return (normalized_name, error). Exactly one of them is empty."""
    normalized = normalize_exe(name)
    if not normalized:
        return "", "Enter the program's name, for example chrome.exe."
    if normalized in PROTECTED_PROCESSES:
        return "", f"{normalized} is protected and cannot be locked (it could lock you out of Windows)."
    return normalized, ""


def locked_apps_detailed(db) -> list:
    with db.lock:
        rows = db.conn.execute("SELECT name, added_at FROM locked_apps ORDER BY name").fetchall()
    return [(r["name"], local_time(r["added_at"])) for r in rows]


def running_apps(exclude=()) -> list:
    """Names of running programs that could be locked, for the 'pick a running app' list."""
    names = set()
    for proc in psutil.process_iter(["name"]):
        try:
            name = (proc.info["name"] or "").lower()
        except psutil.Error:
            continue
        if name.endswith(".exe") and name not in PROTECTED_PROCESSES and name not in exclude:
            names.add(name)
    return sorted(names)


# -- audit log views -----------------------------------------------------------------------

EVENT_LABELS = {
    "blocked": "App blocked", "unlocked": "Unlocked", "denied": "Access denied",
    "bad_password": "Wrong password", "lockout": "Lockout started", "face_unlock": "Face unlock",
    "face_failed": "Face not recognised", "face_unavailable": "Face unavailable",
    "guard_start": "Protection started", "guard_stop": "Protection stopped",
    "unclean_shutdown": "Unclean shutdown", "tamper_detected": "Log tampering detected",
    "usb_blocked": "USB storage blocked", "usb_allowed": "USB storage allowed",
    "usb_blocked_dev": "USB block (dev, simulated)", "usb_allowed_dev": "USB allow (dev, simulated)",
    "usb_storage_seen": "USB drive seen", "usb_policy_restored": "USB block restored",
    "usb_enforce_failed": "USB block repair failed", "idle_lock": "Idle lock",
    "manual_lock": "Locked manually", "password_set": "Password set", "app_added": "App locked",
    "app_removed": "App unlocked (removed)", "face_enrolled": "Face enrolled",
    "face_cleared": "Face data deleted", "log_pruned": "Old log entries removed",
    "log_reset": "Log chain reset", "released_manually": "Frozen apps released",
    "released_on_exit": "Frozen apps released on exit", "enforce_failed": "Could not suspend app",
    "dashboard_login": "Dashboard login", "dashboard_locked": "Dashboard locked",
}
GOOD = {"unlocked", "face_unlock", "guard_start", "password_set", "face_enrolled", "dashboard_login",
        "usb_blocked", "app_added"}
BAD = {"denied", "bad_password", "lockout", "tamper_detected", "face_failed", "enforce_failed",
       "usb_enforce_failed"}
WARN = {"blocked", "unclean_shutdown", "usb_storage_seen", "usb_policy_restored", "face_unavailable",
        "idle_lock_failed", "manual_lock_failed"}


def describe(event: str) -> str:
    return EVENT_LABELS.get(event) or event.replace("_", " ").capitalize()


def severity(event: str) -> str:
    return "good" if event in GOOD else "bad" if event in BAD else "warn" if event in WARN else "info"


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def local_time(ts: str) -> str:
    try:
        return _parse(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ts


def _cutoff(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")


def query_events(db, event=None, text: str = "", hours=None, limit: int = 500) -> list:
    """Newest first. `text` matches the event name or detail, case-insensitively."""
    sql, params = "SELECT id, ts, event, detail FROM audit_log WHERE 1=1", []
    if event:
        sql += " AND event = ?"
        params.append(event)
    if text.strip():
        sql += " AND instr(lower(event || ' ' || detail), ?) > 0"
        params.append(text.strip().lower())
    if hours:
        sql += " AND ts >= ?"
        params.append(_cutoff(hours))
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with db.lock:
        return [dict(r) for r in db.conn.execute(sql, params).fetchall()]


def count_events(db) -> int:
    with db.lock:
        return db.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]


def event_types(db) -> list:
    with db.lock:
        return [r["event"] for r in db.conn.execute("SELECT DISTINCT event FROM audit_log ORDER BY event")]


def counts_since(db, hours: float) -> dict:
    with db.lock:
        rows = db.conn.execute("SELECT event, COUNT(*) AS n FROM audit_log WHERE ts >= ? GROUP BY event",
                               (_cutoff(hours),)).fetchall()
    return {r["event"]: r["n"] for r in rows}


def activity_by_day(db, days: int = 7, today=None) -> list:
    """[{'date': date, 'unlocked': n, 'denied': n, 'blocked': n}], oldest first, local days."""
    today = (today or datetime.now().astimezone()).date()
    start = today - timedelta(days=days - 1)
    buckets = {start + timedelta(days=i): {"unlocked": 0, "denied": 0, "blocked": 0} for i in range(days)}
    since = datetime.combine(start, datetime.min.time()).astimezone().astimezone(timezone.utc)
    with db.lock:
        rows = db.conn.execute(
            "SELECT ts, event FROM audit_log WHERE ts >= ? AND event IN ('unlocked','denied','blocked')",
            (since.isoformat(timespec="seconds"),)).fetchall()
    for r in rows:
        day = _parse(r["ts"]).astimezone().date()
        if day in buckets:
            buckets[day][r["event"]] += 1
    return [{"date": d, **counts} for d, counts in buckets.items()]


# -- status ----------------------------------------------------------------------------------


def usb_status(ctx) -> str:
    try:
        return UsbPolicy(ctx).status()
    except Exception:  # no winreg off Windows, or registry unreadable
        return "unknown"


def autolock_minutes(db) -> float:
    return float(db.get_setting(AUTOLOCK_KEY, DEFAULT_AUTOLOCK))


def summary(ctx) -> dict:
    ok, bad = ctx.audit.verify()
    with ctx.db.lock:
        samples = ctx.db.conn.execute("SELECT COUNT(*) FROM face_samples").fetchone()[0]
    last = query_events(ctx.db, limit=1)
    return {
        "dev": ctx.dev,
        "apps": ctx.db.list_apps(),
        "usb_status": usb_status(ctx),
        "usb_wanted": UsbPolicy(ctx).wanted(),
        "idle_minutes": float(ctx.db.get_setting("idle_lock_minutes", 0)),
        "face_enabled": face_unlock_enabled(ctx.db),
        "face_samples": samples,
        "chain_ok": ok,
        "chain_bad": bad,
        "last24": counts_since(ctx.db, 24),
        "last_event": last[0] if last else None,
    }


# -- validated setters (same rules and audit entries as the CLI) ---------------------------------


def _number(value, low, high, label) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a number.") from None
    if not low <= number <= high:
        raise ValueError(f"{label} must be between {low:g} and {high:g}.")
    return number


def set_idle_minutes(ctx, value) -> float:
    minutes = _number(value, 0, 1440, "Idle minutes")
    ctx.db.set_setting("idle_lock_minutes", minutes)
    ctx.audit.record("idle_lock_set", str(minutes))
    return minutes


def set_retention_days(ctx, value) -> int:
    days = int(_number(value, 0, 3650, "Retention days"))
    ctx.db.set_setting("log_retention_days", days)
    ctx.audit.record("retention_set", str(days))
    return days


def set_autolock_minutes(ctx, value) -> float:
    minutes = _number(value, 0, 240, "Dashboard auto-lock minutes")
    ctx.db.set_setting(AUTOLOCK_KEY, minutes)
    ctx.audit.record("dashboard_autolock_set", str(minutes))
    return minutes


def set_face_options(ctx, enabled: bool, threshold, timeout) -> str:
    """Validate and save all face settings together. Returns a warning (possibly empty)."""
    threshold = _number(threshold, *THRESHOLD_RANGE, "Threshold")
    timeout = _number(timeout, 2, 30, "Timeout")
    ctx.db.set_setting("face_threshold", threshold)
    ctx.db.set_setting("face_timeout", timeout)
    ctx.db.set_setting("face_unlock", "1" if enabled else "0")
    ctx.audit.record("face_threshold_set", str(threshold))
    ctx.audit.record("face_timeout_set", str(timeout))
    ctx.audit.record("face_unlock_enabled" if enabled else "face_unlock_disabled")
    if threshold < 0.363:
        return "Below SFace's published 0.363 threshold: false accepts become likely."
    return ""


def face_options(db) -> tuple:
    return face_unlock_enabled(db), get_threshold(db), get_timeout(db)


def create_password(ctx, new: str, repeat: str):
    """First-run password. Returns (ok, message)."""
    if auth.has_password(ctx.db):
        return False, "A password is already set."
    if new != repeat:
        return False, "The two passwords differ."
    try:
        auth.set_password(ctx.db, new)
    except ValueError as exc:
        return False, str(exc)
    ctx.audit.record("password_set", "first run (dashboard)")
    return True, ""


def change_password(ctx, current: str, new: str, repeat: str):
    """Returns (ok, message). Wrong 'current' counts toward the same lockout as everywhere else."""
    wait = auth.lockout_remaining(ctx.db)
    if wait > 0:
        return False, f"Too many wrong passwords. Try again in {int(wait) + 1}s."
    if not auth.check_password(ctx.db, current, ctx.audit):
        ctx.audit.record("bad_password", "change_password")
        return False, "The current password is wrong."
    if new != repeat:
        return False, "The two new passwords differ."
    try:
        auth.set_password(ctx.db, new)
    except ValueError as exc:
        return False, str(exc)
    ctx.audit.record("password_set", "changed from dashboard")
    return True, "Password changed."


# -- one guard per data folder -----------------------------------------------------------------


class SingleInstance:
    """Process-wide lock so the dashboard and a headless `run` can never both guard apps."""

    def __init__(self, directory, name: str = "gatekeeper.lock"):
        self.path = Path(directory) / name
        self._fh = None

    def acquire(self, wait: float = 0) -> bool:
        deadline = time.monotonic() + wait
        while True:
            fh = open(self.path, "a+")
            try:
                if os.name == "nt":
                    import msvcrt
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                fh.close()
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.25)
                continue
            self._fh = fh
            return True

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._fh, fcntl.LOCK_UN)
        except OSError:
            pass
        self._fh.close()
        self._fh = None
