"""Tk-free logic behind the desktop dashboard, so it can be unit-tested without a display.

Everything the GUI changes goes through here (or through the same db/auth/audit objects the CLI
uses), so the CLI and the dashboard always agree on rules, limits and audit entries.
"""

import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psutil

from . import auth, enrolment, schedule
from .config import PROTECTED_PROCESSES
from .matcher import (THRESHOLD_RANGE, TIMEOUT_RANGE, WEAK_THRESHOLD, enrolment_current, face_unlock_enabled,
                      get_threshold, get_timeout)
from .usb import UsbPolicy

AUTOLOCK_KEY = "ui_autolock_minutes"   # settings key: dashboard window auto-lock
DEFAULT_AUTOLOCK = 5.0

# -- app names -----------------------------------------------------------------------------


def normalize_exe(name: str) -> str:
    """'C:\\Apps\\Chrome.EXE' -> 'chrome.exe'; 'notepad' -> 'notepad.exe'."""
    # The guard matches on the bare, lower-case process name, so store names the same way.
    name = os.path.basename(name.strip().strip('"').replace("\\", "/")).lower()
    if not name:
        return ""
    return name if "." in name else name + ".exe"


def validate_app(name: str):
    """Return (normalized_name, error). Exactly one of them is empty."""
    normalized = normalize_exe(name)
    if not normalized:
        return "", "Enter the program's name, for example chrome.exe."
    if normalized in PROTECTED_PROCESSES:  # locking these could make Windows unusable
        return "", f"{normalized} is protected and cannot be locked (it could lock you out of Windows)."
    return normalized, ""


def lock_app(ctx, raw: str):
    """Validate and lock one app (typed name or full .exe path). Returns (name, error) like validate_app.

    It also fingerprints the program file (the browsed .exe, or copies running right now), so a
    renamed copy of it is recognised too (see identity.py)."""
    from .identity import Identifier, learn_from_running
    name, error = validate_app(raw)
    if error:
        return name, error
    ctx.db.add_app(name)
    ctx.audit.record("app_added", name)
    path = raw.strip().strip('"')
    if os.path.isfile(path):
        Identifier(ctx.db).learn(name, path)
    else:
        learn_from_running(ctx.db, [name])
    return name, ""


def locked_apps_detailed(db) -> list:
    """[(name, locked_since_local_time)] sorted by name."""
    with db.lock:
        rows = db.conn.execute("SELECT name, added_at FROM locked_apps ORDER BY name").fetchall()
    return [(r["name"], local_time(r["added_at"])) for r in rows]


# One-click groups for the "Add a preset" menu.
PRESETS = {
    "Browsers": ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"],
    "Games": ["steam.exe", "epicgameslauncher.exe", "minecraft.exe", "valorant.exe", "robloxplayerbeta.exe"],
    "Chat apps": ["discord.exe", "telegram.exe", "whatsapp.exe", "slack.exe", "teams.exe"],
    "Office": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"],
}


def app_stats(db) -> dict:
    """{exe: {'last': local time of the last blocked start, 'blocked': n, 'denied': n, 'unlocked': n}}."""
    with db.lock:
        rows = db.conn.execute("SELECT ts, event, detail FROM audit_log WHERE event IN "
                               "('blocked','denied','unlocked') ORDER BY id").fetchall()
    stats = {}
    for r in rows:
        # The guard writes these details as "<exe> pid=..." / "<exe> (n process(es))".
        name = (r["detail"] or "").split(" ")[0].lower()
        entry = stats.setdefault(name, {"last": "", "blocked": 0, "denied": 0, "unlocked": 0})
        entry[r["event"]] += 1
        if r["event"] == "blocked":
            entry["last"] = local_time(r["ts"])  # rows are oldest first, so this ends on the newest
    return stats


def locked_apps_overview(db) -> list:
    """[(name, locked_since, schedule_text, last_attempt, denied_count)] for the Locked apps table."""
    stats = app_stats(db)
    rows = []
    for name, added in locked_apps_detailed(db):
        info = stats.get(name, {})
        rows.append((name, added, schedule.get(db, name) or "Always",
                     info.get("last") or "never", info.get("denied", 0)))
    return rows


def top_apps(db, limit: int = 5) -> list:
    """[(exe, attempts)] most-attempted first (attempts = blocked starts)."""
    ranked = sorted(((n, s["blocked"]) for n, s in app_stats(db).items() if s["blocked"]),
                    key=lambda item: -item[1])
    return ranked[:limit]


def running_apps(exclude=()) -> list:
    """Names of running programs that could be locked, for the 'pick a running app' list."""
    names = set()
    for proc in psutil.process_iter(["name"]):
        try:
            name = (proc.info["name"] or "").lower()
        except psutil.Error:  # the process exited while we were looking
            continue
        if name.endswith(".exe") and name not in PROTECTED_PROCESSES and name not in exclude:
            names.add(name)
    return sorted(names)


def face_sample_count(db) -> int:
    """How many face samples are enrolled (counting needs no decryption key)."""
    with db.lock:
        return db.conn.execute("SELECT COUNT(*) FROM face_samples").fetchone()[0]


# -- audit log views -----------------------------------------------------------------------

# Friendly names for the raw event ids stored in the audit log.
EVENT_LABELS = {
    "blocked": "App blocked", "unlocked": "Unlocked", "denied": "Access denied",
    "bad_password": "Wrong password", "lockout": "Lockout started", "face_unlock": "Face unlock",
    "face_failed": "Face not recognised", "face_unavailable": "Face unavailable",
    "guard_start": "Protection started", "guard_stop": "Protection stopped",
    "unclean_shutdown": "Unclean shutdown", "tamper_detected": "Log tampering detected",
    "env_ignored": "Data-folder override ignored", "setup_blocked": "Setup refused (data missing)",
    "relock": "Open apps re-locked", "relocked": "Open app frozen", "held": "Kept frozen (not unlocked)",
    "relock_set": "Re-lock time changed",
    "face_lockout": "Face unlock paused", "face_virtual_camera": "Face refused: software camera",
    "face_camera_allowed": "Camera allowed for face unlock",
    "usb_temporary_allow": "USB allowed temporarily", "usb_temporary_allow_dev": "USB temporary allow (dev)",
    "usb_temporary_allow_ended": "USB blocked again",
    "folder_added": "Folder locked (added)", "folder_removed": "Folder no longer protected",
    "folder_locked": "Folder locked", "folder_unlocked": "Folder unlocked",
    "folders_relocked": "Folders re-locked", "folder_lock_restored": "Folder lock restored", "usb_reblock_task_failed": "USB re-block task not created",
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
    "app_schedule_set": "App schedule changed", "dashboard_theme_set": "Theme changed",
    "dashboard_grace_set": "Confirm grace changed",
}
# Severity buckets drive row colours and the Good / Warnings / Problems filter chips.
GOOD = {"folder_locked", "folder_added", "unlocked", "face_unlock", "guard_start", "password_set", "face_enrolled", "dashboard_login",
        "usb_blocked", "app_added"}
BAD = {"setup_blocked", "face_lockout", "face_virtual_camera", "denied", "bad_password", "lockout", "tamper_detected", "face_failed", "enforce_failed",
       "usb_enforce_failed"}
WARN = {"folder_unlocked", "folder_lock_restored", "usb_temporary_allow", "usb_reblock_task_failed", "blocked", "relocked", "held", "unclean_shutdown", "env_ignored", "usb_storage_seen", "usb_policy_restored", "face_unavailable",
        "idle_lock_failed", "manual_lock_failed"}
SEVERITY_EVENTS = {"good": GOOD, "bad": BAD, "warn": WARN}


def describe(event: str) -> str:
    return EVENT_LABELS.get(event) or event.replace("_", " ").capitalize()


def severity(event: str) -> str:
    return "good" if event in GOOD else "bad" if event in BAD else "warn" if event in WARN else "info"


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def local_time(ts: str) -> str:
    """Stored UTC ISO timestamp -> local 'YYYY-MM-DD HH:MM:SS' (unparseable text is shown as is)."""
    try:
        return _parse(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ts


def _cutoff(hours: float) -> str:
    """UTC ISO timestamp `hours` ago. ISO strings in one timezone sort like times, so SQL can compare them."""
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")


def _local_midnight_utc(day) -> datetime:
    """Start of a local calendar day, as a UTC datetime."""
    return datetime.combine(day, datetime.min.time()).astimezone().astimezone(timezone.utc)


def query_events(db, event=None, text: str = "", hours=None, limit: int = 500, day=None, severity=None) -> list:
    """Newest first. `text` matches the event name or detail, case-insensitively.

    All filters run in SQL, before LIMIT, so a filter never hides matches beyond the limit.
    """
    sql, params = "SELECT id, ts, event, detail FROM audit_log WHERE 1=1", []
    if event:
        sql += " AND event = ?"
        params.append(event)
    if severity:
        events = sorted(SEVERITY_EVENTS.get(severity, ()))
        sql += f" AND event IN ({','.join('?' * len(events)) or 'NULL'})"  # one ? per event, still parameterised
        params += events
    if text.strip():
        # instr() instead of LIKE so % and _ typed by the user are plain characters.
        sql += " AND instr(lower(event || ' ' || detail), ?) > 0"
        params.append(text.strip().lower())
    if hours:
        sql += " AND ts >= ?"
        params.append(_cutoff(hours))
    if day:
        # Next local midnight, not start + 24h: daylight-saving days are 23 or 25 hours long.
        sql += " AND ts >= ? AND ts < ?"
        params += [_local_midnight_utc(day).isoformat(timespec="seconds"),
                   _local_midnight_utc(day + timedelta(days=1)).isoformat(timespec="seconds")]
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with db.lock:
        return [dict(r) for r in db.conn.execute(sql, params).fetchall()]


def count_events(db) -> int:
    with db.lock:
        return db.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]


def event_types(db) -> list:
    """Every event id that occurs in the log (fills the event-type dropdown)."""
    with db.lock:
        return [r["event"] for r in db.conn.execute("SELECT DISTINCT event FROM audit_log ORDER BY event")]


def counts_since(db, hours: float) -> dict:
    """{event: count} over the last `hours`."""
    with db.lock:
        rows = db.conn.execute("SELECT event, COUNT(*) AS n FROM audit_log WHERE ts >= ? GROUP BY event",
                               (_cutoff(hours),)).fetchall()
    return {r["event"]: r["n"] for r in rows}


def activity_by_day(db, days: int = 7, today=None) -> list:
    """[{'date': date, 'unlocked': n, 'denied': n, 'blocked': n}], oldest first, local days."""
    today = (today or datetime.now().astimezone()).date()
    start = today - timedelta(days=days - 1)
    # Pre-fill every day with zeros so quiet days still get a (zero-height) bar.
    buckets = {start + timedelta(days=i): {"unlocked": 0, "denied": 0, "blocked": 0} for i in range(days)}
    with db.lock:
        rows = db.conn.execute(
            "SELECT ts, event FROM audit_log WHERE ts >= ? AND event IN ('unlocked','denied','blocked')",
            (_local_midnight_utc(start).isoformat(timespec="seconds"),)).fetchall()
    for r in rows:
        day = _parse(r["ts"]).astimezone().date()  # bucket by the LOCAL date
        if day in buckets:
            buckets[day][r["event"]] += 1
    return [{"date": d, **counts} for d, counts in buckets.items()]


# -- status ----------------------------------------------------------------------------------


def problems_since(db, hours: float = 24) -> int:
    """Number of 'Problems' events (wrong passwords, denials, ...) in the last `hours`.
    Counts exactly what the log's Problems filter shows, so the Dashboard tile and the log agree."""
    counts = counts_since(db, hours)
    return sum(n for event, n in counts.items() if event in BAD)


def usb_status(ctx) -> str:
    try:
        return UsbPolicy(ctx).status()
    except Exception:  # no winreg off Windows, or registry unreadable
        return "unknown"


def autolock_minutes(db) -> float:
    return float(db.get_setting(AUTOLOCK_KEY, DEFAULT_AUTOLOCK))


def summary(ctx) -> dict:
    """Everything the Dashboard page shows, in one call."""
    ok, bad = ctx.audit.verify()
    return {
        "apps": ctx.db.list_apps(),
        "usb_status": usb_status(ctx),
        "usb_wanted": UsbPolicy(ctx).wanted(),
        "usb_alert": usb_alert(ctx),
        "idle_minutes": float(ctx.db.get_setting("idle_lock_minutes", 0)),
        "face_enabled": face_unlock_enabled(ctx.db),
        "face_samples": face_sample_count(ctx.db),
        "face_current": enrolment_current(ctx.db),  # False: samples from older models, re-enrol needed
        "chain_ok": ok,
        "chain_bad": bad,
        "problems24": problems_since(ctx.db, 24),
    }


# -- validated setters (same rules and audit entries as the CLI) ---------------------------------


def _number(value, low, high, label) -> float:
    """Parse user input as a number in [low, high] or raise ValueError with a readable message."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a number.") from None
    if not low <= number <= high:  # also rejects NaN (every comparison with NaN is False)
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


def relock_minutes(db) -> float:
    from .idle import relock_minutes as current
    return current(db)


def set_relock_minutes(ctx, value) -> float:
    """Idle minutes before apps that are already open lock again (0 = only when Windows locks)."""
    from .idle import RELOCK_KEY
    minutes = _number(value, 0, 240, "Re-lock minutes")
    ctx.db.set_setting(RELOCK_KEY, minutes)
    ctx.audit.record("relock_set", str(minutes))
    return minutes


def set_autolock_minutes(ctx, value) -> float:
    minutes = _number(value, 0, 240, "Dashboard auto-lock minutes")
    ctx.db.set_setting(AUTOLOCK_KEY, minutes)
    ctx.audit.record("dashboard_autolock_set", str(minutes))
    return minutes


THEME_KEY, GRACE_KEY, CHECKLIST_KEY = "ui_theme", "ui_confirm_grace", "ui_checklist_dismissed"
GRACE_SECONDS = 60  # how long a password confirmation is remembered when the user opts in


def get_theme(db) -> str:
    return "dark" if db.get_setting(THEME_KEY, "light") == "dark" else "light"


def set_theme(ctx, theme: str) -> str:
    theme = "dark" if theme == "dark" else "light"  # anything unknown falls back to light
    ctx.db.set_setting(THEME_KEY, theme)
    ctx.audit.record("dashboard_theme_set", theme)
    return theme


def confirm_grace(db) -> bool:
    return db.get_setting(GRACE_KEY, "0") == "1"


def set_confirm_grace(ctx, enabled: bool) -> None:
    if confirm_grace(ctx.db) == bool(enabled):
        return  # unchanged: don't add a log entry every time Settings is saved
    ctx.db.set_setting(GRACE_KEY, "1" if enabled else "0")
    ctx.audit.record("dashboard_grace_set", "on" if enabled else "off")


def checklist(ctx) -> list:
    """First-run steps as [(label, done, page)]; the Dashboard shows them until all are done."""
    usb_done = ctx.db.get_setting("usb_choice_made", "0") == "1" or UsbPolicy(ctx).wanted()
    return [("Choose a password", auth.has_password(ctx.db), "settings"),
            ("Lock your first app", bool(ctx.db.list_apps()), "apps"),
            ("Decide on USB storage blocking", usb_done, "usb"),
            ("Enroll your face (optional)", face_sample_count(ctx.db) > 0 and enrolment_current(ctx.db), "face")]


def checklist_dismissed(db) -> bool:
    return db.get_setting(CHECKLIST_KEY, "0") == "1"


def dismiss_checklist(db) -> None:
    db.set_setting(CHECKLIST_KEY, "1")


def set_app_schedule(ctx, name: str, start: str, end: str, always: bool) -> str:
    """Save (or clear) one app's lock window. Returns the stored text ('' = always)."""
    window = "" if always else schedule.format_window(start, end)  # raises ValueError on bad times
    schedule.set_window(ctx.db, name, window)
    ctx.audit.record("app_schedule_set", f"{name} {window or 'always'}")
    return window


def add_preset(ctx, preset: str) -> list:
    """Lock every app in a preset (skipping protected ones). Returns the names newly added."""
    added = []
    existing = set(ctx.db.list_apps())
    for raw in PRESETS.get(preset, []):
        name, error = validate_app(raw)
        if error or name in existing:
            continue
        ctx.db.add_app(name)
        ctx.audit.record("app_added", f"{name} (preset {preset})")
        added.append(name)
    if added:
        from .identity import learn_from_running
        learn_from_running(ctx.db, added)  # fingerprint any of them that are open right now
    return added


def remove_app(ctx, name: str) -> bool:
    """Stop locking `name` (and forget its schedule). Same effect as `gatekeeper remove`."""
    removed = ctx.db.remove_app(name)
    schedule.set_window(ctx.db, name, "")
    if removed:
        ctx.audit.record("app_removed", name)
    return removed


def set_face_options(ctx, enabled: bool, threshold, timeout) -> str:
    """Validate and save all face settings together. Returns a warning (possibly empty)."""
    # Validate both values before saving either, so a bad timeout doesn't leave a half-saved state.
    threshold = _number(threshold, *THRESHOLD_RANGE, "Threshold")
    timeout = _number(timeout, *TIMEOUT_RANGE, "Timeout")
    ctx.db.set_setting("face_threshold", threshold)
    ctx.db.set_setting("face_timeout", timeout)
    ctx.db.set_setting("face_unlock", "1" if enabled else "0")
    ctx.audit.record("face_threshold_set", str(threshold))
    ctx.audit.record("face_timeout_set", str(timeout))
    ctx.audit.record("face_unlock_enabled" if enabled else "face_unlock_disabled")
    if threshold < WEAK_THRESHOLD:
        return f"Below {WEAK_THRESHOLD}: other people's faces start to match."
    return ""


def face_options(db) -> tuple:
    return face_unlock_enabled(db), get_threshold(db), get_timeout(db)


def create_password(ctx, new: str, repeat: str):
    """First-run password. Returns (ok, message)."""
    if auth.has_password(ctx.db):  # never let the setup screen overwrite an existing password
        return False, "A password is already set."
    if enrolment.setup_blocked(ctx.db, ctx.enrolment):  # data deleted after setup: don't let anyone re-own it
        ctx.audit.record("setup_blocked", "first-run setup refused: this user was set up before")
        return False, enrolment.BLOCKED_MESSAGE
    if new != repeat:
        return False, "The two passwords differ."
    try:
        auth.set_password(ctx.db, new)
    except ValueError as exc:
        return False, str(exc)
    ctx.audit.record("password_set", "first run (dashboard)")
    if ctx.enrolment:
        ctx.enrolment.mark()
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
    """Process-wide lock so the dashboard and a headless `run` can never both guard apps.

    It is an OS file lock on `gatekeeper.lock`, so it is released automatically if the process dies.
    """

    def __init__(self, directory, name: str = "gatekeeper.lock"):
        self.path = Path(directory) / name
        self._fh = None

    def acquire(self, wait: float = 0) -> bool:
        """Try to take the lock, retrying for up to `wait` seconds. True on success."""
        deadline = time.monotonic() + wait
        while True:
            fh = open(self.path, "a+")
            try:
                if os.name == "nt":
                    import msvcrt
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)  # lock byte 0, don't block
                else:
                    import fcntl
                    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:  # someone else holds it
                fh.close()
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.25)
                continue
            self._fh = fh
            return True

    def release(self) -> None:
        if self._fh is None:  # never acquired, or already released
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


# -- face unlock safeguards ------------------------------------------------------------------------

def blocking_cameras(db) -> list:
    """Software cameras installed on this PC that currently switch face unlock off."""
    from .matcher import virtual_cameras
    return virtual_cameras(db)


def allow_cameras(ctx, names) -> None:
    """The owner confirms these software camera names are their real camera."""
    import json
    from .matcher import CAMERA_ALLOW_KEY, allowed_cameras
    allowed = sorted(allowed_cameras(ctx.db) | set(names))
    ctx.db.set_setting(CAMERA_ALLOW_KEY, json.dumps(allowed))
    ctx.audit.record("face_camera_allowed", ", ".join(sorted(names)))


def face_pause_remaining(db) -> float:
    """Seconds face unlock is paused after too many failed face attempts (0 = not paused)."""
    return auth.face_locked_remaining(db)


# -- USB extras --------------------------------------------------------------------------------------

def usb_alert(ctx) -> str:
    try:
        return UsbPolicy(ctx).alert()
    except Exception:  # registry unreadable (or not Windows): nothing to warn about
        return ""


def usb_temporary_remaining(ctx) -> float:
    return UsbPolicy(ctx, reg=_NoRegistry()).temporary_remaining()


class _NoRegistry:
    """Reading the temporary-allow timer needs no registry access."""
    def get_start(self):
        return None

    def set_start(self, value):
        raise PermissionError("read-only")
