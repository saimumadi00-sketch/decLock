"""Per-app lock schedules: "lock only between HH:MM and HH:MM". No schedule means always locked.

Stored in the settings table as `schedule:<exe>` = "HH:MM-HH:MM". A window that ends before it
starts (22:00-06:00) runs overnight.
"""

import re
from datetime import datetime

PREFIX = "schedule:"
_PATTERN = re.compile(  # "H:MM-HH:MM" with 1-2 digit hours
    r"^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})$")


def _minutes(hour: str, minute: str) -> int:
    """"HH", "MM" -> minutes since midnight, validated."""
    h, m = int(hour), int(minute)
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError("Times must look like 09:00 (24-hour clock).")
    return h * 60 + m


def parse(text: str):
    """'22:00-06:00' -> (1320, 360). Empty text -> None (always). Raises ValueError if malformed."""
    text = (text or "").strip()
    if not text:
        return None
    match = _PATTERN.match(text.replace(" ", ""))  # tolerate "22:00 - 06:00"
    if not match:
        raise ValueError("Times must look like 09:00 (24-hour clock).")
    start, end = _minutes(match[1], match[2]), _minutes(match[3], match[4])
    if start == end:
        raise ValueError("Start and end times must differ.")
    return start, end


def format_window(start: str, end: str) -> str:
    """Validate two HH:MM strings and return the canonical 'HH:MM-HH:MM'."""
    a, b = parse(f"{start.strip()}-{end.strip()}")
    return f"{a // 60:02d}:{a % 60:02d}-{b // 60:02d}:{b % 60:02d}"


def get(db, name: str) -> str:
    """The stored window for one app, or "" (always locked)."""
    return db.get_setting(PREFIX + name, "") or ""


def set_window(db, name: str, window: str) -> None:
    """Store a canonical window (see format_window), or "" to clear it."""
    db.set_setting(PREFIX + name, window)


def is_active(window: str, now=None) -> bool:
    """True when the app should be locked at `now`. Unparseable windows fail safe (locked)."""
    try:
        parsed = parse(window)
    except ValueError:
        return True
    if parsed is None:
        return True
    now = now or datetime.now()
    current = now.hour * 60 + now.minute
    start, end = parsed
    # Same-day window: start <= now < end. Overnight window (end < start): after start OR before end.
    return start <= current < end if start < end else current >= start or current < end


def locked_now(db, now=None) -> set:
    """Locked apps whose schedule is active right now (what the guard enforces)."""
    return {name for name in db.list_apps() if is_active(get(db, name), now)}
