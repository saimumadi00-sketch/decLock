"""Per-app lock schedules: "lock only between HH:MM and HH:MM". No schedule means always locked.

Stored in the settings table as `schedule:<exe>` = "HH:MM-HH:MM@<offset>". A window that ends
before it starts (22:00-06:00) runs overnight.

The "@<offset>" part is the PC's UTC offset in minutes when the schedule was saved (e.g. @+360 for
Dhaka). Schedules are checked against that fixed offset, not the current time zone: a standard user
may change the time zone, and with plain local time that would shift "now" out of the lock window.
(Changing the clock itself needs Administrator.) Schedules saved by older versions have no offset
and keep using local time until they are saved again.
"""

import re
from datetime import datetime, timedelta, timezone

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


def _split(stored: str):
    """'09:00-17:00@+360' -> ('09:00-17:00', 360); no or bad offset -> (window, None)."""
    window, _, offset = (stored or "").partition("@")
    try:
        minutes = int(offset) if offset else None
    except ValueError:
        minutes = None
    if minutes is not None and not -14 * 60 <= minutes <= 14 * 60:
        minutes = None
    return window, minutes


def local_offset_minutes() -> int:
    """This PC's current UTC offset, in minutes."""
    return int(datetime.now().astimezone().utcoffset().total_seconds() // 60)


def get(db, name: str) -> str:
    """The stored window for one app ("HH:MM-HH:MM"), or "" (always locked)."""
    return _split(db.get_setting(PREFIX + name, "") or "")[0]


def set_window(db, name: str, window: str, offset=None) -> None:
    """Store a canonical window (see format_window), pinned to the current UTC offset; "" clears it."""
    if window:
        offset = local_offset_minutes() if offset is None else offset
        window = f"{window}@{offset:+d}"
    db.set_setting(PREFIX + name, window)


def is_active(window: str, now=None) -> bool:
    """True when the app should be locked at `now` (the time in the schedule's own zone; by default
    the real time at the offset it was saved with). Unparseable windows fail safe (locked)."""
    window, offset = _split(window)
    if now is None and offset is not None:
        now = (datetime.now(timezone.utc) + timedelta(minutes=offset)).replace(tzinfo=None)
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
    return {name for name in db.list_apps() if is_active(db.get_setting(PREFIX + name, "") or "", now)}
