"""Checkpoints of the activity log kept where the user can't edit or delete them.

The log's hash chain and head seal live in %APPDATA%, so someone with the user's rights can
rewrite the whole log and recompute both. The enrolment folder (%ProgramData%\\Gatekeeper\\enrolled,
see enrolment.py) only lets users ADD files. About once an hour Gatekeeper adds a checkpoint there:
the id and hash of the newest log entry. Later:

  * a checkpointed entry whose hash changed      -> the log was rewritten
  * a checkpointed entry that is gone, though it is
    newer than the retention period               -> entries were deleted

A legitimate "Reset log chain" adds a reset marker; checkpoints from before the newest reset are
then ignored. Someone could add a fake reset marker too (anyone may add files), but never remove
one: a reset the owner didn't make stays visible (resets()), which is the point.

Files: <SID>.log.<id> = "<hash> <unix time of the entry>", <SID>.reset.<unix time>.
Only active in the installed build, like the enrolment markers.
"""

import logging
import os
import time
from datetime import datetime

log = logging.getLogger("gatekeeper.logwitness")

INTERVAL = 3600       # seconds between checkpoints
PRUNE_SLACK = 86400   # a day of grace around the retention cutoff
CACHE_SECONDS = 60    # the dashboard verifies every few seconds; re-read the folder at most this often


def _epoch(iso: str) -> float:
    try:
        return datetime.fromisoformat(iso).timestamp()
    except (TypeError, ValueError):
        return 0.0


class LogWitness:
    def __init__(self, enrolment, clock=time.time):
        self.enrolment, self.clock = enrolment, clock
        self._last_written = 0.0
        self._cache = None  # (time, data_version, result)

    @property
    def active(self) -> bool:
        try:
            return self.enrolment is not None and self.enrolment.active
        except Exception:
            return False

    def _files(self):
        """(checkpoints [(id, hash, ts)], resets [ts]) for this user."""
        prefix = f"{self.enrolment.sid}."
        checkpoints, resets = [], []
        for name in os.listdir(self.enrolment.folder):
            if not name.startswith(prefix):
                continue
            kind, _, rest = name[len(prefix):].partition(".")
            try:
                if kind == "log":
                    digest, ts = (self.enrolment.folder / name).read_text(encoding="ascii").split()
                    checkpoints.append((int(rest), digest, float(ts)))
                elif kind == "reset":
                    resets.append(float(rest))
            except (OSError, ValueError):
                continue  # unreadable or junk: ignore (it can't make a clean log look tampered)
        return checkpoints, resets

    def _add(self, name: str, text: str) -> None:
        path = self.enrolment.folder / f"{self.enrolment.sid}.{name}"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)  # add-only folder: new files only
        try:
            os.write(fd, text.encode("ascii"))
        finally:
            os.close(fd)

    def checkpoint(self, db, force: bool = False) -> bool:
        """Add a checkpoint of the newest entry, at most once per INTERVAL. Never raises."""
        if not self.active or (not force and self.clock() - self._last_written < INTERVAL):
            return False
        try:
            with db.lock:
                row = db.conn.execute("SELECT id, ts, hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            if row is None:
                return False
            self._add(f"log.{row['id']}", f"{row['hash']} {_epoch(row['ts']):.0f}")
            self._last_written = self.clock()
            return True
        except FileExistsError:
            self._last_written = self.clock()  # that entry is already checkpointed
            return False
        except Exception:
            log.warning("could not write a log checkpoint", exc_info=True)
            return False

    def mark_reset(self) -> None:
        """Record a legitimate reset (call just before the log is cleared). Never raises."""
        if not self.active:
            return
        try:
            self._add(f"reset.{self.clock():.0f}", "")
            self._cache = None
        except Exception:
            log.warning("could not record the log reset", exc_info=True)

    def resets(self) -> list:
        """Times (unix) the log was reset, oldest first. Each one is permanent."""
        if not self.active:
            return []
        try:
            return sorted(self._files()[1])
        except Exception:
            return []

    def verify(self, db):
        """(ok, reason). Fails only on evidence; any error reading the folder counts as ok."""
        if not self.active:
            return True, ""
        with db.lock:
            version = db.conn.execute("PRAGMA data_version").fetchone()[0], db.conn.total_changes
        now = self.clock()
        if self._cache and now - self._cache[0] < CACHE_SECONDS and self._cache[1] == version:
            return self._cache[2]
        try:
            result = self._verify(db, now)
        except Exception:
            log.warning("log checkpoint check failed", exc_info=True)
            result = (True, "")
        self._cache = (now, version, result)
        return result

    def _verify(self, db, now):
        checkpoints, resets = self._files()
        last_reset = max(resets, default=0.0)
        retention = int(db.get_setting("log_retention_days", 90) or 0)
        for entry_id, digest, ts in sorted(checkpoints):
            if ts <= last_reset:
                continue  # from a chain the owner (visibly) reset
            with db.lock:
                row = db.conn.execute("SELECT hash FROM audit_log WHERE id=?", (entry_id,)).fetchone()
            if row is not None:
                if row["hash"] != digest:
                    return False, f"entry {entry_id} was rewritten"
            elif retention == 0 or ts > now - retention * 86400 - PRUNE_SLACK:
                return False, f"entry {entry_id} was deleted"
        return True, ""
