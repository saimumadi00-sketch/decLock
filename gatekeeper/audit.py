"""Tamper-evident audit log: each row's hash covers the previous row's hash.

Editing or deleting a row in the middle breaks the chain. A small "head seal" file
(id + hash of the newest row) also catches truncation or replacement of the database.
Both are detection, not prevention: someone running as the same Windows user can
rewrite the database and the seal together (see docs/LIMITATIONS.md).

Retention pruning removes old rows and stores the last removed hash as an anchor, so
the remaining chain still verifies.
"""

import csv
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .db import Database

GENESIS = "0" * 64                          # the "previous hash" of the very first row
TAIL = "tail (log truncated or replaced)"   # verify() reports this instead of a row id
log = logging.getLogger("gatekeeper.audit")


def _digest(prev: str, ts: str, event: str, detail: str) -> str:
    # \x1f (unit separator) between fields, so ("ab", "c") and ("a", "bc") hash differently.
    return hashlib.sha256("\x1f".join((prev, ts, event, detail)).encode("utf-8")).hexdigest()


def _csv_safe(value: str) -> str:
    """Stop spreadsheet formula injection: details can contain attacker-chosen text."""
    # Excel/LibreOffice run a cell starting with one of these as a formula; a leading ' makes it text.
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


class AuditLog:
    def __init__(self, db: Database, seal_path: Path = None):
        self.db, self.seal_path = db, seal_path
        self.witness = None  # logwitness.LogWitness: checkpoints the user can't delete (installed build)
        # Verification cache: (data_version, total_changes, last_id, last_hash) of the last chain that
        # verified. It lets the dashboard re-check the log every few seconds by hashing only new rows.
        self._verified = None

    def _anchor(self) -> str:
        # After pruning, the hash of the last deleted row; GENESIS for a log that was never pruned.
        return self.db.get_setting("audit_anchor", GENESIS)

    def _fingerprint(self) -> tuple:
        """Changes whenever the database is written by anything other than our own record() calls.

        `PRAGMA data_version` changes when ANOTHER connection or process commits (e.g. someone
        editing the .db file); `total_changes` counts writes made through THIS connection.
        """
        version = self.db.conn.execute("PRAGMA data_version").fetchone()[0]
        return version, self.db.conn.total_changes

    def record(self, event: str, detail: str = "") -> None:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.db.lock:
            # Was the cache still valid just before this insert? Then an append keeps it valid.
            fresh = self._verified is not None and self._fingerprint() == self._verified[:2]
            with self.db.conn:  # one transaction: read the newest hash and append atomically
                row = self.db.conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
                prev = row["hash"] if row else self._anchor()
                digest = _digest(prev, ts, event, detail)
                cur = self.db.conn.execute(
                    "INSERT INTO audit_log(ts,event,detail,prev_hash,hash) VALUES(?,?,?,?,?)",
                    (ts, event, detail, prev, digest))
            if fresh:
                # Our own append: the verified prefix is untouched, so only roll the fingerprint forward.
                self._verified = self._fingerprint() + self._verified[2:]
            if self.seal_path:
                # The seal remembers the newest row, so deleting rows from the end is detectable.
                self.seal_path.write_text(f"{cur.lastrowid} {digest}", encoding="ascii")
        log.info("audit %s %s", event, detail)

    def verify(self):
        """Return (ok, first_bad_id, or TAIL if the seal does not match)."""
        with self.db.lock:
            fingerprint = self._fingerprint()
            if self._verified is not None and fingerprint == self._verified[:2]:
                # Nothing but our own appends since the last good check: hash only the new rows.
                _v, _c, last_id, prev = self._verified
            else:
                last_id, prev = 0, self._anchor()
            rows = self.db.conn.execute("SELECT * FROM audit_log WHERE id > ? ORDER BY id", (last_id,)).fetchall()
            for r in rows:
                # Each row must point at the previous row's hash AND its own hash must match its content.
                if r["prev_hash"] != prev or r["hash"] != _digest(prev, r["ts"], r["event"], r["detail"]):
                    self._verified = None
                    return False, r["id"]
                prev, last_id = r["hash"], r["id"]
            self._verified = fingerprint + (last_id, prev)
        if self.seal_path:
            if not self.seal_path.exists():
                # Every record() writes the seal, so rows without a seal mean it was deleted.
                return (False, TAIL) if last_id else (True, None)
            try:
                seal_id, seal_hash = self.seal_path.read_text(encoding="ascii").split()
                seal_id = int(seal_id)
            except ValueError:
                return False, TAIL
            with self.db.lock:
                row = self.db.conn.execute("SELECT hash FROM audit_log WHERE id=?", (seal_id,)).fetchone()
            # A seal older than the newest row is fine (crash between insert and seal write).
            if row is None or row["hash"] != seal_hash:
                return False, TAIL
        if self.witness is not None:
            ok, why = self.witness.verify(self.db)
            if not ok:
                return False, f"history ({why})"
        return True, None

    def prune(self, days: int) -> int:
        """Delete entries older than `days`, always keeping the newest one. Returns rows removed."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        with self.db.lock:
            with self.db.conn:
                # The newest old row (never the very last row, so the chain always has a head).
                boundary = self.db.conn.execute(
                    "SELECT id, hash FROM audit_log WHERE ts < ? AND id < (SELECT MAX(id) FROM audit_log) "
                    "ORDER BY id DESC LIMIT 1", (cutoff,)).fetchone()
                if boundary is None:
                    return 0
                removed = self.db.conn.execute("DELETE FROM audit_log WHERE id <= ?", (boundary["id"],)).rowcount
                # The first surviving row points at boundary's hash, so that becomes the new anchor.
                self.db.set_setting("audit_anchor", boundary["hash"])
            self._verified = None
        self.record("log_pruned", f"{removed} entries older than {days} days")
        return removed

    def export_csv(self, path) -> int:
        with self.db.lock:
            rows = self.db.conn.execute("SELECT id,ts,event,detail,hash FROM audit_log ORDER BY id").fetchall()
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["id", "timestamp_utc", "event", "detail", "hash"])
            for r in rows:
                writer.writerow([r["id"], r["ts"], _csv_safe(r["event"]), _csv_safe(r["detail"]), r["hash"]])
        return len(rows)

    def reset(self) -> None:
        """Start a fresh chain (used after a tamper alarm, once the old log has been exported)."""
        if self.witness is not None:
            self.witness.mark_reset()  # permanent: old checkpoints stop counting from here
        with self.db.lock, self.db.conn:
            self.db.conn.execute("DELETE FROM audit_log")
            self.db.set_setting("audit_anchor", GENESIS)
            self._verified = None
        if self.seal_path and self.seal_path.exists():
            self.seal_path.unlink()
        self.record("log_reset", "fresh chain started")  # writes a new seal for the new chain
