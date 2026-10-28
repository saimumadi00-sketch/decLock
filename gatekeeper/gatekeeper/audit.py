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

GENESIS = "0" * 64
TAIL = "tail (log truncated or replaced)"
log = logging.getLogger("gatekeeper.audit")


def _digest(prev: str, ts: str, event: str, detail: str) -> str:
    return hashlib.sha256("\x1f".join((prev, ts, event, detail)).encode("utf-8")).hexdigest()


def _csv_safe(value: str) -> str:
    """Stop spreadsheet formula injection: details can contain attacker-chosen text."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


class AuditLog:
    def __init__(self, db: Database, seal_path: Path = None):
        self.db, self.seal_path = db, seal_path

    def _anchor(self) -> str:
        return self.db.get_setting("audit_anchor", GENESIS)

    def record(self, event: str, detail: str = "") -> None:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.db.lock:
            with self.db.conn:
                row = self.db.conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
                prev = row["hash"] if row else self._anchor()
                digest = _digest(prev, ts, event, detail)
                cur = self.db.conn.execute(
                    "INSERT INTO audit_log(ts,event,detail,prev_hash,hash) VALUES(?,?,?,?,?)",
                    (ts, event, detail, prev, digest))
            if self.seal_path:
                self.seal_path.write_text(f"{cur.lastrowid} {digest}", encoding="ascii")
        log.info("audit %s %s", event, detail)

    def verify(self):
        """Return (ok, first_bad_id, or TAIL if the seal does not match)."""
        prev = self._anchor()
        with self.db.lock:
            rows = self.db.conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        for r in rows:
            if r["prev_hash"] != prev or r["hash"] != _digest(prev, r["ts"], r["event"], r["detail"]):
                return False, r["id"]
            prev = r["hash"]
        if self.seal_path and self.seal_path.exists():
            try:
                seal_id, seal_hash = self.seal_path.read_text(encoding="ascii").split()
            except ValueError:
                return False, TAIL
            with self.db.lock:
                row = self.db.conn.execute("SELECT hash FROM audit_log WHERE id=?", (int(seal_id),)).fetchone()
            # A seal older than the newest row is fine (crash between insert and seal write).
            if row is None or row["hash"] != seal_hash:
                return False, TAIL
        return True, None

    def prune(self, days: int) -> int:
        """Delete entries older than `days`, always keeping the newest one. Returns rows removed."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        with self.db.lock:
            with self.db.conn:
                boundary = self.db.conn.execute(
                    "SELECT id, hash FROM audit_log WHERE ts < ? AND id < (SELECT MAX(id) FROM audit_log) "
                    "ORDER BY id DESC LIMIT 1", (cutoff,)).fetchone()
                if boundary is None:
                    return 0
                removed = self.db.conn.execute("DELETE FROM audit_log WHERE id <= ?", (boundary["id"],)).rowcount
                self.db.set_setting("audit_anchor", boundary["hash"])
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
        with self.db.lock, self.db.conn:
            self.db.conn.execute("DELETE FROM audit_log")
            self.db.set_setting("audit_anchor", GENESIS)
        if self.seal_path and self.seal_path.exists():
            self.seal_path.unlink()
        self.record("log_reset", "fresh chain started")
