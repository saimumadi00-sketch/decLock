"""SQLite storage: settings (key/value), locked apps, the audit log and face samples."""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS locked_apps (name TEXT PRIMARY KEY, added_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    event TEXT NOT NULL,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS face_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    embedding BLOB NOT NULL,   -- Fernet-encrypted float32 vector
    snapshot BLOB              -- Fernet-encrypted JPEG of the face crop, optional
);
-- SHA-256 of program files known to be a locked app, so renamed copies are still recognised.
CREATE TABLE IF NOT EXISTS app_fingerprints (sha256 TEXT PRIMARY KEY, name TEXT NOT NULL);
"""


class Database:
    """SQLite wrapper. One shared connection guarded by `lock` (guard thread + UI thread)."""

    def __init__(self, path: Path):
        # check_same_thread=False: the guard, USB and idle threads share this connection under `lock`.
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row  # rows can be read by column name
        self.lock = threading.RLock()
        with self.lock, self.conn:
            self.conn.execute("PRAGMA journal_mode=WAL")  # the CLI can read while the app writes
            self.conn.executescript(SCHEMA)

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    def get_setting(self, key, default=None):
        with self.lock:
            row = self.conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key, value) -> None:
        """Insert or overwrite one setting (values are stored as text)."""
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

    def add_app(self, name: str) -> None:
        """Lock an app by executable name. Adding one that is already locked does nothing."""
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.lock, self.conn:
            self.conn.execute("INSERT OR IGNORE INTO locked_apps(name,added_at) VALUES(?,?)", (name, now))

    def remove_app(self, name: str) -> bool:
        """True if the app was locked (and now isn't)."""
        with self.lock, self.conn:
            self.conn.execute("DELETE FROM app_fingerprints WHERE name=?", (name,))  # forget its copies too
            return self.conn.execute("DELETE FROM locked_apps WHERE name=?", (name,)).rowcount > 0

    def list_apps(self) -> list:
        with self.lock:
            return [r["name"] for r in self.conn.execute("SELECT name FROM locked_apps ORDER BY name")]

    def add_fingerprint(self, sha256: str, name: str) -> None:
        """Remember that the program file with this hash is the locked app `name`."""
        with self.lock, self.conn:
            self.conn.execute("INSERT INTO app_fingerprints(sha256,name) VALUES(?,?) "
                              "ON CONFLICT(sha256) DO UPDATE SET name=excluded.name", (sha256, name))

    def fingerprint_name(self, sha256: str):
        """The locked app a program-file hash belongs to, or None."""
        with self.lock:
            row = self.conn.execute("SELECT name FROM app_fingerprints WHERE sha256=?", (sha256,)).fetchone()
        return row["name"] if row else None
