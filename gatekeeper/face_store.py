"""Encrypted storage of face samples. Embeddings and snapshots are Fernet-encrypted
(key wrapped by DPAPI) before they touch SQLite."""

from datetime import datetime, timezone

import numpy as np

from .crypto import KeyStore
from .faces import MODEL_ID
from .db import Database


class FaceStore:
    def __init__(self, db: Database, keys: KeyStore):
        self.db, self.keys = db, keys

    def replace_all(self, samples) -> None:
        """Atomically replace the enrolment. `samples` = [(embedding, jpeg_bytes_or_None)]."""
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        rows = [(now, self.keys.encrypt(np.asarray(e, np.float32).tobytes()),
                 self.keys.encrypt(s) if s else None) for e, s in samples]
        with self.db.lock, self.db.conn:
            self.db.conn.execute("DELETE FROM face_samples")
            self.db.conn.executemany(
                "INSERT INTO face_samples(created_at,embedding,snapshot) VALUES(?,?,?)", rows)
        if self.db.get_setting("face_model") != MODEL_ID:
            # First enrolment with these models: an old strictness setting meant something else.
            from .matcher import DEFAULT_THRESHOLD
            self.db.set_setting("face_threshold", DEFAULT_THRESHOLD)
        self.db.set_setting("face_model", MODEL_ID)  # which models made these samples

    def embeddings(self) -> list:
        """All enrolled face vectors, decrypted (raises if key.bin no longer matches)."""
        with self.db.lock:
            rows = self.db.conn.execute("SELECT embedding FROM face_samples ORDER BY id").fetchall()
        return [np.frombuffer(self.keys.decrypt(r["embedding"]), np.float32) for r in rows]

    def snapshots(self) -> list:
        """Decrypted JPEG snapshots (used to check what was stored)."""
        with self.db.lock:
            rows = self.db.conn.execute(
                "SELECT snapshot FROM face_samples WHERE snapshot IS NOT NULL ORDER BY id").fetchall()
        return [self.keys.decrypt(r["snapshot"]) for r in rows]

    def count(self) -> int:
        with self.db.lock:
            return self.db.conn.execute("SELECT COUNT(*) FROM face_samples").fetchone()[0]

    def clear(self) -> None:
        with self.db.lock, self.db.conn:
            self.db.conn.execute("DELETE FROM face_samples")
