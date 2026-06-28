import os
import base64
import sqlite3
import hashlib
from contextlib import contextmanager
from cryptography.fernet import Fernet


def _get_encryption_key():
    """Derive a Fernet key from the SECRET_KEY env var (must be set)."""
    secret = os.environ.get("SECRET_KEY", "")
    if not secret:
        raise RuntimeError("SECRET_KEY must be set for key encryption")
    # Fernet needs a 32-byte URL-safe base64-encoded key. Derive via SHA-256.
    raw = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(raw)


SCHEMA = """
CREATE TABLE IF NOT EXISTS streams (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    app TEXT NOT NULL,
    publish_key_enc BLOB NOT NULL,
    play_key_enc BLOB NOT NULL,
    stats_key_enc BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class Store:
    def __init__(self, db_path):
        self.db_path = db_path
        self._fernet = Fernet(_get_encryption_key())
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _encrypt(self, plaintext: str) -> bytes:
        return self._fernet.encrypt(plaintext.encode("utf-8"))

    def _decrypt(self, ciphertext: bytes) -> str:
        return self._fernet.decrypt(ciphertext).decode("utf-8")

    def add_stream(self, stream_id, name, app, publish_key, play_key, stats_key):
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO streams (id, name, app, publish_key_enc, play_key_enc, stats_key_enc) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (stream_id, name, app,
                 self._encrypt(publish_key),
                 self._encrypt(play_key),
                 self._encrypt(stats_key)),
            )

    def list_streams(self):
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM streams ORDER BY created_at DESC").fetchall()
            result = []
            for row in rows:
                d = dict(row)
                # Decrypt keys for API consumers
                d["publish_key"] = self._decrypt(d.pop("publish_key_enc"))
                d["play_key"] = self._decrypt(d.pop("play_key_enc"))
                d["stats_key"] = self._decrypt(d.pop("stats_key_enc"))
                result.append(d)
            return result

    def get_stream(self, stream_id):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM streams WHERE id = ?", (stream_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["publish_key"] = self._decrypt(d.pop("publish_key_enc"))
            d["play_key"] = self._decrypt(d.pop("play_key_enc"))
            d["stats_key"] = self._decrypt(d.pop("stats_key_enc"))
            return d

    def delete_stream(self, stream_id):
        with self._connect() as conn:
            conn.execute("DELETE FROM streams WHERE id = ?", (stream_id,))
