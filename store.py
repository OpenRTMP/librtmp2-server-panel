import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS streams (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    app TEXT NOT NULL,
    publish_key TEXT NOT NULL,
    play_key TEXT NOT NULL,
    stats_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class Store:
    def __init__(self, db_path):
        self.db_path = db_path
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

    def add_stream(self, stream_id, name, app, publish_key, play_key, stats_key):
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO streams (id, name, app, publish_key, play_key, stats_key) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (stream_id, name, app, publish_key, play_key, stats_key),
            )

    def list_streams(self):
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM streams ORDER BY created_at DESC").fetchall()
            return [dict(row) for row in rows]

    def get_stream(self, stream_id):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM streams WHERE id = ?", (stream_id,)).fetchone()
            return dict(row) if row else None

    def delete_stream(self, stream_id):
        with self._connect() as conn:
            conn.execute("DELETE FROM streams WHERE id = ?", (stream_id,))
