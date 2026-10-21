"""Single-host durable inbox. SQLite transactions serialize worker claims."""

import json
from contextlib import contextmanager
import sqlite3
import time
from pathlib import Path

from src.events import normalize_event
from src.lifecycle import initialize, observe


class Inbox:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS inbox (
                event_id TEXT PRIMARY KEY, thread_id TEXT NOT NULL,
                payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
                run_id TEXT, attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt REAL NOT NULL DEFAULT 0,
                lease_until REAL NOT NULL DEFAULT 0, error TEXT,
                created_at REAL NOT NULL, updated_at REAL NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS inbox_thread ON inbox(thread_id)")
            db.execute("CREATE INDEX IF NOT EXISTS inbox_schedule ON inbox(status,next_attempt)")
            initialize(db)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def accept(self, events: list[dict]) -> list[dict]:
        results = []
        with self.connect() as db:
            for event in events:
                now = time.time()
                cursor = db.execute(
                    "INSERT OR IGNORE INTO inbox(event_id,thread_id,payload,created_at,updated_at) VALUES(?,?,?,?,?)",
                    (event["event_id"], event["thread_id"], json.dumps(event), now, now),
                )
                if cursor.rowcount:
                    observe(db, event["event_id"], event["thread_id"],
                            normalize_event(event["source"], event["raw"], event["cluster"]), now)
                row = dict(db.execute("SELECT * FROM inbox WHERE event_id=?", (event["event_id"],)).fetchone())
                results.append({**self.public(row), "duplicate": cursor.rowcount == 0})
        return results

    @staticmethod
    def public(row: dict) -> dict:
        return {key: row[key] for key in ("event_id", "thread_id", "run_id", "status", "attempts", "error")}

    def get(self, event_id: str) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM inbox WHERE event_id=?", (event_id,)).fetchone()
            return self.public(dict(row)) if row else None

    def claim(self) -> dict | None:
        now = time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # A crash after POST may have created a run. Reconcile, never blindly POST again.
            db.execute("UPDATE inbox SET status='uncertain' WHERE status='dispatching' AND lease_until < ?", (now,))
            row = db.execute("""SELECT * FROM inbox i
                WHERE status IN ('pending','uncertain','submitted') AND next_attempt <= ? AND lease_until < ?
                AND NOT EXISTS (SELECT 1 FROM inbox older WHERE older.thread_id=i.thread_id
                    AND older.rowid < i.rowid AND older.status NOT IN ('success','error','timeout','interrupted'))
                ORDER BY next_attempt,created_at LIMIT 1""", (now, now)).fetchone()
            if not row:
                return None
            db.execute("UPDATE inbox SET lease_until=? WHERE event_id=?", (now + 120, row["event_id"]))
            return dict(row)

    def update(self, event_id: str, **fields):
        allowed = {"status", "run_id", "attempts", "next_attempt", "lease_until", "error"}
        if not fields.keys() <= allowed:
            raise ValueError("Unknown inbox fields")
        fields["updated_at"] = time.time()
        with self.connect() as db:
            db.execute("UPDATE inbox SET " + ",".join(f"{key}=?" for key in fields) + " WHERE event_id=?",
                       (*fields.values(), event_id))
