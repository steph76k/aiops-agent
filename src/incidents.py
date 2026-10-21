"""Durable incident correlation and a single-host ServiceNow outbox.

Exact event duplicates are handled by Inbox before RCA. This store groups distinct
events, and remembers every external write before attempting it. Journal writes
with an unknown outcome are never blindly repeated.
"""

import asyncio
from contextlib import contextmanager
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import sqlite3
import time
from uuid import uuid4

from src.ticket_format import format_note
from src.lifecycle import initialize, observe, recurrence, schedule_recovery
from src.evidence_links import build_links

logger = logging.getLogger(__name__)


def database_path():
    return os.getenv("AIOPS_INBOX_PATH", "data/inbox.sqlite3")


def correlation_key(event: dict) -> str:
    labels = event.get("labels", {})
    fields = event.get("output_fields", {})
    explicit = labels.get("aiops_incident_key") or fields.get("aiops.incident_key")
    if explicit:
        parts = ["explicit", event.get("cluster"), str(explicit)]
    else:
        resource = next(((k, event[k]) for k in ("pod", "node", "instance", "service")
                         if event.get(k)), ("fingerprint", event.get("fingerprint")))
        # Unscoped events must not accidentally collapse into a cluster-wide ticket.
        if not resource[1]:
            resource = ("episode", event["thread_id"])
        parts = ["signal", event.get("source"), event.get("cluster"),
                 event.get("namespace"), resource, event.get("event_type")]
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


class IncidentStore:
    def __init__(self, path=None):
        self.path = str(path or database_path())
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY, group_key TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'active', created_at REAL NOT NULL,
                    last_seen REAL NOT NULL, sys_id TEXT, number TEXT
                );
                CREATE INDEX IF NOT EXISTS incidents_group ON incidents(group_key,last_seen);
                CREATE TABLE IF NOT EXISTS incident_episodes (
                    thread_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incident_events (
                    event_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL,
                    thread_id TEXT NOT NULL, phase TEXT NOT NULL, payload TEXT NOT NULL,
                    rca TEXT NOT NULL, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ticket_jobs (
                    event_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending', operation TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL,
                    lease_until REAL NOT NULL DEFAULT 0, error TEXT, updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ticket_jobs_schedule ON ticket_jobs(status,next_attempt);
            """)
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

    def _choose_incident(self, db, key, now, window):
        row = db.execute("SELECT incident_id FROM incidents WHERE group_key=? AND state='active' "
                         "AND last_seen>=? ORDER BY last_seen DESC LIMIT 1", (key, now-window)).fetchone()
        if row:
            return row["incident_id"]
        incident_id = str(uuid4())
        db.execute("INSERT INTO incidents(incident_id,group_key,created_at,last_seen) VALUES(?,?,?,?)",
                   (incident_id, key, now, now))
        return incident_id

    def record(self, event_id, thread_id, event, rca, window=3600):
        now = time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT incident_id FROM incident_events WHERE event_id=?", (event_id,)).fetchone()
            if old:
                return old["incident_id"]
            observe(db, event_id, thread_id, event, now)
            episode = db.execute("SELECT incident_id FROM incident_episodes WHERE thread_id=?", (thread_id,)).fetchone()
            if event.get("status") == "resolved" and not episode:
                return None
            incident_id = episode["incident_id"] if episode else self._choose_incident(
                db, correlation_key({**event, "thread_id": thread_id}), now, window)
            event = dict(event)
            context = recurrence(db, event, thread_id)
            if context:
                event["recurrence"] = context
            db.execute("INSERT OR IGNORE INTO incident_episodes VALUES(?,?)", (thread_id, incident_id))
            recovery_status = schedule_recovery(db, event_id, incident_id, thread_id, event, now)
            if event.get("status") == "resolved":
                event["recovery_status"] = recovery_status or "disabled"
            db.execute("INSERT INTO incident_events VALUES(?,?,?,?,?,?,?)", (event_id, incident_id,
                       thread_id, event.get("status", "firing"), json.dumps(event), rca or "", now))
            db.execute("UPDATE incidents SET last_seen=? WHERE incident_id=?", (now, incident_id))
            db.execute("INSERT INTO ticket_jobs(event_id,incident_id,next_attempt,updated_at) VALUES(?,?,?,?)",
                       (event_id, incident_id, now+2, now))
            return incident_id

    def event_ticket(self, event_id):
        with self.connect() as db:
            row = db.execute("SELECT j.event_id,j.incident_id,j.status,j.operation,j.attempts,j.error,"
                             "i.sys_id,i.number FROM ticket_jobs j JOIN incidents i USING(incident_id) "
                             "WHERE j.event_id=?", (event_id,)).fetchone()
            return dict(row) if row else None

    def get(self, incident_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if not row:
                return None
            result = dict(row)
            result["correlation_id"] = "aiops:" + incident_id
            result["events"] = [dict(r) for r in db.execute(
                "SELECT e.event_id,e.thread_id,e.phase,e.created_at,j.status,j.error FROM incident_events e "
                "JOIN ticket_jobs j USING(event_id) WHERE e.incident_id=? ORDER BY e.created_at", (incident_id,))]
            result["recovery_checks"] = [dict(r) for r in db.execute(
                "SELECT event_id,status,healthy_since,last_check,samples,next_check,result FROM recovery_checks "
                "WHERE incident_id=? ORDER BY created_at", (incident_id,))]
            for check in result["recovery_checks"]:
                check["result"] = json.loads(check["result"]) if check["result"] else None
            return result

    def claim(self, event_id=None):
        now = time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # The OS file lock ensures no writer is still active when this runs.
            db.execute("UPDATE ticket_jobs SET status='uncertain',lease_until=0 WHERE status='sending'")
            query = ("SELECT j.*,e.thread_id,e.phase,e.payload,e.rca,i.sys_id,i.number,i.group_key "
                     "FROM ticket_jobs j JOIN incident_events e USING(event_id) "
                     "JOIN incidents i ON i.incident_id=j.incident_id "
                     "WHERE j.status IN ('pending','uncertain') AND j.lease_until<=? ")
            args = [now]
            if event_id:
                query += "AND j.event_id=? "
                args.append(event_id)
            else:
                query += "AND j.next_attempt<=? "
                args.append(now)
            query += ("AND NOT EXISTS (SELECT 1 FROM ticket_jobs older WHERE older.incident_id=j.incident_id "
                      "AND older.rowid<j.rowid AND older.status NOT IN ('success','dry_run','skipped_closed','skipped_superseded')) "
                      "ORDER BY j.next_attempt,j.rowid LIMIT 1")
            row = db.execute(query, args).fetchone()
            if row:
                db.execute("UPDATE ticket_jobs SET lease_until=? WHERE event_id=?", (now+120, row["event_id"]))
            return dict(row) if row else None

    def update_job(self, event_id, **fields):
        if not fields.keys() <= {"status", "operation", "attempts", "next_attempt", "lease_until", "error"}:
            raise ValueError("Invalid job fields")
        fields["updated_at"] = time.time()
        with self.connect() as db:
            db.execute("UPDATE ticket_jobs SET " + ",".join(k+"=?" for k in fields) + " WHERE event_id=?",
                       (*fields.values(), event_id))

    def link(self, incident_id, remote):
        with self.connect() as db:
            db.execute("UPDATE incidents SET sys_id=?,number=? WHERE incident_id=?",
                       (remote["sys_id"], remote["number"], incident_id))

    def retry(self, event_id):
        """Explicit retry only for a confirmed failure, never an unknown write."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM ticket_jobs WHERE event_id=?", (event_id,)).fetchone()
            if row is None:
                raise KeyError(event_id)
            if row["status"] != "error":
                raise ValueError("Only confirmed errors can be retried; uncertain writes require reconciliation.")
            db.execute("UPDATE ticket_jobs SET status='pending',next_attempt=?,lease_until=0,error=NULL,updated_at=? "
                       "WHERE event_id=?", (time.time(), time.time(), event_id))
        return self.event_ticket(event_id)

    def move_from_closed(self, row, window):
        """A new firing after remote closure gets a new correlation ID/ticket."""
        now = time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE incidents SET state='closed' WHERE incident_id=?", (row["incident_id"],))
            new_id = self._choose_incident(db, row["group_key"], now, window)
            # Include a queued resolved update belonging to this same alert episode.
            ids = [r[0] for r in db.execute("SELECT e.event_id FROM incident_events e JOIN ticket_jobs j USING(event_id) "
                   "WHERE e.thread_id=? AND j.status='pending'", (row["thread_id"],))]
            for eid in ids:
                db.execute("UPDATE incident_events SET incident_id=? WHERE event_id=?", (new_id, eid))
                db.execute("UPDATE ticket_jobs SET incident_id=?,operation=NULL,lease_until=0 WHERE event_id=?", (new_id, eid))
            db.execute("UPDATE recovery_checks SET incident_id=? WHERE thread_id=? AND status='pending'",
                       (new_id, row["thread_id"]))
            db.execute("UPDATE incident_episodes SET incident_id=? WHERE thread_id=?", (new_id, row["thread_id"]))
            db.execute("UPDATE incidents SET last_seen=? WHERE incident_id=?", (now, new_id))


def work_note(row, settings=None):
    return format_note(row, html=settings is None or settings.note_format == "html")


def create_payload(row, settings):
    event = json.loads(row["payload"])
    if event.get("rca_reused_from") and event.get("reused_rca"):
        # A remotely closed/deleted ticket may force a fresh ticket. Preserve
        # the reused analysis there, clearly identified as historical.
        source = event.pop("rca_reused_from")
        row = {**row, "payload": json.dumps(event),
               "rca": f"Previous analysis from event {source}; not freshly revalidated.\n\n" + event["reused_rca"]}
    severity = event.get("severity", "info").lower()
    urgency = "1" if severity in {"critical", "emergency", "alert"} else "2" if severity in {"warning", "error"} else "3"
    resource = event.get("pod") or event.get("node") or event.get("namespace") or event.get("cluster")
    payload = {"short_description": f"[AIOps] {event.get('event_type')} - {resource}"[:160],
               "description": format_note(row, html=False),
               "work_notes": work_note(row, settings),
               settings.correlation_field: "aiops:" + row["incident_id"],
               "category": settings.category, "impact": "3", "urgency": urgency}
    if settings.subcategory:
        payload["subcategory"] = settings.subcategory
    if settings.assignment_group:
        payload["assignment_group"] = settings.assignment_group
    return payload


class TicketWorker:
    def __init__(self, store, settings=None, client_factory=None):
        from src.servicenow import Settings, ServiceNowClient
        self.store = store
        self.settings = settings or Settings.from_env()
        self.client_factory = client_factory or ServiceNowClient
        self.window = max(1, int(os.getenv("AIOPS_INCIDENT_WINDOW_SECONDS", "3600")))

    async def once(self, event_id=None):
        if not self.settings.enabled:
            return False
        with open(self.store.path + ".servicenow.lock", "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            row = await asyncio.to_thread(self.store.claim, event_id)
            if not row:
                return False
            await self._process(row)
            return True

    async def _update(self, row, **fields):
        await asyncio.to_thread(self.store.update_job, row["event_id"], lease_until=0, **fields)

    async def _process(self, row):
        from src.servicenow import SnowAmbiguousWrite, SnowError
        correlation = "aiops:" + row["incident_id"]
        try:
            if row["phase"].startswith("recovery_"):
                from src.lifecycle import signal_key, timestamp
                event = json.loads(row["payload"])
                with self.store.connect() as db:
                    newer = db.execute("SELECT 1 FROM lifecycle_observations WHERE signal_key=? AND started_at>? LIMIT 1",
                        (signal_key(event), timestamp(event.get("starts_at") or event.get("event_time")))).fetchone()
                if newer:
                    await self._update(row, status="skipped_superseded", error=None)
                    return
            if self.settings.dry_run:
                if row["status"] == "uncertain":
                    await self._update(row, next_attempt=time.time()+60, error="Unknown write outcome requires reconciliation in live mode.")
                else:
                    await self._update(row, status="dry_run", error=None)
                return
            async with self.client_factory(self.settings) as client:
                if row["status"] == "uncertain":
                    if row["operation"] == "create":
                        remote = await client.find_incident(correlation)
                        if remote:
                            await asyncio.to_thread(self.store.link, row["incident_id"], remote)
                            await self._update(row, status="success", error=None)
                            return
                    await self._update(row, next_attempt=time.time()+60,
                                       error="Write outcome unknown; no automatic repeat. Inspect ServiceNow and reconcile this event.")
                    return
                remote = await client.get_incident(row["sys_id"]) if row["sys_id"] else await client.find_incident(correlation)
                if remote:
                    if remote.get(self.settings.correlation_field) != correlation:
                        raise SnowError("Linked ServiceNow incident has a different correlation ID; no update performed.")
                    await asyncio.to_thread(self.store.link, row["incident_id"], remote)
                    closed = str(remote.get("active", "true")).lower() == "false" or str(remote.get("state")) in {"6", "7", "8"}
                    if closed:
                        if row["phase"] != "firing":
                            await self._update(row, status="skipped_closed", error=None)
                        else:
                            await asyncio.to_thread(self.store.move_from_closed, row, self.window)
                        return
                operation = "update" if remote else "create"
                # A resolved notification must never create a new ticket.
                if not remote and row["phase"] != "firing":
                    await self._update(row, status="error", error="Original incident missing; resolved update did not create a ticket.")
                    return
                row["operation"] = operation
                await asyncio.to_thread(self.store.update_job, row["event_id"], status="sending",
                                        operation=operation, attempts=row["attempts"]+1)
                if remote:
                    await client.update_incident(remote["sys_id"], {"work_notes": work_note(row, self.settings),
                                                                  self.settings.correlation_field: correlation})
                else:
                    remote = await client.create_incident(create_payload(row, self.settings))
                    await asyncio.to_thread(self.store.link, row["incident_id"], remote)
                await self._update(row, status="success", error=None)
        except SnowAmbiguousWrite:
            await self._update(row, status="uncertain", next_attempt=time.time()+30,
                               error="ServiceNow write outcome unknown; reconciling without repeating the write.")
        except SnowError as exc:
            status = "uncertain" if row["status"] == "uncertain" else "pending" if exc.retryable else "error"
            await self._update(row, status=status,
                               next_attempt=time.time()+30, error=str(exc))
        except Exception as exc:
            # Keep sending unchanged: after a crash/DB error claim() reconciles it.
            # Avoid provider response bodies/credentials in persisted diagnostics.
            await asyncio.to_thread(self.store.update_job, row["event_id"], lease_until=0,
                                    next_attempt=time.time()+30, error="Unexpected ticket synchronization error; inspect server logs.")
            logger.error("Ticket synchronization failed for event %s (%s)", row["event_id"], type(exc).__name__)

    async def run(self):
        while True:
            try:
                worked = await self.once()
            except Exception as exc:
                logger.error("Ticket worker failed (%s)", type(exc).__name__)
                worked = False
            await asyncio.sleep(0.2 if worked else 1)


def record_incident(state):
    from src.servicenow import Settings
    settings = Settings.from_env()
    if not settings.enabled:
        return {"ticket": {"status": "disabled"}}
    store = IncidentStore()
    event = dict(state["trigger_event"])
    event["evidence_links"] = build_links(event, state["event_thread_id"],
        state.get("investigation", {}).get("current_evidence", []) if state.get("event_action") == "investigate" else [])
    incident_id = store.record(state["event_id"], state["event_thread_id"],
                               event, state.get("investigation", {}).get("rca", "")
                               if state.get("event_action") == "investigate" else "",
                               window=max(1, int(os.getenv("AIOPS_INCIDENT_WINDOW_SECONDS", "3600"))))
    if incident_id is None:
        return {"ticket": {"status": "ignored", "reason": "resolved_without_incident"}}
    return {"incident_id": incident_id, "ticket": store.event_ticket(state["event_id"])}


async def sync_servicenow(state):
    if state.get("ticket", {}).get("status") in {"disabled", "ignored"}:
        return {}
    store = await asyncio.to_thread(IncidentStore)
    await TicketWorker(store).once(state["event_id"])
    ticket = await asyncio.to_thread(store.event_ticket, state["event_id"])
    return {"ticket": ticket, "incident_id": ticket["incident_id"]}
