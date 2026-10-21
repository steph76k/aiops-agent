"""Durable observations shared by ingress, recurrence detection and recovery."""

from datetime import datetime
import hashlib
import json
import os
import time


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.timestamp() if parsed.tzinfo else None
    except (ValueError, OverflowError, OSError):
        return None


def signal_key(event):
    # Unlike ticket correlation, this identifies one alert series, not all
    # alerts on a pod or an explicit cross-source incident grouping.
    identity = event.get("fingerprint") or event.get("labels") or {
        k: event.get(k) for k in ("event_type", "namespace", "pod", "node", "instance")}
    return hashlib.sha256(json.dumps([event.get("source"), event.get("cluster"), identity],
                                    sort_keys=True).encode()).hexdigest()


def initialize(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS lifecycle_observations (
            event_id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, signal_key TEXT NOT NULL,
            phase TEXT NOT NULL, started_at REAL NOT NULL, observed_at REAL NOT NULL,
            payload TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS lifecycle_signal ON lifecycle_observations(signal_key,started_at);
        CREATE TABLE IF NOT EXISTS recovery_checks (
            event_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, thread_id TEXT NOT NULL,
            signal_key TEXT NOT NULL, started_at REAL NOT NULL, payload TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending', created_at REAL NOT NULL,
            next_check REAL NOT NULL, healthy_since REAL, last_check REAL,
            samples INTEGER NOT NULL DEFAULT 0, result TEXT
        );
        CREATE INDEX IF NOT EXISTS recovery_schedule ON recovery_checks(status,next_check);
    """)


def observe(db, event_id, thread_id, event, now=None):
    if event.get("source") != "prometheus" or event.get("status") not in {"firing", "resolved"}:
        return
    now = time.time() if now is None else now
    started = timestamp(event.get("starts_at") or event.get("event_time"))
    if started is None:
        return
    key = signal_key(event)
    db.execute("INSERT OR IGNORE INTO lifecycle_observations VALUES(?,?,?,?,?,?,?)",
               (event_id, thread_id, key, event["status"], started, now, json.dumps(event)))
    # Cancel on receipt, before the model/incident worker catches up. An old
    # delivery or duplicate from the same episode must not cancel a newer check.
    db.execute("UPDATE recovery_checks SET status='superseded' WHERE signal_key=? "
               "AND started_at<? AND status='pending'", (key, started))


def recurrence(db, event, thread_id):
    if event.get("source") != "prometheus":
        return {}
    started = timestamp(event.get("starts_at") or event.get("event_time"))
    if started is None:
        return {}
    window = max(60, int(os.getenv("AIOPS_FLAP_WINDOW_SECONDS", "1800")))
    threshold = max(2, int(os.getenv("AIOPS_FLAP_THRESHOLD", "3")))
    rows = db.execute("SELECT DISTINCT thread_id FROM lifecycle_observations WHERE signal_key=? "
                      "AND phase='firing' AND started_at BETWEEN ? AND ?",
                      (signal_key(event), started-window, started)).fetchall()
    count = len({r["thread_id"] for r in rows} | ({thread_id} if event.get("status") == "firing" else set()))
    return {"episodes": count, "window_seconds": window, "flapping": count >= threshold}


def prepare_lifecycle(state):
    if state.get("event_action") not in {"investigate", "resolved"}:
        return {}
    from src.incidents import IncidentStore
    from src.servicenow import Settings
    if not Settings.from_env().enabled:
        return {}
    store = IncidentStore()
    event = dict(state["trigger_event"])
    with store.connect() as db:
        observe(db, state["event_id"], state["event_thread_id"], event)
        context = recurrence(db, event, state["event_thread_id"])
        if context:
            event["recurrence"] = context
        # Reuse only an actual recent RCA of the exact series and severity.
        # Recurrence notes themselves are never used as analysis cache entries.
        if context.get("flapping") and state["event_action"] == "investigate":
            previous = db.execute("SELECT e.event_id,e.payload,e.rca FROM incident_events e "
                "JOIN lifecycle_observations o USING(event_id) JOIN incidents i USING(incident_id) "
                "WHERE o.signal_key=? AND e.phase='firing' AND e.thread_id!=? AND e.rca!='' "
                "AND e.created_at>=? AND i.state='active' ORDER BY e.created_at DESC LIMIT 20",
                (signal_key(event), state["event_thread_id"], time.time()-context["window_seconds"])).fetchall()
            for row in previous:
                prior = json.loads(row["payload"])
                if not prior.get("rca_reused_from") and prior.get("severity") == event.get("severity"):
                    event["rca_reused_from"] = row["event_id"]
                    event["reused_rca"] = row["rca"]
                    return {"trigger_event": event, "event_action": "recurrence"}
    return {"trigger_event": event}


def schedule_recovery(db, event_id, incident_id, thread_id, event, now):
    if event.get("source") != "prometheus" or event.get("status") != "resolved":
        return
    if os.getenv("AIOPS_RECOVERY_ENABLED", "true").lower() not in {"1", "true", "yes", "on"}:
        return
    started = timestamp(event.get("starts_at") or event.get("event_time"))
    if started is None:
        return
    key = signal_key(event)
    newer = db.execute("SELECT 1 FROM lifecycle_observations WHERE signal_key=? AND started_at>? LIMIT 1",
                       (key, started)).fetchone()
    db.execute("INSERT OR IGNORE INTO recovery_checks "
               "(event_id,incident_id,thread_id,signal_key,started_at,payload,status,created_at,next_check) "
               "VALUES(?,?,?,?,?,?,?,?,?)", (event_id, incident_id, thread_id, key, started,
                   json.dumps(event), "superseded" if newer else "pending", now, now))
    return "superseded" if newer else "pending"
