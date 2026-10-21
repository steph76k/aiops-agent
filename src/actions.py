"""Durable, incident-scoped approvals and a shared executor for complete MCP plans."""

import asyncio
import fcntl
import json
import logging
import os
import time
from uuid import uuid4

from langchain_mcp_adapters.client import MultiServerMCPClient

logger = logging.getLogger(__name__)


def enabled():
    return bool(os.getenv("AIOPS_ACTIONS_USERS") and os.getenv("AIOPS_AGENT_PUBLIC_URL"))


def remediation_scope(event):
    namespaces = {name.strip() for name in os.getenv("AIOPS_REMEDIATION_NAMESPACES", "").split(",") if name.strip()}
    return bool(os.getenv("AIOPS_REMEDIATION_MCP_URL")
                and event.get("cluster") == os.getenv("AIOPS_REMEDIATION_CLUSTER")
                and ("*" in namespaces or event.get("namespace") in namespaces))


class ActionStore:
    def __init__(self, incidents):
        self.incidents = incidents
        with incidents.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS operator_actions (
                action_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, event_id TEXT NOT NULL,
                actor TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL,
                status TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
                run_id TEXT, result TEXT
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS operator_action_steps (
                action_id TEXT NOT NULL, step_index INTEGER NOT NULL, status TEXT NOT NULL,
                updated_at REAL, PRIMARY KEY(action_id,step_index)
            )""")

    def event(self, incident_id):
        with self.incidents.connect() as db:
            row = db.execute("SELECT e.* FROM incident_events e JOIN incidents i USING(incident_id) "
                             "WHERE e.incident_id=? AND i.state='active' AND e.phase='firing' "
                             "ORDER BY e.created_at DESC, e.rowid DESC LIMIT 1", (incident_id,)).fetchone()
            if not row:
                raise ValueError("Kein aktiver Incident mit ursprünglichem Alarm vorhanden.")
            return dict(row)

    def evidence(self, incident_id):
        row = self.event(incident_id)
        with self.incidents.connect() as db:
            recent = db.execute("SELECT phase,rca FROM incident_events WHERE incident_id=? AND thread_id=? "
                                "ORDER BY created_at DESC, rowid DESC LIMIT 5", (incident_id, row["thread_id"])).fetchall()
        return [{"phase": item["phase"], "report": item["rca"][:16000]} for item in reversed(recent)]

    def create(self, incident_id, actor, kind, *, plan=None, purpose=None, event_id=None, endpoint=None):
        row = self.event(incident_id)
        event = json.loads(row["payload"])
        if kind not in {"analysis", "plan"}:
            raise ValueError("Unbekannte Aktion. Bitte einen neuen Plan vorbereiten.")
        if kind == "plan":
            if not remediation_scope(event):
                raise ValueError("Pläne sind für diesen Cluster/Namespace nicht eingerichtet.")
            if event_id != row["event_id"] or endpoint != os.getenv("AIOPS_REMEDIATION_MCP_URL"):
                raise ValueError("Alarm oder Zielkonfiguration geändert. Plan erneut vorbereiten.")
            if purpose not in {"analysis", "remediation"} or not plan or not plan.get("steps"):
                raise ValueError("Ein vollständiger Maßnahmenplan ist erforderlich.")
        action_id, now = str(uuid4()), time.time()
        payload = {"event": event, "thread_id": row["thread_id"], "previous_rca": row["rca"],
                   "purpose": purpose if kind == "plan" else "analysis", "plan": plan,
                   "endpoint": endpoint if kind == "plan" else None}
        with self.incidents.connect() as db:
            db.execute("INSERT INTO operator_actions VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                       (action_id, incident_id, row["event_id"], actor, kind, json.dumps(payload),
                        "draft", now, now + 600, None, None))
            if kind == "plan":
                for index, step in enumerate(plan["steps"]):
                    db.execute("INSERT INTO operator_action_steps(action_id,step_index,status) VALUES(?,?,?)",
                               (action_id, index, "pending"))
                from urllib.parse import urlsplit
                base = urlsplit(os.getenv("AIOPS_AGENT_PUBLIC_URL", ""))
                review_url = f"{base.scheme}://{base.netloc}{base.path.rstrip('/')}/operator/actions/{action_id}"
                note = ("Plan vorbereitet — noch nicht freigegeben.\n\n"
                        f"[Vollständigen Plan prüfen und freigeben]({review_url})"
                        + "\n\n" + plan_text(payload))
                draft_event = {**event, "operator": actor, "status": "plan_prepared"}
                for key in ("recovery", "recurrence", "rca_reused_from", "reused_rca"):
                    draft_event.pop(key, None)
                draft_id = str(uuid4())
                db.execute("INSERT INTO incident_events VALUES(?,?,?,?,?,?,?)",
                           (draft_id, incident_id, row["thread_id"], "plan_prepared", json.dumps(draft_event), note, now))
                db.execute("INSERT INTO ticket_jobs(event_id,incident_id,next_attempt,updated_at) VALUES(?,?,?,?)",
                           (draft_id, incident_id, now, now))
        return self.get(action_id)

    def steps(self, action_id):
        with self.incidents.connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM operator_action_steps WHERE action_id=? ORDER BY step_index", (action_id,))]

    def step_progress(self, action_id, index, status):
        with self.incidents.connect() as db:
            db.execute("UPDATE operator_action_steps SET status=?,updated_at=? WHERE action_id=? AND step_index=?",
                       (status, time.time(), action_id, index))

    def validate_target(self, action):
        row = self.event(action["incident_id"])
        if action["kind"] == "analysis":
            return
        if row["event_id"] != action["event_id"]:
            raise ValueError("Der Incident hat einen neueren Alarm; Eingriff erneut prüfen.")
        with self.incidents.connect() as db:
            resolved = db.execute("SELECT 1 FROM incident_events WHERE incident_id=? AND thread_id=? "
                                  "AND phase='resolved'", (action["incident_id"], row["thread_id"])).fetchone()
        if resolved:
            raise ValueError("Alarm bereits beendet; Eingriff nicht mehr freigegeben.")

    def get(self, action_id):
        with self.incidents.connect() as db:
            row = db.execute("SELECT * FROM operator_actions WHERE action_id=?", (action_id,)).fetchone()
            return dict(row) if row else None

    def confirm(self, action_id, actor):
        action = self.get(action_id)
        if not action or action["actor"] != actor:
            raise ValueError("Freigabe nicht gefunden.")
        if action["kind"] not in {"analysis", "plan"}:
            raise ValueError("Alter Einzelauftrag. Bitte einen neuen Plan vorbereiten.")
        if action["status"] == "draft":
            self.validate_target(action)
            if action["kind"] == "plan":
                validate_plan_context(action)
        with self.incidents.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM operator_actions WHERE action_id=? AND actor=?",
                             (action_id, actor)).fetchone()
            if not row:
                raise ValueError("Freigabe nicht gefunden.")
            if row["status"] != "draft":
                return dict(row)  # Repeated POST never repeats an action.
            if row["expires_at"] <= time.time():
                raise ValueError("Freigabe abgelaufen. Bitte neu vorbereiten.")
            active = db.execute("SELECT 1 FROM operator_actions WHERE incident_id=? "
                                "AND status IN ('queued','running')", (row["incident_id"],)).fetchone()
            if active:
                raise ValueError("Für diesen Incident läuft bereits eine Aktion.")
            db.execute("UPDATE operator_actions SET status='queued' WHERE action_id=?", (action_id,))
        return self.get(action_id)

    def claim(self):
        with self.incidents.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM operator_actions WHERE status='queued' ORDER BY created_at LIMIT 1").fetchone()
            if row:
                db.execute("UPDATE operator_actions SET status='running' WHERE action_id=?", (row["action_id"],))
                return {**dict(row), "status": "running"}

    def finish(self, action, status, result, evidence=()):
        payload = json.loads(action["payload"])
        event = payload["event"]
        for key in ("recovery", "recurrence", "rca_reused_from", "reused_rca"):
            event.pop(key, None)
        event["status"] = action["kind"]
        event["operator"] = action["actor"]
        from src.evidence_links import build_links
        event["evidence_links"] = build_links(event, payload["thread_id"], evidence)
        note = f"Operator: {action['actor']}\n\nAction: {action['kind']} — {status}\n\n{result}"
        if action["kind"] == "plan":
            note += "\n\n" + plan_text(payload)
        now = time.time()
        with self.incidents.connect() as db:
            if status != "success":
                db.execute("UPDATE operator_action_steps SET status='uncertain',updated_at=? WHERE action_id=? AND status='running'",
                           (now, action["action_id"]))
                db.execute("UPDATE operator_action_steps SET status='skipped',updated_at=? WHERE action_id=? AND status='pending'",
                           (now, action["action_id"]))
            if action["kind"] == "plan":
                steps = db.execute("SELECT step_index,status FROM operator_action_steps WHERE action_id=? ORDER BY step_index",
                                   (action["action_id"],)).fetchall()
                progress = "\n".join(f"Schritt {row['step_index'] + 1}: {row['status']}" for row in steps)
                note = f"{progress}\n\n" + note
            db.execute("UPDATE operator_actions SET status=?,result=? WHERE action_id=?", (status, result, action["action_id"]))
            db.execute("INSERT OR IGNORE INTO incident_events VALUES(?,?,?,?,?,?,?)",
                       (action["action_id"], action["incident_id"], payload["thread_id"], action["kind"], json.dumps(event), note, now))
            db.execute("INSERT OR IGNORE INTO ticket_jobs(event_id,incident_id,next_attempt,updated_at) VALUES(?,?,?,?)",
                       (action["action_id"], action["incident_id"], now, now))


async def remediation_tools():
    client = MultiServerMCPClient({"remediation": {"transport": "streamable_http",
                                                 "url": os.environ["AIOPS_REMEDIATION_MCP_URL"]}})
    tools = await client.get_tools()
    for tool in tools:
        tool.handle_tool_error = False
    return {tool.name: tool for tool in tools}


def validate_plan_context(action):
    payload = json.loads(action["payload"])
    if (action["kind"] != "plan" or action["status"] not in {"draft", "queued", "running"}
            or time.time() >= action["expires_at"] or not remediation_scope(payload["event"])
            or payload["endpoint"] != os.getenv("AIOPS_REMEDIATION_MCP_URL")):
        raise ValueError("Freigabe abgelaufen oder Zielkonfiguration geändert.")


def plan_text(payload):
    plan = payload["plan"]
    event = payload["event"]
    text = (f"Zweck: {payload['purpose']} | Cluster: {event.get('cluster')}\n\n"
            f"{plan['summary']}\n\nAuswirkungen: {plan['risks']}")
    for index, step in enumerate(plan["steps"], 1):
        text += (f"\n\n{index}. {step['title']} — {step['tool']} ({step['phase']})\n"
                 + json.dumps(step["arguments"], ensure_ascii=False, indent=2)
                 + f"\nErwartet: {step['expected_result']}")
    return text


class ActionWorker:
    def __init__(self, store, client, executor=None):
        self.store, self.client, self.executor = store, client, executor

    async def once(self):
        action = await asyncio.to_thread(self.store.claim)
        if not action:
            return False
        try:
            if not enabled() or action["actor"] not in json.loads(os.getenv("AIOPS_ACTIONS_USERS", "{}")):
                await asyncio.to_thread(self.store.finish, action, "denied", "Operator-Zugang wurde deaktiviert.")
                return True
            if time.time() >= action["expires_at"]:
                await asyncio.to_thread(self.store.finish, action, "expired", "Freigabe vor Ausführung abgelaufen.")
                return True
            await asyncio.to_thread(self.store.validate_target, action)
            if action["kind"] == "analysis":
                payload = json.loads(action["payload"])
                thread_id = payload["thread_id"]
                run = await self.client.runs.create(thread_id, "aiops-agent",
                    input={"event_input": None, "analysis_input": payload},
                    metadata={"source": "operator_analysis", "action_id": action["action_id"]},
                    config={"recursion_limit": 100}, multitask_strategy="enqueue", durability="sync")
                run_id = run["run_id"]
                with self.store.incidents.connect() as db:
                    db.execute("UPDATE operator_actions SET run_id=? WHERE action_id=?", (run_id, action["action_id"]))
                await self.client.runs.join(thread_id, run_id)
                run = await self.client.runs.get(thread_id, run_id)
                if run["status"] != "success":
                    raise RuntimeError("Analysis run did not succeed")
                history = await self.client.threads.get_history(thread_id, limit=1, metadata={"run_id": run_id})
                investigation = history[0]["values"]["investigation"]
                await asyncio.to_thread(self.store.finish, action, "success", investigation["rca"], investigation.get("current_evidence", []))
            elif action["kind"] == "plan":
                from src.action_plans import execute_plan
                async def check():
                    if not enabled() or action["actor"] not in json.loads(os.getenv("AIOPS_ACTIONS_USERS", "{}")):
                        raise ValueError("Operator-Zugang wurde deaktiviert.")
                    await asyncio.to_thread(self.store.validate_target, action)
                async def progress(index, status):
                    await asyncio.to_thread(self.store.step_progress, action["action_id"], index, status)
                execution = (self.executor(action) if self.executor else
                             execute_plan(action, check=check, progress=progress))
                result = await asyncio.wait_for(execution, timeout=600)
                await asyncio.to_thread(self.store.finish, action, "success", result)
            else:
                await asyncio.to_thread(self.store.finish, action, "denied", "Alter Einzelauftrag. Bitte einen neuen Plan vorbereiten.")
        except Exception as exc:
            logger.exception("Operator action %s failed; no automatic replay", action["action_id"])
            await asyncio.to_thread(self.store.finish, action, "uncertain",
                f"Aktion nicht sicher abgeschlossen ({type(exc).__name__}). Schrittprotokoll und Cluster prüfen; keine automatische Wiederholung.")
        return True

    async def run(self):
        with open(self.store.incidents.path + ".actions.lock", "a") as lock:
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    await asyncio.sleep(1)
            with self.store.incidents.connect() as db:
                interrupted = [dict(r) for r in db.execute("SELECT * FROM operator_actions WHERE status='running'")]
            for action in interrupted:
                await asyncio.to_thread(self.store.finish, action, "uncertain", "Serverneustart während Ausführung; Ergebnis prüfen. Keine automatische Wiederholung.")
            while True:
                try:
                    worked = await self.once()
                except Exception:
                    logger.exception("Operator action worker failed")
                    worked = False
                await asyncio.sleep(0.2 if worked else 1)
