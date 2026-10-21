"""Read-only recovery checks with durable stability windows and ticket outbox."""

import asyncio
from datetime import datetime, timezone
import fcntl
import json
import logging
import math
import os
import time
from urllib.parse import parse_qs, urlsplit
from uuid import NAMESPACE_URL, uuid5

from src.evidence_links import alert_selector, build_links, safe_url, selector

logger = logging.getLogger(__name__)


def resource_queries(event):
    if event.get("namespace") and event.get("pod"):
        return [selector("kube_pod_status_ready", {"namespace": event["namespace"],
            "pod": event["pod"], "condition": "true"})]
    if event.get("node"):
        return [selector("kube_node_status_condition", {"node": event["node"],
            "condition": "Ready", "status": "true"})]
    if event.get("instance") and event.get("job"):
        return [selector("up", {"instance": event["instance"], "job": event["job"]})]
    return []


def vector_result(result):
    """Accept MCP adapter content blocks and structured Prometheus responses."""
    if hasattr(result, "content"):
        result = result.content
    if isinstance(result, list):
        texts = [block.get("text", "") for block in result if isinstance(block, dict) and block.get("type") == "text"]
        if len(texts) != 1:
            raise ValueError("Ambiguous MCP response")
        result = texts[0]
    if isinstance(result, str):
        result = json.loads(result)
    if not isinstance(result, dict) or result.get("isError") or result.get("status") == "error" or result.get("warnings"):
        raise ValueError("Query did not succeed cleanly")
    if "structuredContent" in result:
        return vector_result(result["structuredContent"])
    if "content" in result:
        return vector_result(result["content"])
    result = result.get("data", result)
    if result.get("resultType") != "vector" or not isinstance(result.get("result"), list):
        raise ValueError("Expected an instant vector")
    values = [float(row["value"][1]) for row in result["result"]]
    if not all(math.isfinite(value) for value in values):
        raise ValueError("Non-finite observation")
    return values


class PrometheusProbe:
    def __init__(self):
        self.tool = None

    async def query(self, query):
        if self.tool is None:
            from langchain_mcp_adapters.client import MultiServerMCPClient
            url = os.environ["PROMETHEUS_MCP_URL"]
            client = MultiServerMCPClient({"prometheus": {"transport": "streamable_http", "url": url}})
            tools = await client.get_tools()
            self.tool = next(t for t in tools if t.name == "prod_execute_query")
        return vector_result(await self.tool.ainvoke({"query": query}))

    async def check(self, event, quiet_seconds=0):
        evidence = []

        async def query(expression):
            values = await self.query(expression)
            evidence.append({"source": "prod_execute_query", "category": "metric",
                "query": expression, "collected_at": datetime.now(timezone.utc).isoformat(),
                "content": f"{len(values)} series; values={values[:10]}"})
            return values

        cluster = os.getenv("AIOPS_RECOVERY_CLUSTER", os.getenv("AIOPS_CLUSTER", "default"))
        if event.get("cluster") != cluster:
            return {"healthy": False, "reason": "No recovery data source configured for this cluster.", "evidence": []}
        health = resource_queries(event)
        if not health:
            return {"healthy": False, "reason": "No scoped positive resource-health check available; absence of alerts is insufficient.", "evidence": []}
        try:
            alerts = alert_selector(event)
            active = await query(alerts)
            if active:
                return {"healthy": False, "reason": "The alert is firing or pending again.", "evidence": evidence}
            if quiet_seconds:
                recent = await query(f"max_over_time({alerts}[{max(1, int(quiet_seconds))}s])")
                if recent:
                    return {"healthy": False, "reason": "Alert activity was observed during the stability window.", "evidence": evidence}
            url = safe_url(event.get("generator_url"))
            expression = parse_qs(urlsplit(url).query).get("g0.expr", [""])[0] if url else ""
            if not expression or len(expression) > 2000:
                return {"healthy": False, "reason": "Original alert expression unavailable; recovery cannot be verified.", "evidence": evidence}
            if await query(expression):
                return {"healthy": False, "reason": "The original alert expression still returns results.", "evidence": evidence}
            for expression in health:
                values = await query(expression)
                ages = await query(f"time() - timestamp({expression})")
                if not values or not ages or len(values) != len(ages) or any(v != 1 for v in values) or any(a < -30 or a > 120 for a in ages):
                    return {"healthy": False, "reason": "Resource health is missing, unhealthy or stale.", "evidence": evidence}
            return {"healthy": True, "reason": "Alert condition absent and scoped resource health freshly confirmed.", "evidence": evidence}
        except Exception as exc:
            # Never persist upstream bodies or credentials in a ticket.
            self.tool = None
            return {"healthy": False, "reason": f"Recovery check unavailable ({type(exc).__name__}); no recovery confirmed.", "evidence": evidence}


class RecoveryWorker:
    def __init__(self, store, probe=None):
        self.store = store
        self.probe = probe or PrometheusProbe()
        self.interval = max(10, int(os.getenv("AIOPS_RECOVERY_INTERVAL_SECONDS", "60")))
        self.stability = max(self.interval, int(os.getenv("AIOPS_RECOVERY_STABLE_SECONDS", "600")))
        self.max_age = max(self.stability+self.interval, int(os.getenv("AIOPS_RECOVERY_MAX_SECONDS", "3600")))

    async def once(self):
        # A single checker across reloads; a crash only repeats a read-only check.
        with open(self.store.path + ".recovery.lock", "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            with self.store.connect() as db:
                row = db.execute("SELECT * FROM recovery_checks WHERE status='pending' AND next_check<=? "
                                 "ORDER BY next_check LIMIT 1", (time.time(),)).fetchone()
            if not row:
                return False
            row = dict(row)
            event = json.loads(row["payload"])
            now = time.time()
            gap = row["last_check"] is not None and now-row["last_check"] > 2*self.interval
            since = row["healthy_since"] if not gap else None
            quiet = now-since if since is not None else 0
            try:
                result = await asyncio.wait_for(self.probe.check(event, quiet), timeout=30)
            except Exception as exc:
                result = {"healthy": False, "reason": f"Recovery check unavailable ({type(exc).__name__}).", "evidence": []}
            self.finish(row, result, time.time(), gap)
            return True

    def finish(self, row, result, now, gap=False):
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT * FROM recovery_checks WHERE event_id=?", (row["event_id"],)).fetchone()
            if current["status"] != "pending":
                return  # A newly ingested alarm superseded this check while it ran.
            # Catch updates committed by another writer even if this worker read earlier.
            newer = db.execute("SELECT 1 FROM lifecycle_observations WHERE signal_key=? AND started_at>? LIMIT 1",
                               (row["signal_key"], row["started_at"])).fetchone()
            if newer:
                db.execute("UPDATE recovery_checks SET status='superseded' WHERE event_id=?", (row["event_id"],))
                return
            since = current["healthy_since"] if not gap else None
            samples = current["samples"] if not gap else 0
            if result.get("healthy") is True:
                since = now if since is None else since
                samples += 1
            else:
                since, samples = None, 0
            verified = since is not None and samples >= 2 and now-since >= self.stability
            expired = now-current["created_at"] >= self.max_age
            status = "verified" if verified else "unverified" if expired else "pending"
            db.execute("UPDATE recovery_checks SET status=?,healthy_since=?,samples=?,last_check=?,next_check=?,result=? WHERE event_id=?",
                       (status, since, samples, now, now+self.interval, json.dumps(result), row["event_id"]))
            if status == "pending":
                return
            event = json.loads(row["payload"])
            event["recovery"] = {"status": status, "reason": result["reason"], "samples": samples,
                "stable_seconds": int(now-since) if since is not None else 0,
                "checked_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
                "evidence": result.get("evidence", [])}
            event["evidence_links"] = build_links(event, row["thread_id"], result.get("evidence", []))
            note_id = str(uuid5(NAMESPACE_URL, "aiops:recovery:" + row["event_id"]))
            phase = "recovery_verified" if verified else "recovery_unverified"
            db.execute("INSERT OR IGNORE INTO incident_events VALUES(?,?,?,?,?,?,?)", (note_id, row["incident_id"],
                row["thread_id"], phase, json.dumps(event), "", now))
            db.execute("INSERT OR IGNORE INTO ticket_jobs(event_id,incident_id,next_attempt,updated_at) VALUES(?,?,?,?)",
                       (note_id, row["incident_id"], now, now))

    async def run(self):
        while True:
            try:
                worked = await self.once()
            except Exception as exc:
                logger.warning("Recovery worker failed (%s)", type(exc).__name__)
                worked = False
            await asyncio.sleep(0.2 if worked else 2)
