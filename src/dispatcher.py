"""Submit inbox entries to the same Agent Server used by Studio."""

import asyncio
import fcntl
import json
import logging
import time

import httpx

from src.inbox import Inbox

logger = logging.getLogger(__name__)


class Dispatcher:
    def __init__(self, inbox: Inbox, client):
        self.inbox, self.client = inbox, client

    async def matching_run(self, row):
        offset = 0
        while True:
            runs = await self.client.runs.list(row["thread_id"], limit=100, offset=offset)
            for run in runs:
                if run.get("metadata", {}).get("event_id") == row["event_id"]:
                    return run
            if len(runs) < 100:
                return None
            offset += len(runs)

    async def once(self):
        row = await asyncio.to_thread(self.inbox.claim)
        if not row:
            return False
        event_id = row["event_id"]
        status = row["status"]
        try:
            if row["run_id"]:
                run = await self.client.runs.get(row["thread_id"], row["run_id"])
            else:
                event = json.loads(row["payload"])
                await self.client.threads.create(thread_id=row["thread_id"], if_exists="do_nothing",
                                                 metadata={"event_thread_id": row["thread_id"], "source": event["source"]})
                run = await self.matching_run(row)
                if run is None and status == "uncertain":
                    await asyncio.to_thread(self.inbox.update, event_id, lease_until=0,
                        next_attempt=time.time() + 30,
                        error="Submission outcome unknown; reconciling runs, no automatic resubmission.")
                    return True
                if run is None:
                    status = "dispatching"
                    await asyncio.to_thread(self.inbox.update, event_id, status=status,
                                            attempts=row["attempts"] + 1)
                    run = await self.client.runs.create(
                        row["thread_id"], "aiops-agent",
                        input={"event_input": event, "event_action": None},
                        metadata={"event_id": event_id, "event_thread_id": row["thread_id"], "source": event["source"]},
                        config={"recursion_limit": 50}, multitask_strategy="enqueue",
                        durability="sync",
                    )
            status = run["status"] if run["status"] in {"success", "error", "timeout", "interrupted"} else "submitted"
            await asyncio.to_thread(self.inbox.update, event_id, status=status,
                                    run_id=run["run_id"], lease_until=0,
                                    next_attempt=time.time() + 2, error=None)
        except Exception as exc:
            # Connection establishment failed: no HTTP request reached the server.
            if status == "dispatching":
                status = "pending" if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout)) else "uncertain"
            await asyncio.to_thread(self.inbox.update, event_id, status=status,
                lease_until=0, next_attempt=time.time() + min(60, 2 ** min(row["attempts"] + 1, 6)),
                error=f"{type(exc).__name__}: {exc}"[:500])
            logger.warning("Event %s dispatch failed (%s)", event_id, type(exc).__name__)
        return True

    async def run(self):
        # One dispatcher per local inbox, including during overlapping reloads.
        # SQLite remains the durable store; the OS releases this lock on a crash.
        with open(self.inbox.path + ".worker.lock", "a") as lock:
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    await asyncio.sleep(1)
            while True:
                try:
                    worked = await self.once()
                except Exception:
                    logger.exception("Inbox worker failed; will retry")
                    worked = False
                await asyncio.sleep(0.1 if worked else 1)
