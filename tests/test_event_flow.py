import asyncio
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import httpx
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.checkpoint.memory import InMemorySaver

from src.api import app, envelope
from src.dispatcher import Dispatcher
from src.events import AlertmanagerWebhook, FalcoWebhook
from src.graph import build_basic_graph, record_tool_evidence
from src.inbox import Inbox


def alert(status="firing", **changes):
    return {"status": status, "labels": {"alertname": "PodDown", "namespace": "test", "pod": "demo"},
            "annotations": {"summary": "Pod is unavailable"}, "startsAt": "2026-09-12T08:00:00Z",
            "fingerprint": "abc", **changes}


def event(**changes):
    return envelope("prometheus", AlertmanagerWebhook(alerts=[alert(**changes)]).alerts[0].model_dump(mode="json"))


class EventTests(unittest.TestCase):
    def test_episode_and_phase_identity(self):
        firing = event()
        self.assertEqual(firing["event_id"], event(annotations={"summary": "changed"})["event_id"])
        resolved = event(status="resolved")
        self.assertEqual(firing["thread_id"], resolved["thread_id"])
        self.assertNotEqual(firing["event_id"], resolved["event_id"])
        self.assertNotEqual(firing["thread_id"], event(startsAt="2026-09-13T08:00:00Z")["thread_id"])
        self.assertEqual(firing["thread_id"], event(startsAt="2026-09-12T10:00:00+02:00")["thread_id"])

    def test_falco_retains_nanoseconds(self):
        raw = {"rule": "Shell", "priority": "Warning", "output": "shell opened",
               "time": "2026-09-12T08:00:00.123456789Z"}
        first = envelope("falco", FalcoWebhook(**raw).model_dump(mode="json"))
        raw["time"] = "2026-09-12T08:00:00.123456790Z"
        second = envelope("falco", FalcoWebhook(**raw).model_dump(mode="json"))
        self.assertNotEqual(first["event_id"], second["event_id"])

    def test_evidence_keeps_scope_history_and_turn_boundary(self):
        original = {"scope": {"type": "pod", "pod": "demo"}, "turn_started_at_message_count": 1,
                    "historical_evidence": [{"source": "old"}]}
        state = {"investigation": original, "messages": [HumanMessage("help"),
                 ToolMessage(content="result", tool_call_id="x", name="pods_log")]}
        result = record_tool_evidence(state)["investigation"]
        self.assertEqual(result["scope"], original["scope"])
        self.assertEqual(result["historical_evidence"], original["historical_evidence"])
        self.assertEqual(result["turn_started_at_message_count"], 1)
        self.assertEqual(len(result["current_evidence"]), 1)


class InboxTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.inbox = Inbox(str(Path(self.temp.name) / "inbox.sqlite3"))
        self.client = AsyncMock()
        self.client.runs.list.return_value = []
        self.client.runs.create.return_value = {"run_id": str(uuid4()), "status": "pending"}
        self.worker = Dispatcher(self.inbox, self.client)

    async def asyncTearDown(self):
        self.temp.cleanup()

    async def test_concurrent_delivery_is_deduplicated_and_survives_reopen(self):
        ev = event()
        results = await asyncio.gather(*(asyncio.to_thread(self.inbox.accept, [ev]) for _ in range(8)))
        self.assertEqual(sum(not result[0]["duplicate"] for result in results), 1)
        reopened = Inbox(self.inbox.path)
        self.assertEqual(reopened.get(ev["event_id"])["status"], "pending")
        await self.worker.once()
        self.client.runs.create.assert_awaited_once()
        self.assertEqual(reopened.get(ev["event_id"])["status"], "submitted")

    async def test_response_lost_is_reconciled_after_restart(self):
        ev = event()
        self.inbox.accept([ev])
        self.client.runs.create.side_effect = httpx.ReadTimeout("lost response")
        await self.worker.once()
        self.assertEqual(self.inbox.get(ev["event_id"])["status"], "uncertain")
        run = {"run_id": str(uuid4()), "status": "success", "metadata": {"event_id": ev["event_id"]}}
        self.client.runs.list.return_value = [run]
        self.inbox.update(ev["event_id"], next_attempt=0)
        await Dispatcher(Inbox(self.inbox.path), self.client).once()
        self.client.runs.create.assert_awaited_once()
        self.assertEqual(self.inbox.get(ev["event_id"])["run_id"], run["run_id"])
        self.assertEqual(self.inbox.get(ev["event_id"])["status"], "success")

    async def test_unknown_submission_never_blindly_retries(self):
        ev = event()
        self.inbox.accept([ev])
        self.inbox.update(ev["event_id"], status="dispatching", lease_until=0)
        await self.worker.once()
        self.client.runs.create.assert_not_awaited()
        self.assertEqual(self.inbox.get(ev["event_id"])["status"], "uncertain")

    async def test_server_unavailable_before_submission_retries(self):
        ev = event()
        self.inbox.accept([ev])
        self.client.threads.create.side_effect = httpx.ConnectError("offline")
        await self.worker.once()
        self.assertEqual(self.inbox.get(ev["event_id"])["status"], "pending")
        self.client.threads.create.side_effect = None
        self.inbox.update(ev["event_id"], next_attempt=0)
        await self.worker.once()
        self.client.runs.create.assert_awaited_once()

    async def test_resolved_waits_for_firing_run(self):
        firing, resolved = event(), event(status="resolved")
        self.inbox.accept([firing, resolved])
        await self.worker.once()
        self.assertFalse(await self.worker.once())
        self.inbox.update(firing["event_id"], status="success")
        await self.worker.once()
        self.assertEqual(self.client.runs.create.await_count, 2)

    async def test_polling_old_runs_does_not_starve_new_events(self):
        old, new = event(), event(fingerprint="other")
        self.inbox.accept([old, new])
        self.inbox.update(old["event_id"], status="submitted", next_attempt=1,
                          run_id=str(uuid4()))
        self.assertEqual(self.inbox.claim()["event_id"], new["event_id"])

    async def test_webhook_batch_validation_and_chat(self):
        app.state.inbox, app.state.client = self.inbox, self.client
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as web:
            response = await web.post("/prometheus", json={"status": "firing", "alerts": [alert(),
                alert(status="resolved", fingerprint="def"), alert(labels={"alertname": "Watchdog"})]})
            self.assertEqual(response.status_code, 202)
            body = response.json()
            self.assertEqual(len(body["events"]), 2)
            self.assertEqual(body["ignored"], 1)
            self.assertEqual((await web.post("/falco", json={})).status_code, 422)
            thread = body["events"][0]["thread_id"]
            response = await web.post("/chat", json={"thread_id": thread, "message": "Was soll ich prüfen?"})
            self.assertEqual(response.status_code, 202)
            call = self.client.runs.create.call_args
            self.assertEqual(call.args[0], thread)
            self.assertEqual(call.kwargs["input"]["messages"][0]["content"], "Was soll ich prüfen?")
            self.assertEqual(call.kwargs["multitask_strategy"], "enqueue")
            bad = await web.post("/v1/chat/completions", json={"thread_id": thread,
                "messages": [{"role": "user", "content": "old"}, {"role": "user", "content": "new"}]})
            self.assertEqual(bad.status_code, 422)


class FakeModel:
    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages):
        return AIMessage(content="RCA: test evidence. Confidence level: low")


class GraphTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        isolation = patch.dict(os.environ, {"SERVICENOW_INSTANCE_URL": "", "SERVICENOW_DRY_RUN": "true"})
        isolation.start()
        self.addCleanup(isolation.stop)

    async def test_event_rca_followup_and_resolved(self):
        graph = build_basic_graph(FakeModel(), [], "Investigate read-only.")
        # Agent Server supplies the checkpointer in deployment.
        graph.checkpointer = InMemorySaver()
        config = {"configurable": {"thread_id": str(uuid4())}}
        first = await graph.ainvoke({"event_input": event()}, config)
        self.assertEqual(first["investigation"]["scope"]["pod"], "demo")
        self.assertIn("RCA", first["investigation"]["rca"])
        followup = await graph.ainvoke({"messages": [HumanMessage("What should I check next?")]}, config)
        self.assertEqual(followup["investigation"]["scope"]["pod"], "demo")
        self.assertGreater(len(followup["messages"]), len(first["messages"]))
        resolved = await graph.ainvoke({"event_input": event(status="resolved")}, config)
        self.assertEqual(resolved["trigger_event"]["status"], "resolved")
        self.assertEqual(resolved["investigation"], followup["investigation"])
        final = await graph.ainvoke({"messages": [HumanMessage("Explain the resolution")]}, config)
        self.assertIsNone(final["event_action"])
        self.assertIsInstance(final["messages"][-1], AIMessage)


if __name__ == "__main__":
    unittest.main()
