"""Real graph nodes with a mocked ServiceNow transport and isolated persistence."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

import httpx
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.checkpoint.memory import InMemorySaver

from src.api import envelope
from src.graph import build_basic_graph
from src.incidents import IncidentStore
from src.servicenow import ServiceNowClient
from tests.test_event_flow import event


class Model:
    def __init__(self):
        self.calls = 0

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages):
        self.calls += 1
        return AIMessage(content="RCA: a simulated fault. Confidence: high")


class TicketGraphTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = temp.name + "/inbox.sqlite3"
        env = patch.dict(os.environ, {
            "AIOPS_INBOX_PATH": self.path, "SERVICENOW_INSTANCE_URL": "https://snow.invalid",
            "SERVICENOW_USER": "fake", "SERVICENOW_PASSWORD": "fake",
            "SERVICENOW_DRY_RUN": "false", "SERVICENOW_CORRELATION_FIELD": "correlation_id",
            "AIOPS_INCIDENT_WINDOW_SECONDS": "3600",
        })
        env.start()
        self.addCleanup(env.stop)
        self.remotes = {}
        self.writes = []

        def handle(request):
            if request.method == "GET":
                if request.url.path.endswith("/incident"):
                    key = request.url.params["sysparm_query"].split("=", 1)[1]
                    result = [r for r in self.remotes.values() if r["correlation_id"] == key]
                else:
                    result = self.remotes[request.url.path.rsplit("/", 1)[1]]
            else:
                body = json.loads(request.content)
                self.writes.append((request.method, body))
                if request.method == "POST":
                    identity = f"{len(self.remotes)+1:032x}"
                    result = {"sys_id": identity, "number": f"INC{len(self.remotes)+1:07}",
                              "active": "true", "state": "1", "correlation_id": body["correlation_id"]}
                    self.remotes[identity] = result
                else:
                    result = self.remotes[request.url.path.rsplit("/", 1)[1]]
            return httpx.Response(200, json={"result": result})

        transport = httpx.MockTransport(handle)
        client_patch = patch("src.servicenow.ServiceNowClient",
                             lambda settings: ServiceNowClient(settings, transport=transport))
        client_patch.start()
        self.addCleanup(client_patch.stop)
        self.model = Model()
        self.graph = build_basic_graph(self.model, [], "Investigate.")
        self.graph.checkpointer = InMemorySaver()

    async def invoke(self, payload):
        return await self.graph.ainvoke({"event_input": payload},
            {"configurable": {"thread_id": payload["thread_id"]}})

    async def test_rca_auto_create_chat_and_resolved(self):
        first_event = event()
        first = await self.invoke(first_event)
        self.assertEqual(first["ticket"]["status"], "success")
        self.assertEqual(self.writes[0][0], "POST")
        self.assertIn("RCA: a simulated fault", self.writes[0][1]["description"])
        self.assertNotIn("__interrupt__", first)
        self.assertIn("sync_servicenow", self.graph.get_graph().nodes)
        config = {"configurable": {"thread_id": first_event["thread_id"]}}
        await self.graph.ainvoke({"messages": [HumanMessage("Explain the finding")]}, config)
        self.assertEqual(len(self.writes), 1, "Chat must not create/update a ticket")
        model_calls = self.model.calls
        resolved = await self.invoke(event(status="resolved"))
        self.assertEqual(self.model.calls, model_calls, "Resolved must not repeat RCA")
        self.assertEqual(resolved["incident_id"], first["incident_id"])
        self.assertEqual([method for method, _ in self.writes], ["POST", "PATCH"])
        self.assertNotIn("state", self.writes[-1][1], "Resolved must not auto-close")
        store = IncidentStore(self.path)
        self.assertEqual(len(store.get(first["incident_id"])["events"]), 2)

    async def test_distinct_falco_events_share_ticket_and_replay_does_not_write(self):
        raw = {"rule": "Sensitive file", "priority": "Warning", "output": "test",
               "time": "2026-09-13T14:00:00.000000001Z", "output_fields": {
                   "k8s.ns.name": "test", "k8s.pod.name": "demo"}}
        one = envelope("falco", raw)
        first = await self.invoke(one)
        second = await self.invoke(envelope("falco", {**raw, "time": "2026-09-13T14:00:01.000000001Z"}))
        self.assertEqual(first["incident_id"], second["incident_id"])
        self.assertEqual([m for m, _ in self.writes], ["POST", "PATCH"])
        await self.invoke(one)
        self.assertEqual(len(self.writes), 2)

    async def test_resolved_without_existing_episode_does_not_write(self):
        state = await self.invoke(event(status="resolved"))
        self.assertEqual(state["ticket"]["status"], "ignored")
        self.assertEqual(self.model.calls, 0)
        self.assertEqual(self.writes, [])

    async def test_flapping_skips_third_rca_but_retains_event_and_ticket(self):
        with patch.dict(os.environ, {"AIOPS_FLAP_THRESHOLD": "3", "AIOPS_FLAP_WINDOW_SECONDS": "1800"}):
            first = await self.invoke(event(startsAt="2026-09-26T08:00:00Z"))
            await self.invoke(event(startsAt="2026-09-26T08:05:00Z"))
            third = await self.invoke(event(startsAt="2026-09-26T08:10:00Z"))
        self.assertEqual(self.model.calls, 2)
        self.assertEqual(third["incident_id"], first["incident_id"])
        self.assertEqual(third["event_action"], "recurrence")
        self.assertEqual(len(self.writes), 3)
        note = self.writes[-1][1]["work_notes"]
        self.assertIn("FLAPPING", note)
        self.assertIn("3 alarm episodes", note)
        self.assertIn("not been freshly revalidated", note)
