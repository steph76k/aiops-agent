import json
import os
import re
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from fastapi import FastAPI
import httpx
from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import InMemorySaver
from jsonschema.exceptions import ValidationError

from src.action_routes import router
from src.actions import ActionStore, ActionWorker
from src.action_plans import contract, execute_plan, prepare_plan, validate_steps
from src.agent import filter_tools
from src.graph import build_basic_graph, tool_budget
from src.incidents import IncidentStore
from src.ticket_format import format_note


class ActionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.env = patch.dict(os.environ, {
            "AIOPS_AGENT_PUBLIC_URL": "https://agent.example", "AIOPS_ACTIONS_USERS": '{"alice":"secret","bob":"other"}',
            "AIOPS_REMEDIATION_MCP_URL": "https://mcp.example/mcp", "AIOPS_REMEDIATION_CLUSTER": "cluster1",
            "AIOPS_REMEDIATION_NAMESPACES": "test", "AIOPS_INBOX_PATH": self.temp.name + "/inbox.db",
            "SERVICENOW_INSTANCE_URL": "https://snow.invalid", "SERVICENOW_DRY_RUN": "true",
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.incidents = IncidentStore()
        self.store = ActionStore(self.incidents)
        self.thread_id, self.event_id = str(uuid4()), str(uuid4())
        self.event = {"source": "prometheus", "status": "firing", "event_type": "PodDown",
                      "cluster": "cluster1", "namespace": "test", "pod": "demo", "thread_id": self.thread_id}
        self.incident_id = self.incidents.record(self.event_id, self.thread_id, self.event, "Old RCA")
        app = FastAPI()
        app.include_router(router)
        app.state.actions = self.store
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://agent.example")
        self.addAsyncCleanup(self.client.aclose)
        self.client.auth = ("alice", "secret")
        self.url = f"/incidents/{self.incident_id}/actions"

    def csrf(self, page):
        return re.search('name="csrf" value="([^"]+)"', page.text).group(1)

    async def test_get_is_inert_auth_and_csrf_required(self):
        self.assertEqual((await self.client.get(self.url, auth=("alice", "wrong"))).status_code, 401)
        response = await self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertIsNone(self.store.claim())
        self.assertEqual((await self.client.post(self.url, data={"kind": "analysis"})).status_code, 403)
        with patch("src.action_routes.time.time", return_value=time.time() + 700):
            self.assertEqual((await self.client.post(self.url, data={"kind": "analysis", "csrf": self.csrf(response)})).status_code, 403)

    async def test_confirmation_is_bound_to_actor_and_idempotent(self):
        page = await self.client.get(self.url)
        prepared = await self.client.post(self.url, data={"kind": "analysis", "csrf": self.csrf(page)}, follow_redirects=False)
        self.assertEqual(prepared.status_code, 303)
        location = prepared.headers["location"]
        self.assertIsNone(self.store.claim())
        confirmation = await self.client.get(location)
        token = self.csrf(confirmation)
        self.assertEqual((await self.client.post(location, data={"csrf": token}, auth=("bob", "other"))).status_code, 403)
        for _ in range(2):
            self.assertEqual((await self.client.post(location, data={"csrf": token}, follow_redirects=False)).status_code, 303)
        action = self.store.claim()
        self.assertEqual(action["kind"], "analysis")
        self.assertIsNone(self.store.claim())

    def tools(self):
        def tool(name, properties, required):
            return SimpleNamespace(name=name, description=name, metadata={},
                args_schema={"type": "object", "properties": properties, "required": required, "additionalProperties": False},
                ainvoke=AsyncMock(return_value="ok"))
        string = {"type": "string"}
        target = {"namespace": string, "name": string}
        self.catalog = {
            "pods_get": tool("pods_get", target, ["namespace", "name"]),
            "pods_exec": tool("pods_exec", {**target, "container": string,
                "command": {"type": "array", "items": string}}, ["namespace", "name", "container", "command"]),
            "resources_scale": tool("resources_scale", {**target, "apiVersion": string, "kind": string,
                "scale": {"type": "integer"}}, ["namespace", "name", "apiVersion", "kind"]),
            "resources_create_or_update": tool("resources_create_or_update", {"resource": string}, ["resource"]),
            "resources_delete": tool("resources_delete", {**target, "apiVersion": string, "kind": string},
                                     ["namespace", "name", "apiVersion", "kind"]),
        }
        return self.catalog

    def make_plan(self, tool="resources_scale", arguments=None):
        if not hasattr(self, "catalog"):
            self.tools()
        arguments = arguments if arguments is not None else {
            "namespace": "test", "name": "demo", "apiVersion": "apps/v1", "kind": "Deployment", "scale": 2}
        return {"summary": "Replikazahl korrigieren", "risks": "Zusätzliche Ressourcen erforderlich.", "steps": [
            {"title": "Maßnahme", "tool": tool, "arguments": arguments, "phase": "action",
             "expected_result": "Ziel erreicht", "contract": contract(self.catalog[tool])},
            {"title": "Prüfen", "tool": "pods_get", "arguments": {"namespace": "test", "name": "demo"},
             "phase": "verification", "expected_result": "Pod gesund", "contract": contract(self.catalog["pods_get"])}]}

    def create_plan(self, plan=None, purpose="remediation"):
        return self.store.create(self.incident_id, "alice", "plan", plan=plan or self.make_plan(), purpose=purpose,
                                 event_id=self.event_id, endpoint=os.environ["AIOPS_REMEDIATION_MCP_URL"])

    def approve(self, action):
        self.store.confirm(action["action_id"], "alice")
        return self.store.claim()

    def test_scope_expiry_and_closed_incident(self):
        with patch.dict(os.environ, {"AIOPS_REMEDIATION_NAMESPACES": "other"}):
            with self.assertRaises(ValueError):
                self.create_plan()
        for kind in ("restart", "exec"):
            with self.assertRaises(ValueError):
                self.store.create(self.incident_id, "alice", kind)
        action = self.create_plan()
        with patch("src.actions.time.time", return_value=time.time() + 601):
            with self.assertRaises(ValueError):
                self.store.confirm(action["action_id"], "alice")
        self.incidents.record(str(uuid4()), self.thread_id, {**self.event, "status": "resolved"}, "")
        with self.assertRaises(ValueError):
            self.store.confirm(action["action_id"], "alice")
        with self.incidents.connect() as db:
            db.execute("UPDATE incidents SET state='closed'")
        with self.assertRaises(ValueError):
            self.store.create(self.incident_id, "alice", "analysis")

    async def test_plan_is_inert_until_approved_and_exact_arguments_are_executed(self):
        plan = self.make_plan("pods_exec", {"name": "demo", "namespace": "test", "container": "app", "command": ["ls", "/tmp"]})
        action = self.create_plan(plan, "analysis")
        with self.assertRaises(ValueError):
            await execute_plan(action, AsyncMock(return_value=self.catalog))
        self.assertIsNone(self.store.claim())
        self.store.confirm(action["action_id"], "alice")
        self.catalog["pods_exec"].ainvoke.return_value = "SECRET OUTPUT"
        with patch("src.actions.remediation_tools", AsyncMock(return_value=self.catalog)), patch(
                "src.action_plans.summarize_results", AsyncMock(return_value="Diagnose abgeschlossen")):
            worker = ActionWorker(self.store, None)
            await worker.once()
            await worker.once()
        self.catalog["pods_exec"].ainvoke.assert_awaited_once_with(plan["steps"][0]["arguments"])
        self.assertEqual(self.store.get(action["action_id"])["status"], "success")
        self.assertEqual([s["status"] for s in self.store.steps(action["action_id"])], ["completed", "completed"])
        with self.incidents.connect() as db:
            note = db.execute("SELECT rca FROM incident_events WHERE event_id=?", (action["action_id"],)).fetchone()[0]
        self.assertIn("alice", note)
        self.assertIn("ls", note)
        self.assertNotIn("SECRET OUTPUT", note)
        self.assertEqual(self.incidents.event_ticket(action["action_id"])["incident_id"], self.incident_id)

    async def test_expired_queued_and_ambiguous_calls_are_never_replayed(self):
        action = self.create_plan()
        self.store.confirm(action["action_id"], "alice")
        executor = AsyncMock(side_effect=TimeoutError())
        worker = ActionWorker(self.store, None, executor)
        with patch("src.actions.time.time", return_value=time.time() + 601):
            await worker.once()
        executor.assert_not_awaited()
        self.assertEqual(self.store.get(action["action_id"])["status"], "expired")
        action = self.create_plan()
        self.store.confirm(action["action_id"], "alice")
        with self.assertLogs("src.actions", level="ERROR"):
            await worker.once()
        await worker.once()
        executor.assert_awaited_once()
        self.assertEqual(self.store.get(action["action_id"])["status"], "uncertain")

    async def test_generic_plan_supports_scale_create_and_delete_in_order(self):
        plan = self.make_plan()
        for tool, args in [
            ("resources_create_or_update", {"resource": 'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: demo, namespace: test}\ndata: {mode: safe}'}),
            ("resources_delete", {"name": "old", "namespace": "test", "apiVersion": "v1", "kind": "ConfigMap"})]:
            plan["steps"].insert(-1, {"title": tool, "tool": tool, "arguments": args, "phase": "action",
                                   "expected_result": "Änderung angewendet", "contract": contract(self.catalog[tool])})
        action = self.approve(self.create_plan(plan))
        order = []
        for name, tool in self.catalog.items():
            async def invoke(args, name=name):
                order.append(name)
                return "ok"
            tool.ainvoke.side_effect = invoke
        await execute_plan(action, AsyncMock(return_value=self.catalog), summarize=AsyncMock(return_value="Geprüft"))
        self.assertEqual(order, [step["tool"] for step in plan["steps"]])

    async def test_changed_endpoint_or_tool_contract_blocks_before_first_call(self):
        action = self.approve(self.create_plan())
        factory = AsyncMock(return_value=self.catalog)
        with patch.dict(os.environ, {"AIOPS_REMEDIATION_MCP_URL": "https://other.example"}):
            with self.assertRaises(ValueError):
                await execute_plan(action, factory)
        self.catalog["pods_get"].description = "changed"
        with self.assertRaises(ValueError):
            await execute_plan(action, factory)
        self.catalog["resources_scale"].ainvoke.assert_not_awaited()

    async def test_invalid_later_step_blocks_entire_plan_before_mutation(self):
        plan = self.make_plan()
        plan["steps"][-1]["arguments"]["name"] = 42
        action = self.approve(self.create_plan(plan))
        with self.assertRaises(ValidationError):
            await execute_plan(action, AsyncMock(return_value=self.catalog))
        self.catalog["resources_scale"].ainvoke.assert_not_awaited()

    def test_exec_requires_explicit_container_and_command(self):
        plan = self.make_plan("pods_exec", {"name": "demo", "namespace": "test", "container": "", "command": ["ls"]})
        with self.assertRaises(ValueError):
            validate_steps(plan, "analysis", self.catalog)
        plan["steps"][0]["arguments"].update(container="app", command=[])
        with self.assertRaises(ValueError):
            validate_steps(plan, "analysis", self.catalog)

    async def test_error_stops_following_steps_and_records_partial_progress(self):
        plan = self.make_plan()
        plan["steps"].insert(1, {**plan["steps"][0], "arguments": {**plan["steps"][0]["arguments"], "scale": 3}})
        action = self.create_plan(plan)
        self.store.confirm(action["action_id"], "alice")
        self.catalog["resources_scale"].ainvoke.side_effect = ["ok", TimeoutError()]
        with patch("src.actions.remediation_tools", AsyncMock(return_value=self.catalog)):
            worker = ActionWorker(self.store, None)
            with self.assertLogs("src.actions", level="ERROR"):
                await worker.once()
            await worker.once()
        self.assertEqual(self.catalog["resources_scale"].ainvoke.await_count, 2)
        self.catalog["pods_get"].ainvoke.assert_not_awaited()
        self.assertEqual([s["status"] for s in self.store.steps(action["action_id"])], ["completed", "uncertain", "skipped"])

    async def test_new_alarm_between_steps_stops_execution(self):
        action = self.create_plan()
        self.store.confirm(action["action_id"], "alice")
        async def changed(args):
            self.incidents.record(str(uuid4()), self.thread_id, self.event, "New alarm")
            return "ok"
        self.catalog["resources_scale"].ainvoke.side_effect = changed
        with patch("src.actions.remediation_tools", AsyncMock(return_value=self.catalog)):
            with self.assertLogs("src.actions", level="ERROR"):
                await ActionWorker(self.store, None).once()
        self.catalog["pods_get"].ainvoke.assert_not_awaited()

    def test_analysis_rejects_mutations_and_remediation_requires_verification(self):
        plan = self.make_plan()
        with self.assertRaises(ValueError):
            validate_steps(plan, "analysis", self.catalog)
        plan["steps"][0]["arguments"].pop("scale")
        validate_steps(plan, "analysis", self.catalog)
        plan["steps"].pop()
        with self.assertRaises(ValueError):
            validate_steps(plan, "remediation", self.catalog)

    async def test_planner_only_proposes_calls_and_uses_current_evidence(self):
        plan = self.make_plan()
        proposal = {"summary": plan["summary"], "risks": plan["risks"], "steps": [
            {k: v for k, v in {**s, "arguments_json": json.dumps(s["arguments"])}.items()
             if k not in {"arguments", "contract"}} for s in plan["steps"]]}
        model = SimpleNamespace(with_structured_output=lambda *a, **kw: SimpleNamespace(ainvoke=AsyncMock(return_value=proposal)))
        result = await prepare_plan(self.event, [{"report": "Fresh RCA"}], "remediation",
                                    tools_factory=AsyncMock(return_value=self.catalog), model=model)
        self.assertEqual(result, plan)
        for tool in self.catalog.values():
            tool.ainvoke.assert_not_awaited()

    async def test_browser_shows_entire_plan_and_confirms_once(self):
        plan = self.make_plan()
        page = await self.client.get(self.url)
        self.assertNotIn('value="restart"', page.text)
        self.assertNotIn('value="exec"', page.text)
        with patch("src.action_routes.prepare_plan", AsyncMock(return_value=plan)):
            prepared = await self.client.post(self.url, data={"kind": "remediation", "csrf": self.csrf(page)})
        self.assertEqual(prepared.status_code, 303)
        location = prepared.headers["location"]
        confirmation = await self.client.get(location)
        for value in ("resources_scale", "pods_get", "Replikazahl korrigieren", "Alle angezeigten Schritte"):
            self.assertIn(value, confirmation.text)
        self.assertIsNone(self.store.claim())
        with self.incidents.connect() as db:
            row = dict(db.execute("SELECT * FROM incident_events WHERE phase='plan_prepared'").fetchone())
        self.assertIn(location, format_note(row, html=False))
        for _ in range(2):
            response = await self.client.post(location, data={"csrf": self.csrf(confirmation)})
            self.assertEqual(response.status_code, 303)
        self.assertEqual(self.store.claim()["kind"], "plan")
        self.assertIsNone(self.store.claim())

    async def test_extended_analysis_uses_same_plan_executor_path(self):
        plan = self.make_plan("pods_exec", {"name": "demo", "namespace": "test", "container": "app", "command": ["ls"]})
        page = await self.client.get(self.url)
        with patch("src.action_routes.prepare_plan", AsyncMock(return_value=plan)) as planner:
            result = await self.client.post(self.url, data={"kind": "analysis", "access": "extended", "csrf": self.csrf(page)})
        self.assertEqual(result.status_code, 303)
        planner.assert_awaited_once()
        self.assertEqual(planner.await_args.args[2], "analysis")
        action = self.store.get(result.headers["location"].split("/")[-1])
        self.assertEqual(action["kind"], "plan")
        self.assertEqual(json.loads(action["payload"])["purpose"], "analysis")

    async def test_analysis_worker_writes_result_to_same_ticket(self):
        action = self.store.create(self.incident_id, "alice", "analysis")
        self.store.confirm(action["action_id"], "alice")
        client = SimpleNamespace(runs=SimpleNamespace(create=AsyncMock(return_value={"run_id": "run1"}),
            join=AsyncMock(), get=AsyncMock(return_value={"status": "success"})),
            threads=SimpleNamespace(get_history=AsyncMock(return_value=[{"values": {"investigation": {"rca": "Fresh detailed RCA"}}}])))
        await ActionWorker(self.store, client).once()
        self.assertEqual(self.store.get(action["action_id"])["status"], "success")
        self.assertEqual(self.incidents.event_ticket(action["action_id"])["incident_id"], self.incident_id)
        client.threads.get_history.assert_awaited_once_with(self.thread_id, limit=1, metadata={"run_id": "run1"})

    async def test_analysis_graph_refreshes_scope_then_chat_resets_budget(self):
        model = SimpleNamespace(bind_tools=lambda tools: model, ainvoke=AsyncMock(return_value=AIMessage(content="Fresh RCA")))
        graph = build_basic_graph(model, [], "Investigate")
        graph.checkpointer = InMemorySaver()
        config = {"configurable": {"thread_id": self.thread_id}}
        result = await graph.ainvoke({"analysis_input": {"event": self.event, "previous_rca": "Old RCA"}}, config)
        self.assertEqual(result["event_action"], "analysis")
        self.assertEqual(result["investigation"]["scope"]["pod"], "demo")
        self.assertIsNone(result["analysis_input"])
        self.assertEqual(tool_budget(result, 6), 12)
        self.assertNotIn("ticket", result)
        self.assertIn("detailed analysis", result["selected_prompt"])
        chat = await graph.ainvoke({"messages": [{"role": "user", "content": "Explain"}]}, config)
        self.assertIsNone(chat["event_action"])
        self.assertEqual(tool_budget(chat, 6), 6)

    def test_model_does_not_receive_privileged_or_unknown_tools(self):
        tools = [SimpleNamespace(name=name, metadata={}) for name in ("pods_exec", "pods_delete", "pods_get", "new_write_tool")]
        with patch.dict(os.environ, {"AIOPS_ENABLE_MUTATING_TOOLS": "true"}):
            self.assertEqual([t.name for t in filter_tools(tools)], ["pods_get"])

    def test_all_html_links_open_separately_and_text_keeps_urls(self):
        event = {**self.event, "evidence_links": [{"label": "Metrics", "url": "https://example.com"}]}
        row = {"incident_id": self.incident_id, "event_id": self.event_id, "thread_id": self.thread_id,
               "phase": "firing", "payload": json.dumps(event), "rca": "[RCA](https://example.com/rca)"}
        note = format_note(row)
        links = re.findall(r"<a [^>]+>", note)
        self.assertEqual(len(links), 4)
        for link in links:
            self.assertIn('target="_blank"', link)
            self.assertIn('rel="noopener noreferrer"', link)
        text = format_note(row, html=False)
        self.assertIn(self.url, text)
        self.assertNotIn("<a", text)
        self.assertLessEqual(len(format_note({**row, "rca": "Very long " * 4000})), 8000)
