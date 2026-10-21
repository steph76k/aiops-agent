"""Real Agent Server, SQLite inbox and checkpoints; no external MCP/model calls."""

import json
import os
import re
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

import httpx


ROOT = Path(__file__).resolve().parents[1]


class ServerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.config = self.directory / "langgraph.json"
        self.config.write_text(json.dumps({
            "dependencies": [str(ROOT)],
            "graphs": {"aiops-agent": str(ROOT / "tests/fixtures/server_graph.py") + ":build_graph"},
            "http": {"app": str(ROOT / "src/api.py") + ":app"},
        }))
        self.log = open(self.directory / "server.log", "w+")
        self.addCleanup(self.log.close)
        self.client = httpx.Client(base_url=f"http://127.0.0.1:{self.port}", timeout=30)
        self.addCleanup(self.client.close)
        self.process = None
        self.addCleanup(self.stop)
        self.start()

    def start(self):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("LANGSMITH_", "LANGCHAIN_", "LANGGRAPH_", "AIOPS_", "SERVICENOW_"))}
        env.update({"PYTHONPATH": str(ROOT), "LANGSMITH_TRACING": "false",
                    "LANGCHAIN_TRACING_V2": "false", "AIOPS_INBOX_PATH": str(self.directory / "inbox.sqlite3")})
        if getattr(self, "ticket_dry_run", False):
            env.update({"SERVICENOW_INSTANCE_URL": "https://snow.invalid", "SERVICENOW_DRY_RUN": "true",
                        "AIOPS_ACTIONS_USERS": '{"operator":"test-password"}',
                        "AIOPS_AGENT_PUBLIC_URL": f"http://127.0.0.1:{self.port}"})
        self.process = subprocess.Popen([
            str(ROOT / ".venv/bin/langgraph"), "dev", "--config", str(self.config),
            "--host", "127.0.0.1", "--port", str(self.port), "--no-browser", "--no-reload", "--allow-blocking",
        ], cwd=self.directory, env=env, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                if self.client.get("/ok").is_success:
                    return
            except httpx.TransportError:
                pass
            time.sleep(0.2)
        self.log.flush()
        self.fail("Agent Server did not start:\n" + (self.directory / "server.log").read_text()[-8000:])

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def wait_event(self, event_id):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            response = self.client.get(f"/events/{event_id}")
            response.raise_for_status()
            event = response.json()
            if event["status"] in {"success", "error", "timeout", "uncertain"}:
                self.assertEqual(event["status"], "success", event)
                return event
            time.sleep(0.2)
        self.log.flush()
        self.fail("Event did not finish:\n" + (self.directory / "server.log").read_text()[-8000:])

    def test_webhook_studio_chat_and_restart(self):
        payload = {"alerts": [{"status": "firing", "labels": {
            "alertname": "PodDown", "namespace": "test", "pod": "demo"},
            "startsAt": "2026-09-12T08:00:00Z", "fingerprint": "abc"}]}
        accepted = self.client.post("/prometheus", json=payload)
        self.assertEqual(accepted.status_code, 202, accepted.text)
        event = self.wait_event(accepted.json()["events"][0]["event_id"])
        thread_id = event["thread_id"]
        state = self.client.get(f"/threads/{thread_id}/state").json()
        self.assertEqual(state["values"]["trigger_event"]["source"], "prometheus")
        self.assertEqual(state["values"]["investigation"]["scope"]["pod"], "demo")
        self.assertIn("RCA", state["values"]["investigation"]["rca"])
        answer = self.client.post("/v1/chat/completions", json={"thread_id": thread_id,
            "messages": [{"role": "user", "content": "What should I check next?"}]})
        self.assertEqual(answer.status_code, 200, answer.text)
        self.assertEqual(answer.json()["thread_id"], thread_id)
        self.assertIn("RCA", answer.json()["choices"][0]["message"]["content"])
        self.stop()
        self.start()
        self.assertEqual(self.client.get(f"/threads/{thread_id}/state").status_code, 200)
        duplicate = self.client.post("/prometheus", json=payload).json()["events"][0]
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(duplicate["run_id"], event["run_id"])
        payload["alerts"][0]["status"] = "resolved"
        resolved = self.client.post("/prometheus", json=payload).json()["events"][0]
        self.assertEqual(resolved["thread_id"], thread_id)
        self.wait_event(resolved["event_id"])
        state = self.client.get(f"/threads/{thread_id}/state").json()
        self.assertEqual(state["values"]["trigger_event"]["status"], "resolved")
        chat = self.client.post("/chat", json={"thread_id": thread_id, "message": "Explain the resolution"})
        self.assertEqual(chat.status_code, 202, chat.text)
        ids = chat.json()
        self.client.get(f"/threads/{thread_id}/runs/{ids['run_id']}/join").raise_for_status()
        state = self.client.get(f"/threads/{thread_id}/state").json()
        self.assertIsNone(state["values"]["event_action"])
        self.assertEqual(state["values"]["messages"][-1]["type"], "ai")

    def test_automatic_ticket_nodes_status_and_correlation_survive_restart(self):
        self.stop()
        self.ticket_dry_run = True
        self.start()
        payload = {"rule": "Sensitive file", "priority": "Warning", "output": "isolated test",
                   "time": "2026-09-13T14:00:00.000000001Z",
                   "output_fields": {"k8s.ns.name": "test", "k8s.pod.name": "demo"}}
        first = self.wait_event(self.client.post("/falco", json=payload).json()["events"][0]["event_id"])
        self.assertEqual(first["ticket"]["status"], "dry_run")
        retry = self.client.post(f"/events/{first['event_id']}/ticket/retry")
        self.assertEqual(retry.status_code, 409, "Completed jobs must not be replayed")
        self.assertEqual(self.client.post("/events/00000000-0000-0000-0000-000000000000/ticket/retry").status_code, 404)
        incident_id = first["ticket"]["incident_id"]
        state = self.client.get(f"/threads/{first['thread_id']}/state").json()
        self.assertEqual(state["values"]["ticket"]["status"], "dry_run")
        self.assertEqual(state["next"], [])
        self.stop()
        self.start()
        duplicate = self.client.post("/falco", json=payload).json()["events"][0]
        self.assertTrue(duplicate["duplicate"])
        payload["time"] = "2026-09-13T14:00:01.000000001Z"
        second = self.wait_event(self.client.post("/falco", json=payload).json()["events"][0]["event_id"])
        self.assertEqual(second["ticket"]["incident_id"], incident_id)
        incident = self.client.get(f"/incidents/{incident_id}").json()
        self.assertEqual(len(incident["events"]), 2)
        self.assertTrue(all(e["status"] == "dry_run" for e in incident["events"]))

        # Follow the same authenticated, two-step flow as a ticket button.
        auth = ("operator", "test-password")
        url = f"/incidents/{incident_id}/actions"
        def csrf(response):
            response.raise_for_status()
            return re.search('name="csrf" value="([^"]+)"', response.text).group(1)
        prepared = self.client.post(url, auth=auth, data={"kind": "analysis",
            "csrf": csrf(self.client.get(url, auth=auth))})
        self.assertEqual(prepared.status_code, 303, prepared.text)
        location = prepared.headers["location"]
        confirmed = self.client.post(location, auth=auth,
            data={"csrf": csrf(self.client.get(location, auth=auth))})
        self.assertEqual(confirmed.status_code, 303, confirmed.text)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            incident = self.client.get(f"/incidents/{incident_id}").json()
            analysis = [e for e in incident["events"] if e["phase"] == "analysis"]
            if analysis and analysis[0]["status"] == "dry_run":
                break
            time.sleep(0.2)
        else:
            self.fail("Operator analysis did not reach the original incident outbox")
        self.assertIn("success", self.client.get(location, auth=auth).text)
        state = self.client.get(f"/threads/{second['thread_id']}/state").json()
        self.assertEqual(state["values"]["event_action"], "analysis")
        self.assertIn("detailed analysis", state["values"]["selected_prompt"])
