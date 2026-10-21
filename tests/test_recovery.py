import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from src.incidents import IncidentStore
from src.incidents import TicketWorker
from src.servicenow import Settings
from src.recovery import PrometheusProbe, RecoveryWorker, vector_result
from tests.test_lifecycle import signal
from tests.test_incidents import FakeServiceNowClient


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.probe = PrometheusProbe()
        self.probe.query = AsyncMock()
        self.event = signal(1000, generator_url="https://prom.example/graph?g0.expr=up%3D%3D0")
        env = patch.dict(os.environ, {"AIOPS_RECOVERY_CLUSTER": "default"})
        env.start()
        self.addCleanup(env.stop)

    async def test_absent_alert_and_expression_plus_fresh_positive_resource(self):
        self.probe.query.side_effect = [[], [], [1], [12]]
        result = await self.probe.check(self.event)
        self.assertTrue(result["healthy"])
        self.assertEqual(len(result["evidence"]), 4)

    async def test_empty_health_stale_health_or_unknown_expression_never_verify(self):
        for responses in ([[], [], [], []], [[], [], [1], [301]], [[], [], [0], [1]], [[], [], [float('nan')], [1]]):
            self.probe.query.side_effect = responses
            self.assertFalse((await self.probe.check(self.event))["healthy"])
        self.probe.query.side_effect = [[]]
        self.assertFalse((await self.probe.check({**self.event, "generator_url": None}))["healthy"])

    async def test_recurrence_during_window_and_current_condition_block_recovery(self):
        for responses, quiet in [([[], [1]], 600), ([[], [1]], 0), ([[1]], 0)]:
            self.probe.query.side_effect = responses
            self.assertFalse((await self.probe.check(self.event, quiet))["healthy"])

    async def test_tool_failure_unsupported_scope_and_wrong_cluster_are_unverified(self):
        self.probe.query.side_effect = RuntimeError("secret must not leak")
        result = await self.probe.check(self.event)
        self.assertFalse(result["healthy"])
        self.assertNotIn("secret", result["reason"])
        for changes in ({"pod": None}, {"cluster": "other"}):
            self.probe.query.reset_mock()
            self.assertFalse((await self.probe.check({**self.event, **changes}))["healthy"])
            self.probe.query.assert_not_called()

    def test_mcp_content_and_errors(self):
        data = {"resultType": "vector", "result": [{"metric": {}, "value": [1234, "1"]}]}
        self.assertEqual(vector_result([{"type": "text", "text": json.dumps(data)}]), [1])
        self.assertEqual(vector_result({"status": "success", "data": data}), [1])
        for bad in ({"isError": True}, {"status": "error"}, {**data, "warnings": ["partial"]},
                    {"resultType": "vector", "result": [{"value": [1, "NaN"]}]}, {"resultType": "scalar", "result": [1, "1"]}):
            with self.assertRaises(ValueError):
                vector_result(bad)


class RecoveryWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = str(Path(temp.name) / "db.sqlite3")
        env = patch.dict(os.environ, {"AIOPS_RECOVERY_ENABLED": "true", "AIOPS_RECOVERY_INTERVAL_SECONDS": "60",
            "AIOPS_RECOVERY_STABLE_SECONDS": "600", "AIOPS_RECOVERY_MAX_SECONDS": "3600"})
        env.start()
        self.addCleanup(env.stop)
        self.store = IncidentStore(self.path)
        with patch("src.incidents.time.time", return_value=2000):
            self.incident_id = self.store.record("f1", "t1", signal(1000), "RCA")
            self.store.record("r1", "t1", signal(1000, "resolved"), "")
        self.probe = AsyncMock()
        self.probe.check.return_value = {"healthy": True, "reason": "fresh checks passed", "evidence": []}
        self.worker = RecoveryWorker(self.store, self.probe)

    async def tick(self, now):
        with patch("src.recovery.time.time", return_value=now):
            return await self.worker.once()

    def check(self):
        with self.store.connect() as db:
            return dict(db.execute("SELECT * FROM recovery_checks WHERE event_id='r1'").fetchone())

    async def test_ten_minutes_and_restart_produce_exactly_one_outbox_note(self):
        for now in range(2000, 2600, 60):
            await self.tick(now)
        self.assertEqual(self.check()["status"], "pending")
        self.worker = RecoveryWorker(IncidentStore(self.path), self.probe)
        await self.tick(2600)
        self.assertEqual(self.check()["status"], "verified")
        self.assertEqual(self.check()["samples"], 11)
        self.assertFalse(await self.tick(2660))
        incident = self.store.get(self.incident_id)
        self.assertEqual([e["phase"] for e in incident["events"]], ["firing", "resolved", "recovery_verified"])
        self.assertEqual(len(incident["recovery_checks"]), 1)

    async def test_failure_and_long_sampling_gap_reset_stability(self):
        await self.tick(2000)
        await self.tick(2060)
        self.probe.check.return_value = {"healthy": False, "reason": "missing data", "evidence": []}
        await self.tick(2120)
        self.assertIsNone(self.check()["healthy_since"])
        self.probe.check.return_value = {"healthy": True, "reason": "ok", "evidence": []}
        await self.tick(2180)
        await self.tick(3000)
        self.assertEqual(self.check()["healthy_since"], 3000)
        self.assertEqual(self.check()["samples"], 1)
        self.assertEqual(self.check()["status"], "pending")

    async def test_new_firing_during_probe_supersedes_result(self):
        async def refire(*args):
            self.store.record("f2", "t2", signal(1500), "New RCA")
            return {"healthy": True, "reason": "old probe", "evidence": []}
        self.probe.check.side_effect = refire
        await self.tick(2000)
        self.assertEqual(self.check()["status"], "superseded")
        self.assertNotIn("recovery_verified", [e["phase"] for e in self.store.get(self.incident_id)["events"]])

    async def test_timeout_produces_one_unverified_note(self):
        self.probe.check.return_value = {"healthy": False, "reason": "missing data", "evidence": []}
        await self.tick(5600)
        self.assertEqual(self.check()["status"], "unverified")
        self.assertEqual(self.store.get(self.incident_id)["events"][-1]["phase"], "recovery_unverified")
        self.assertFalse(await self.tick(5700))

    async def test_duplicate_resolved_does_not_reset_or_duplicate_check(self):
        await self.tick(2000)
        before = self.check()
        self.store.record("r1", "t1", signal(1000, "resolved"), "")
        self.assertEqual(self.check(), before)

    async def test_verified_note_updates_existing_ticket_without_closing_or_duplicates(self):
        client = FakeServiceNowClient()
        tickets = TicketWorker(self.store, Settings(instance_url="https://snow.invalid", dry_run=False), client.factory)
        await tickets.once("f1")
        await tickets.once("r1")
        for now in range(2000, 2601, 60):
            await self.tick(now)
        verification_id = self.store.get(self.incident_id)["events"][-1]["event_id"]
        await tickets.once(verification_id)
        self.assertFalse(await tickets.once(verification_id))
        self.assertEqual(len(client.creates), 1)
        self.assertEqual(len(client.updates), 2)
        self.assertIn("RECOVERY VERIFIED", client.updates[-1][1]["work_notes"])
        self.assertNotIn("state", client.updates[-1][1])

    async def test_queued_recovery_note_is_skipped_after_refiring(self):
        for now in range(2000, 2601, 60):
            await self.tick(now)
        verification_id = self.store.get(self.incident_id)["events"][-1]["event_id"]
        self.store.update_job("f1", status="success")
        self.store.update_job("r1", status="success")
        self.store.record("f2", "t2", signal(1500), "New RCA")
        client = FakeServiceNowClient()
        tickets = TicketWorker(self.store, Settings(instance_url="https://snow.invalid", dry_run=False), client.factory)
        await tickets.once(verification_id)
        self.assertEqual(self.store.event_ticket(verification_id)["status"], "skipped_superseded")
        self.assertEqual(client.creates, [])
        self.assertEqual(client.updates, [])

    async def test_recovery_note_never_reopens_closed_ticket(self):
        client = FakeServiceNowClient()
        tickets = TicketWorker(self.store, Settings(instance_url="https://snow.invalid", dry_run=False), client.factory)
        await tickets.once("f1")
        await tickets.once("r1")
        for now in range(2000, 2601, 60):
            await self.tick(now)
        verification_id = self.store.get(self.incident_id)["events"][-1]["event_id"]
        remote = next(iter(client.records.values()))
        remote.update(active="false", state="7")
        await tickets.once(verification_id)
        self.assertEqual(self.store.event_ticket(verification_id)["status"], "skipped_closed")
        self.assertEqual(len(client.creates), 1)
        self.assertEqual(len(client.updates), 1)
