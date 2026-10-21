"""Correlation and durable ticket delivery, without credentials or live services."""

import asyncio
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.incidents import IncidentStore, TicketWorker
from src.servicenow import Settings, SnowAmbiguousWrite, SnowError


def event(**changes):
    return {
        "source": "falco", "status": "firing", "cluster": "cluster-a",
        "namespace": "apps", "pod": "demo-1", "node": "worker-1",
        "event_type": "Read sensitive file untrusted", "severity": "warning",
        "event_time": "2026-09-13T12:00:00Z", "labels": {}, "output_fields": {},
        **changes,
    }


class FakeServiceNowClient:
    """A fake remote store which can commit a write and lose its response."""

    def __init__(self):
        self.records = {}
        self.creates = []
        self.updates = []
        self.lookups = []
        self.contexts = 0
        self.create_error = None
        self.update_error = None
        self.lookup_error = None
        self.lose_create_response = False
        self.lose_update_response = False
        self.create_started = None
        self.release_create = None

    def factory(self, settings):
        return self

    async def __aenter__(self):
        self.contexts += 1
        return self

    async def __aexit__(self, *args):
        return False

    async def find_incident(self, correlation):
        self.lookups.append(correlation)
        if self.lookup_error is not None:
            raise self.lookup_error
        return next((deepcopy(row) for row in self.records.values()
                     if row["correlation_id"] == correlation), None)

    async def get_incident(self, sys_id):
        row = self.records.get(sys_id)
        return deepcopy(row) if row else None

    async def create_incident(self, payload):
        self.creates.append(deepcopy(payload))
        if self.create_started is not None:
            self.create_started.set()
            await self.release_create.wait()
        if self.create_error is not None:
            raise self.create_error
        serial = len(self.creates)
        row = {
            "sys_id": f"{serial:032x}", "number": f"INC{serial:07}",
            "active": "true", "state": "1", **deepcopy(payload),
        }
        self.records[row["sys_id"]] = row
        if self.lose_create_response:
            self.lose_create_response = False
            raise SnowAmbiguousWrite("Response lost after remote create")
        return deepcopy(row)

    async def update_incident(self, sys_id, payload):
        self.updates.append((sys_id, deepcopy(payload)))
        if self.update_error is not None:
            raise self.update_error
        self.records[sys_id].update(deepcopy(payload))
        if self.lose_update_response:
            self.lose_update_response = False
            raise SnowAmbiguousWrite("Response lost after remote update")
        return deepcopy(self.records[sys_id])


class IncidentStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = IncidentStore(Path(self.temp.name) / "inbox.sqlite3")

    def test_exact_duplicate_keeps_original_event_and_rca(self):
        first = self.store.record("event-1", "thread-1", event(), "Original RCA")
        duplicate = self.store.record("event-1", "thread-1", event(pod="changed"), "Changed RCA")
        self.assertEqual(first, duplicate)
        self.assertEqual(len(self.store.get(first)["events"]), 1)
        with self.store.connect() as db:
            saved = db.execute("SELECT payload,rca FROM incident_events").fetchone()
            self.assertIn('"pod": "demo-1"', saved["payload"])
            self.assertEqual(saved["rca"], "Original RCA")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ticket_jobs").fetchone()[0], 1)

    def test_distinct_falco_events_group_within_window(self):
        with patch("src.incidents.time.time", return_value=1000):
            first = self.store.record("event-1", "thread-1", event(), "RCA 1", window=60)
        with patch("src.incidents.time.time", return_value=1059):
            second = self.store.record("event-2", "thread-2", event(), "RCA 2", window=60)
        self.assertEqual(first, second)
        self.assertEqual(len(self.store.get(first)["events"]), 2)

    def test_different_resource_rule_namespace_or_cluster_stays_separate(self):
        first = self.store.record("event-1", "thread-1", event(), "RCA")
        for index, changes in enumerate((
            {"pod": "demo-2"}, {"event_type": "Terminal shell in container"},
            {"cluster": "cluster-b"}, {"namespace": "other"},
        ), start=2):
            with self.subTest(changes=changes):
                other = self.store.record(f"event-{index}", f"thread-{index}", event(**changes), "RCA")
                self.assertNotEqual(first, other)

    def test_explicit_key_correlates_sources_but_keeps_clusters_separate(self):
        falco = self.store.record("falco-1", "falco-thread", event(
            output_fields={"aiops.incident_key": "checkout-outage"}), "RCA")
        prometheus = self.store.record("prom-1", "prom-thread", event(
            source="prometheus", event_type="PodUnavailable", pod="different-pod",
            labels={"aiops_incident_key": "checkout-outage"}), "RCA")
        other_cluster = self.store.record("prom-2", "other-thread", event(
            source="prometheus", cluster="cluster-b",
            labels={"aiops_incident_key": "checkout-outage"}), "RCA")
        self.assertEqual(falco, prometheus)
        self.assertNotEqual(falco, other_cluster)

    def test_unscoped_events_do_not_collapse_into_cluster_ticket(self):
        unscoped = event(pod=None, node=None, namespace=None)
        first = self.store.record("event-1", "thread-1", unscoped, "RCA")
        second = self.store.record("event-2", "thread-2", unscoped, "RCA")
        self.assertNotEqual(first, second)

    def test_prometheus_instances_in_same_job_remain_separate(self):
        signal = event(source="prometheus", event_type="InstanceDown", pod=None,
                       node=None, job="node-exporter", service="monitoring",
                       instance="192.0.2.1:9100")
        first = self.store.record("instance-1", "thread-1", signal, "RCA")
        other_instance = self.store.record("instance-2", "thread-2", {
            **signal, "instance": "192.0.2.2:9100"}, "RCA")
        same_instance = self.store.record("instance-3", "thread-3", signal, "RCA")
        self.assertNotEqual(first, other_instance)
        self.assertEqual(first, same_instance)

    def test_pod_scope_groups_despite_changed_instance_or_node(self):
        first = self.store.record("event-1", "thread-1", event(instance="192.0.2.1:9100"), "RCA")
        second = self.store.record("event-2", "thread-2", event(
            node="worker-2", instance="192.0.2.2:9100"), "RCA")
        self.assertEqual(first, second)

    def test_fingerprint_fallback_keeps_same_job_signals_separate(self):
        signal = event(source="prometheus", pod=None, node=None,
                       job="monitoring", fingerprint="signal-a")
        first = self.store.record("event-1", "thread-1", signal, "RCA")
        different = self.store.record("event-2", "thread-2", {
            **signal, "fingerprint": "signal-b"}, "RCA")
        same = self.store.record("event-3", "thread-3", signal, "RCA")
        self.assertNotEqual(first, different)
        self.assertEqual(first, same)

    def test_retry_unknown_event_fails_without_creating_job(self):
        with self.assertRaises(KeyError):
            self.store.retry("missing")
        self.assertIsNone(self.store.event_ticket("missing"))

    def test_retry_refuses_every_status_except_confirmed_error(self):
        for index, status in enumerate(("pending", "sending", "uncertain", "success",
                                        "dry_run", "skipped_closed")):
            with self.subTest(status=status):
                event_id = f"event-{index}"
                self.store.record(event_id, f"thread-{index}", event(pod=f"pod-{index}"), "RCA")
                self.store.update_job(event_id, status=status)
                original = self.store.event_ticket(event_id)
                with self.assertRaises(ValueError):
                    self.store.retry(event_id)
                self.assertEqual(self.store.event_ticket(event_id), original)

    def test_new_episode_after_window_gets_new_incident(self):
        with patch("src.incidents.time.time", return_value=1000):
            first = self.store.record("event-1", "thread-1", event(), "RCA", window=60)
        with patch("src.incidents.time.time", return_value=1061):
            second = self.store.record("event-2", "thread-2", event(), "RCA", window=60)
        self.assertNotEqual(first, second)

    def test_resolved_uses_original_episode_beyond_window(self):
        with patch("src.incidents.time.time", return_value=1000):
            first = self.store.record("firing", "thread-1", event(source="prometheus"), "RCA", window=60)
        with patch("src.incidents.time.time", return_value=9000):
            resolved = self.store.record("resolved", "thread-1", event(
                source="prometheus", status="resolved"), "", window=60)
        self.assertEqual(first, resolved)
        self.assertEqual(self.store.get(first)["events"][-1]["phase"], "resolved")

    def test_resolved_without_firing_creates_no_incident_or_job(self):
        result = self.store.record("resolved", "unknown-thread", event(status="resolved"), "")
        self.assertIsNone(result)
        self.assertIsNone(self.store.event_ticket("resolved"))
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 0)


class TicketWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = IncidentStore(Path(self.temp.name) / "inbox.sqlite3")
        self.settings = Settings(instance_url="https://snow.invalid", user="test-user",
                                 password="test-password", dry_run=False)
        self.client = FakeServiceNowClient()
        self.worker = TicketWorker(self.store, self.settings, self.client.factory)

    async def test_one_create_then_work_note_for_correlated_event(self):
        incident_id = self.store.record("event-1", "thread-1", event(), "Initial RCA")
        self.store.record("event-2", "thread-2", event(), "Additional RCA")
        self.assertTrue(await self.worker.once("event-1"))
        self.assertTrue(await self.worker.once("event-2"))
        self.assertFalse(await self.worker.once("event-1"))
        self.assertEqual(len(self.client.creates), 1)
        self.assertEqual(len(self.client.updates), 1)
        created = self.client.creates[0]
        updated_id, update = self.client.updates[0]
        self.assertEqual(created["correlation_id"], f"aiops:{incident_id}")
        self.assertIn("Initial RCA", created["description"])
        self.assertIn("[AIOPS-EVENT:event-2]", update["work_notes"])
        self.assertIn("Additional RCA", update["work_notes"])
        self.assertEqual(updated_id, self.store.get(incident_id)["sys_id"])
        self.assertEqual(self.store.event_ticket("event-2")["status"], "success")

    async def test_dry_run_does_not_construct_or_contact_remote_client(self):
        self.store.record("event-1", "thread-1", event(), "RCA")

        def forbid_client(settings):
            self.fail("Dry run must not construct an external client")

        worker = TicketWorker(self.store, replace(self.settings, dry_run=True), forbid_client)
        self.assertTrue(await worker.once("event-1"))
        ticket = self.store.event_ticket("event-1")
        self.assertEqual(ticket["status"], "dry_run")
        self.assertEqual(ticket["attempts"], 0)
        self.assertIsNone(ticket["sys_id"])

    async def test_lost_create_response_reconciles_after_restart_without_second_post(self):
        incident_id = self.store.record("event-1", "thread-1", event(), "RCA")
        self.client.lose_create_response = True
        self.assertTrue(await self.worker.once("event-1"))
        self.assertEqual(self.store.event_ticket("event-1")["status"], "uncertain")
        reopened = IncidentStore(self.store.path)
        restarted = TicketWorker(reopened, self.settings, self.client.factory)
        self.assertTrue(await restarted.once("event-1"))
        ticket = reopened.event_ticket("event-1")
        self.assertEqual(ticket["status"], "success")
        self.assertEqual(ticket["attempts"], 1)
        self.assertEqual(ticket["number"], "INC0000001")
        self.assertEqual(reopened.get(incident_id)["sys_id"], ticket["sys_id"])
        self.assertEqual(len(self.client.creates), 1)
        self.assertEqual(self.client.updates, [])

    async def test_unknown_create_without_match_never_repeats_post(self):
        self.store.record("event-1", "thread-1", event(), "RCA")
        self.client.create_error = SnowAmbiguousWrite("Connection lost; outcome unknown")
        await self.worker.once("event-1")
        self.client.create_error = None
        for _ in range(2):
            await self.worker.once("event-1")
        self.assertEqual(len(self.client.creates), 1)
        self.assertEqual(self.store.event_ticket("event-1")["status"], "uncertain")

    async def test_lookup_failure_during_create_reconciliation_keeps_uncertain(self):
        self.store.record("event-1", "thread-1", event(), "RCA")
        self.client.lose_create_response = True
        await self.worker.once("event-1")
        self.client.lookup_error = SnowError("ServiceNow read failed", retryable=True)
        await self.worker.once("event-1")
        self.assertEqual(self.store.event_ticket("event-1")["status"], "uncertain")
        self.client.lookup_error = None
        await self.worker.once("event-1")
        self.assertEqual(self.store.event_ticket("event-1")["status"], "success")
        self.assertEqual(len(self.client.creates), 1)

    async def test_local_commit_failure_after_create_reconciles_on_restart(self):
        self.store.record("event-1", "thread-1", event(), "RCA")
        with patch.object(self.store, "link", side_effect=OSError("Local write failed")):
            await self.worker.once("event-1")
        self.assertEqual(self.store.event_ticket("event-1")["status"], "sending")
        reopened = IncidentStore(self.store.path)
        await TicketWorker(reopened, self.settings, self.client.factory).once("event-1")
        self.assertEqual(reopened.event_ticket("event-1")["status"], "success")
        self.assertEqual(len(self.client.creates), 1)

    async def test_changed_remote_correlation_is_error_without_patch(self):
        incident_id = self.store.record("event-1", "thread-1", event(), "RCA")
        await self.worker.once("event-1")
        sys_id = self.store.get(incident_id)["sys_id"]
        self.client.records[sys_id]["correlation_id"] = "aiops:00000000-0000-4000-8000-000000000000"
        self.store.record("event-2", "thread-2", event(), "More evidence")
        await self.worker.once("event-2")
        self.assertEqual(self.store.event_ticket("event-2")["status"], "error")
        self.assertEqual(len(self.client.creates), 1)
        self.assertEqual(self.client.updates, [])

    async def test_uncertain_work_note_is_not_repeated_and_blocks_later_event(self):
        self.store.record("event-1", "thread-1", event(), "RCA")
        await self.worker.once("event-1")
        self.store.record("event-2", "thread-2", event(), "More evidence")
        self.store.record("resolved-2", "thread-2", event(status="resolved"), "")
        self.client.lose_update_response = True
        await self.worker.once("event-2")
        self.assertEqual(self.store.event_ticket("event-2")["status"], "uncertain")
        reopened = IncidentStore(self.store.path)
        restarted = TicketWorker(reopened, self.settings, self.client.factory)
        await restarted.once("event-2")
        self.assertEqual(len(self.client.updates), 1)
        self.assertFalse(await restarted.once("resolved-2"))
        self.assertEqual(reopened.event_ticket("resolved-2")["status"], "pending")

    async def test_failed_older_job_prevents_resolved_from_overtaking(self):
        self.store.record("firing", "thread-1", event(source="prometheus"), "RCA")
        self.store.record("resolved", "thread-1", event(source="prometheus", status="resolved"), "")
        self.client.create_error = SnowError("ServiceNow request returned HTTP 403", status_code=403)
        await self.worker.once("firing")
        self.assertEqual(self.store.event_ticket("firing")["status"], "error")
        self.assertFalse(await self.worker.once("resolved"))
        self.assertEqual(len(self.client.creates), 1)
        self.assertEqual(self.client.updates, [])

    async def test_retry_after_corrected_401_delivers_create_and_update(self):
        incident_id = self.store.record("event-1", "thread-1", event(), "Initial RCA")
        self.client.create_error = SnowError("ServiceNow request returned HTTP 401", status_code=401)
        await self.worker.once("event-1")
        failed = self.store.event_ticket("event-1")
        self.assertEqual(failed["status"], "error")
        self.assertEqual(failed["attempts"], 1)
        self.assertEqual(self.client.records, {})

        self.client.create_error = None
        retried = self.store.retry("event-1")
        self.assertEqual(retried["status"], "pending")
        self.assertIsNone(retried["error"])
        self.assertEqual(retried["incident_id"], incident_id)
        self.assertTrue(await self.worker.once())
        self.assertEqual(self.store.event_ticket("event-1")["status"], "success")
        self.assertEqual(self.store.event_ticket("event-1")["attempts"], 2)
        self.assertEqual(len(self.client.records), 1)

        self.store.record("event-2", "thread-2", event(), "Additional RCA")
        self.client.update_error = SnowError("ServiceNow request returned HTTP 401", status_code=401)
        await self.worker.once("event-2")
        self.assertEqual(self.store.event_ticket("event-2")["status"], "error")
        sys_id = self.store.get(incident_id)["sys_id"]
        self.assertNotIn("Additional RCA", self.client.records[sys_id]["work_notes"])

        self.client.update_error = None
        self.assertEqual(self.store.retry("event-2")["status"], "pending")
        self.assertTrue(await self.worker.once())
        succeeded = self.store.event_ticket("event-2")
        self.assertEqual(succeeded["status"], "success")
        self.assertEqual(succeeded["attempts"], 2)
        self.assertEqual(succeeded["sys_id"], sys_id)
        self.assertIn("Additional RCA", self.client.records[sys_id]["work_notes"])
        self.assertEqual(len(self.client.creates), 2)
        self.assertEqual(len(self.client.updates), 2)

    async def test_remote_closed_incident_rotates_firing_and_queued_resolved(self):
        old_id = self.store.record("old-firing", "old-thread", event(), "Old RCA")
        await self.worker.once("old-firing")
        old_sys_id = self.store.get(old_id)["sys_id"]
        self.client.records[old_sys_id].update(active="false", state="7")
        self.assertEqual(self.store.record("new-firing", "new-thread", event(), "New RCA"), old_id)
        self.store.record("new-resolved", "new-thread", event(status="resolved"), "")
        await self.worker.once("new-firing")
        new_id = self.store.event_ticket("new-firing")["incident_id"]
        self.assertNotEqual(new_id, old_id)
        self.assertEqual(self.store.event_ticket("new-resolved")["incident_id"], new_id)
        self.assertEqual(self.store.event_ticket("old-firing")["incident_id"], old_id)
        self.assertEqual(self.store.get(old_id)["state"], "closed")
        await self.worker.once("new-firing")
        await self.worker.once("new-resolved")
        self.assertEqual(len(self.client.creates), 2)
        self.assertEqual(len(self.client.updates), 1)
        self.assertNotEqual(self.client.creates[0]["correlation_id"], self.client.creates[1]["correlation_id"])
        self.assertEqual(self.client.updates[0][0], self.store.get(new_id)["sys_id"])
        self.assertEqual(self.store.event_ticket("new-resolved")["status"], "success")

    async def test_resolved_for_remote_closed_incident_does_not_create_or_reopen(self):
        incident_id = self.store.record("firing", "thread-1", event(), "RCA")
        await self.worker.once("firing")
        sys_id = self.store.get(incident_id)["sys_id"]
        self.client.records[sys_id].update(active="false", state="7")
        self.store.record("resolved", "thread-1", event(status="resolved"), "")
        await self.worker.once("resolved")
        self.assertEqual(self.store.event_ticket("resolved")["status"], "skipped_closed")
        self.assertEqual(len(self.client.creates), 1)
        self.assertEqual(self.client.updates, [])

    async def test_rate_limited_update_rotates_when_remote_ticket_closed_before_retry(self):
        old_id = self.store.record("old-firing", "old-thread", event(), "Old RCA")
        await self.worker.once("old-firing")
        sys_id = self.store.get(old_id)["sys_id"]
        self.store.record("new-firing", "new-thread", event(), "New RCA")
        self.store.record("new-resolved", "new-thread", event(status="resolved"), "")
        self.client.update_error = SnowError("ServiceNow request returned HTTP 429",
                                            status_code=429, retryable=True)
        await self.worker.once("new-firing")
        limited = self.store.event_ticket("new-firing")
        self.assertEqual(limited["status"], "pending")
        self.assertEqual(limited["operation"], "update")
        self.client.update_error = None
        self.client.records[sys_id].update(active="false", state="7")
        await self.worker.once("new-firing")
        rotated = self.store.event_ticket("new-firing")
        self.assertNotEqual(rotated["incident_id"], old_id)
        self.assertIsNone(rotated["operation"])
        self.assertEqual(self.store.event_ticket("new-resolved")["incident_id"], rotated["incident_id"])
        await self.worker.once("new-firing")
        await self.worker.once("new-resolved")
        self.assertEqual(len(self.client.creates), 2)
        self.assertEqual(self.store.event_ticket("new-firing")["status"], "success")
        self.assertEqual(self.store.event_ticket("new-resolved")["status"], "success")

    async def test_missing_remote_incident_does_not_make_resolved_create_ticket(self):
        self.store.record("firing", "thread-1", event(), "RCA")
        await self.worker.once("firing")
        self.client.records.clear()
        self.store.record("resolved", "thread-1", event(status="resolved"), "")
        await self.worker.once("resolved")
        self.assertEqual(self.store.event_ticket("resolved")["status"], "error")
        self.assertEqual(len(self.client.creates), 1)
        self.assertEqual(self.client.updates, [])

    async def test_file_lock_allows_only_one_concurrent_remote_create(self):
        self.store.record("event-1", "thread-1", event(), "RCA")
        self.client.create_started = asyncio.Event()
        self.client.release_create = asyncio.Event()
        first = asyncio.create_task(self.worker.once("event-1"))
        other = TicketWorker(IncidentStore(self.store.path), self.settings, self.client.factory)
        try:
            await asyncio.wait_for(self.client.create_started.wait(), timeout=5)
            self.assertFalse(await other.once("event-1"))
            self.assertEqual(len(self.client.creates), 1)
        finally:
            self.client.release_create.set()
            await first
        self.assertEqual(self.store.event_ticket("event-1")["status"], "success")

    async def test_store_restart_retains_ticket_and_episode_mapping(self):
        incident_id = self.store.record("event-1", "thread-1", event(), "RCA")
        await self.worker.once("event-1")
        before = self.store.event_ticket("event-1")
        reopened = IncidentStore(self.store.path)
        self.assertEqual(reopened.event_ticket("event-1"), before)
        self.assertEqual(reopened.record("event-1", "thread-1", event(), "RCA"), incident_id)
        self.assertEqual(reopened.record("resolved", "thread-1", event(status="resolved"), ""), incident_id)
        await TicketWorker(reopened, self.settings, self.client.factory).once("resolved")
        self.assertEqual(len(self.client.creates), 1)
        self.assertEqual(len(self.client.updates), 1)


if __name__ == "__main__":
    unittest.main()
