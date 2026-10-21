from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.events import normalize_event
from src.inbox import Inbox
from src.incidents import IncidentStore
from src.lifecycle import prepare_lifecycle
from tests.test_event_flow import event as envelope


def signal(start, status="firing", **changes):
    return {"source": "prometheus", "cluster": "default", "status": status,
            "event_type": "PodDown", "namespace": "test", "pod": "demo",
            "starts_at": datetime.fromtimestamp(start, timezone.utc).isoformat(),
            "severity": "warning", "fingerprint": "abc", "labels": {}, **changes}


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = str(Path(temp.name) / "inbox.sqlite3")
        self.store = IncidentStore(self.path)
        env = patch.dict(os.environ, {"AIOPS_INBOX_PATH": self.path,
            "SERVICENOW_INSTANCE_URL": "https://snow.invalid", "AIOPS_FLAP_WINDOW_SECONDS": "1800",
            "AIOPS_FLAP_THRESHOLD": "3", "AIOPS_RECOVERY_ENABLED": "true"})
        env.start()
        self.addCleanup(env.stop)

    def prepare(self, number, start, **changes):
        return prepare_lifecycle({"event_action": "investigate", "event_id": f"e{number}",
            "event_thread_id": f"t{number}", "trigger_event": signal(start, **changes)})

    def test_three_episodes_reuse_recent_analysis_but_not_duplicate_delivery(self):
        self.store.record("e1", "t1", signal(1000), "Original RCA")
        self.store.record("e1", "t1", signal(1000), "Duplicate")
        self.store.record("e2", "t2", signal(1200), "Second RCA")
        result = self.prepare(3, 1400)
        self.assertEqual(result["event_action"], "recurrence")
        self.assertEqual(result["trigger_event"]["recurrence"]["episodes"], 3)
        self.assertEqual(result["trigger_event"]["rca_reused_from"], "e2")

    def test_different_series_or_window_does_not_flap(self):
        self.store.record("e1", "t1", signal(1000), "RCA")
        self.store.record("e2", "t2", signal(1200), "RCA")
        for start, changes in [(1400, {"fingerprint": "different"}), (5000, {})]:
            result = self.prepare(str(start), start, **changes)
            self.assertNotIn("event_action", result)
            self.assertFalse(result["trigger_event"]["recurrence"]["flapping"])

    def test_escalated_severity_and_expired_analysis_are_not_reused(self):
        self.store.record("e1", "t1", signal(1000), "RCA")
        self.store.record("e2", "t2", signal(1200), "RCA")
        self.assertNotIn("event_action", self.prepare(3, 1400, severity="critical"))
        with self.store.connect() as db:
            db.execute("UPDATE incident_events SET created_at=1")
        self.assertNotIn("event_action", self.prepare(4, 1600))

    def test_ingress_supersedes_recovery_before_rca_and_duplicate_does_not(self):
        inbox = Inbox(self.path)
        first = envelope(startsAt="2026-09-26T08:00:00Z")
        inbox.accept([first])
        normal = normalize_event(first["source"], first["raw"], first["cluster"])
        self.store.record(first["event_id"], first["thread_id"], normal, "RCA")
        self.store.record("resolved", first["thread_id"], {**normal, "status": "resolved"}, "")
        inbox.accept([first])
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT status FROM recovery_checks").fetchone()[0], "pending")
        inbox.accept([envelope(startsAt="2026-09-26T08:10:00Z")])
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT status FROM recovery_checks").fetchone()[0], "superseded")

    def test_late_resolved_event_cannot_start_obsolete_verification(self):
        self.store.record("e1", "t1", signal(1000), "RCA")
        self.store.record("e2", "t2", signal(1400), "RCA")
        self.store.record("r1", "t1", signal(1000, "resolved"), "")
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT status FROM recovery_checks").fetchone()[0], "superseded")

    def test_record_preserves_recurrence_without_mutating_input(self):
        event = signal(1000)
        self.store.record("e1", "t1", event, "RCA")
        self.assertNotIn("recurrence", event)
        with self.store.connect() as db:
            payload = json.loads(db.execute("SELECT payload FROM incident_events").fetchone()[0])
        self.assertEqual(payload["recurrence"]["episodes"], 1)
