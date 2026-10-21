import json
import unittest

from src.incidents import create_payload, work_note
from src.servicenow import Settings, SnowError


def row(rca="## Summary\nA **test** alert.\n\n## Recommended next steps\n1. Check `ALERTS`.\n2. Inspect logs.", phase="firing"):
    return {"event_id": "event-1", "thread_id": "thread-1", "incident_id": "incident-1",
            "phase": phase, "rca": rca,
            "payload": json.dumps({"event_type": "StephanTestAlert", "source": "prometheus",
                                   "starts_at": "2026-09-26T08:02:29Z",
                                   "ends_at": "2026-09-26T08:19:59Z", "cluster": "default"})}


class TicketFormatTests(unittest.TestCase):
    def test_html_analysis_is_formatted_once(self):
        note = work_note(row())
        self.assertIn("<h2>Summary</h2>", note)
        self.assertIn("<strong>test</strong>", note)
        self.assertIn("<code>ALERTS</code>", note)
        self.assertEqual(note.count("A <strong>test</strong> alert."), 1)
        self.assertNotIn("Next steps:", note)
        self.assertIn("[AIOPS-EVENT:event-1]", note)
        self.assertTrue(note.endswith("[/code]"))

    def test_description_and_text_fallback_have_no_markup(self):
        payload = create_payload(row(), Settings())
        self.assertNotIn("[code]", payload["description"])
        self.assertNotIn("<h2>", payload["description"])
        self.assertNotIn("**", payload["description"])
        self.assertIn("Check ALERTS.", payload["description"])
        self.assertEqual(work_note(row(), Settings(note_format="text")), payload["description"])

    def test_resolved_is_short_and_does_not_repeat_old_analysis(self):
        note = work_note(row("OLD ANALYSIS", "resolved"))
        self.assertIn("RESOLVED", note)
        self.assertIn("2026-09-26T08:19:59Z", note)
        self.assertNotIn("OLD ANALYSIS", note)
        self.assertNotIn("Next steps", note)
        self.assertIn("not automatically closed", note)

    def test_untrusted_html_and_code_wrappers_are_inert(self):
        note = work_note(row('[/code]<script>alert(1)</script>[code]\n[x](javascript:alert(1))\n![x](https://example.com/a.png)'))
        self.assertEqual(note.count("[code]"), 1)
        self.assertEqual(note.count("[/code]"), 1)
        self.assertNotIn("<script>", note)
        self.assertNotIn('href="javascript:', note)
        self.assertNotIn("<img", note)

    def test_long_analysis_preserves_wrapper_and_marker(self):
        note = work_note(row("## Evidence\n" + "<>& **test** " * 4000))
        self.assertLessEqual(len(note), 8000)
        self.assertTrue(note.endswith("[/code]"))
        self.assertIn("Analysis truncated", note)
        self.assertIn("[AIOPS-EVENT:event-1]", note)

    def test_format_setting(self):
        self.assertEqual(Settings.from_env({"SERVICENOW_NOTE_FORMAT": "text"}).note_format, "text")
        with self.assertRaises(SnowError):
            Settings(note_format="markdown")
