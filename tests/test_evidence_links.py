import json
import os
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from langchain_core.messages import AIMessage, ToolMessage
from src.evidence_links import alert_selector, build_links, safe_url
from src.graph import record_tool_evidence


class EvidenceLinksTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"AIOPS_PROMETHEUS_PUBLIC_URL": "https://prom.example",
            "AIOPS_GRAFANA_PUBLIC_URL": "https://grafana.example", "AIOPS_GRAFANA_PROMETHEUS_UID": "prom-uid",
            "AIOPS_GRAFANA_LOKI_UID": "loki-uid", "AIOPS_AGENT_PUBLIC_URL": "https://agent.example"})
        env.start()
        self.addCleanup(env.stop)
        self.event = {"source": "prometheus", "event_type": "PodDown", "namespace": "test", "pod": "demo",
                      "starts_at": "2026-09-26T08:00:00Z", "ingest_time": "2026-09-26T08:02:00Z"}

    def test_query_links_have_exact_expression_datasource_and_time_window(self):
        evidence = [{"category": "metric", "query": 'up{instance="a:9090"}',
                     "collected_at": "2026-09-26T08:02:00Z"}]
        links = build_links(self.event, "thread-1", evidence)
        metric = next(x for x in links if x["label"] == "Grafana metrics")
        pane = json.loads(parse_qs(urlsplit(metric["url"]).query)["panes"][0])["aiops"]
        self.assertEqual(pane["queries"][0]["expr"], evidence[0]["query"])
        self.assertEqual(pane["datasource"], "prom-uid")
        self.assertEqual(pane["range"], {"from": "1790409420000", "to": "1790410020000"})
        self.assertEqual(metric["collected_at"], evidence[0]["collected_at"])
        self.assertTrue(any(x["url"] == "https://agent.example/threads/thread-1/state" for x in links))

    def test_loki_uses_observed_datasource_and_query(self):
        evidence = [{"category": "log", "query": '{pod="demo"} |= "error"', "datasource_uid": "actual-loki"}]
        link = next(x for x in build_links(self.event, "t", evidence) if x["label"] == "Grafana Loki evidence")
        pane = json.loads(parse_qs(urlsplit(link["url"]).query)["panes"][0])["aiops"]
        self.assertEqual(pane["datasource"], "actual-loki")
        self.assertEqual(pane["queries"][0]["expr"], evidence[0]["query"])

    def test_no_invented_links_without_configuration_and_unsafe_urls_rejected(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(build_links(self.event, "t"), [])
            links = build_links({**self.event, "generator_url": "https://rancher.example/proxy/graph?g0.expr=vector%281%29"}, "t")
            self.assertEqual(len(links), 1)
            self.assertIn("/proxy/graph?", links[0]["url"])
        for value in ("javascript:alert(1)", "https://u:secret@example.com", "https://bad host/a"):
            self.assertIsNone(safe_url(value))

    def test_query_arguments_are_preserved_without_other_parameters(self):
        state = {"messages": [AIMessage(content="", tool_calls=[{"id": "q1", "name": "prod_execute_query",
            "args": {"query": "up", "password": "do-not-store"}}]),
            ToolMessage(content="ok", name="prod_execute_query", tool_call_id="q1")]}
        evidence = record_tool_evidence(state)["investigation"]["current_evidence"][0]
        self.assertEqual(evidence["query"], "up")
        self.assertNotIn("password", evidence)

    def test_external_labels_not_used_and_quotes_escaped(self):
        query = alert_selector({**self.event, "pod": 'a"b', "labels": {"prometheus": "external"}})
        self.assertNotIn("prometheus=", query)
        self.assertIn('pod="a\\"b"', query)
