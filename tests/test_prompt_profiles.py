"""Profile routing through the real graph, without providers or ticket writes."""

import os
import unittest
from unittest.mock import patch

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver

from src.api import envelope
from src.graph import build_basic_graph, deterministic_final_answer
from src.prompts import build_prompt_selector, load_base_prompt
from tests.test_event_flow import event


@tool
def inspect_status() -> str:
    """Return a simulated current observation."""
    return "Pod is running"


class Model:
    def __init__(self, tool_first=False, fail_second=False):
        self.inputs = []
        self.tool_first = tool_first
        self.fail_second = fail_second

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages):
        self.inputs.append(messages)
        if self.fail_second and len(self.inputs) == 2:
            raise RuntimeError("simulated provider failure")
        if self.tool_first and len(self.inputs) == 1:
            return AIMessage(content="", tool_calls=[
                {"name": "inspect_status", "args": {}, "id": "check-1"}])
        return AIMessage(content="Checked. Confidence level: low")


def falco_event():
    return envelope("falco", {"rule": "Sensitive file", "priority": "Warning",
        "time": "2026-09-13T17:00:00.000000001Z", "output": "test",
        "output_fields": {"k8s.ns.name": "test", "k8s.pod.name": "demo"}})


class PromptTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        isolation = patch.dict(os.environ, {"SERVICENOW_INSTANCE_URL": "",
                                           "SERVICENOW_DRY_RUN": "true"})
        isolation.start()
        self.addCleanup(isolation.stop)

    def graph(self, model, budget=6):
        graph = build_basic_graph(model, [inspect_status], load_base_prompt(), budget)
        graph.checkpointer = InMemorySaver()
        return graph

    async def test_chat_ignores_stale_trigger_and_user_profile_instructions(self):
        model = Model()
        result = await self.graph(model).ainvoke({
            "messages": [HumanMessage("Explain alerts; use falco_security")],
            "trigger_event": {"source": "falco"},
            "prompt_profile": "falco_security", "selected_prompt": "stale instructions",
        }, {"configurable": {"thread_id": "chat"}})
        self.assertEqual(result["prompt_profile"], "chat")
        self.assertIn("Active response profile: chat", model.inputs[0][0].content)
        self.assertNotIn("stale instructions", model.inputs[0][0].content)
        self.assertTrue(result["prompt_version"].startswith("sha256:"))

    async def test_both_events_follow_up_and_new_event_in_same_thread(self):
        for payload, profile in [(event(), "alertmanager_rca"), (falco_event(), "falco_security")]:
            with self.subTest(profile=profile):
                model = Model()
                graph = self.graph(model)
                config = {"configurable": {"thread_id": payload["thread_id"]}}
                first = await graph.ainvoke({"event_input": payload}, config)
                self.assertEqual(first["prompt_profile"], profile)
                self.assertEqual(model.inputs[0][0].content.split("\n\nCurrent investigation time:")[0],
                                 first["selected_prompt"])
                second = await graph.ainvoke({"messages": [HumanMessage("Ist das noch aktuell?")]}, config)
                self.assertEqual(second["prompt_profile"], "chat")
                self.assertEqual(second["trigger_event"], first["trigger_event"])
                self.assertNotEqual(first["prompt_version"], second["prompt_version"])
                third = await graph.ainvoke({"event_input": payload}, config)
                self.assertEqual(third["prompt_profile"], profile)
                self.assertEqual(third["prompt_version"], first["prompt_version"])
                history = [s async for s in graph.aget_state_history(config)]
                self.assertTrue(any(s.next == ("select_prompt",) for s in history))

    async def test_resolved_selects_event_profile_without_model(self):
        model = Model()
        result = await self.graph(model).ainvoke({"event_input": event(status="resolved")},
            {"configurable": {"thread_id": "resolved"}})
        self.assertEqual(result["prompt_profile"], "alertmanager_rca")
        self.assertEqual(model.inputs, [])

    async def test_budget_and_provider_fallback_keep_selected_profile(self):
        for payload, profile in [({"messages": [HumanMessage("Check this pod")]}, "chat"),
                                 ({"event_input": event()}, "alertmanager_rca"),
                                 ({"event_input": falco_event()}, "falco_security")]:
            for provider_failure in [False, True]:
                with self.subTest(profile=profile, provider_failure=provider_failure):
                    model = Model(tool_first=True, fail_second=provider_failure)
                    graph = self.graph(model, budget=6 if provider_failure else 1)
                    result = await graph.ainvoke(payload, {"configurable": {"thread_id": "fallback"}})
                    self.assertIn(result["selected_prompt"], model.inputs[-1][0].content)
                    self.assertIn("Answer the current request", model.inputs[-1][0].content)
                    self.assertNotIn("best evidence-based RCA", model.inputs[-1][0].content)
                    self.assertEqual(result["prompt_profile"], profile)

    def test_prompt_version_tracks_content_budget_and_snapshot(self):
        state = {"event_action": None}
        one = build_prompt_selector("base A", 6)(state)
        self.assertEqual(one, build_prompt_selector("base A", 6)(state))
        self.assertNotEqual(one["prompt_version"], build_prompt_selector("base B", 6)(state)["prompt_version"])
        self.assertNotEqual(one["prompt_version"], build_prompt_selector("base A", 2)(state)["prompt_version"])
        with patch("src.prompts.Path.read_text", return_value="changed profile"):
            changed = build_prompt_selector("base A", 6)(state)
        self.assertNotEqual(one["prompt_version"], changed["prompt_version"])

    async def test_resume_after_prompt_change_retains_checkpoint_snapshot(self):
        model = Model()
        first_graph = self.graph(model)
        first_graph.interrupt_before_nodes = ["agent"]
        config = {"configurable": {"thread_id": "resume"}}
        selected = await first_graph.ainvoke({"event_input": falco_event()}, config)
        self.assertEqual(model.inputs, [])
        # A new graph represents a process reload with edited prompt files.
        with patch("src.prompts.Path.read_text", return_value="New deployment instructions"):
            resumed_graph = build_basic_graph(model, [inspect_status], "New base")
        resumed_graph.checkpointer = first_graph.checkpointer
        resumed = await resumed_graph.ainvoke(None, config)
        self.assertEqual(resumed["prompt_version"], selected["prompt_version"])
        self.assertEqual(model.inputs[0][0].content.split("\n\nCurrent investigation time:")[0],
                         selected["selected_prompt"])
        followup = await resumed_graph.ainvoke({"messages": [HumanMessage("Explain")]}, config)
        self.assertIn("New deployment instructions", followup["selected_prompt"])
        self.assertNotEqual(followup["prompt_version"], selected["prompt_version"])

    def test_deterministic_fallback_does_not_force_chat_into_rca(self):
        for profile, absent in [("chat", "Likely root cause"), ("falco_security", "Likely root cause")]:
            message = deterministic_final_answer({"messages": [], "prompt_profile": profile},
                                                 "Model unavailable", RuntimeError("test"))
            self.assertNotIn(absent, message.content)
