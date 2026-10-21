"""Model deadlines, response completeness, and configured output budgets."""

import asyncio
import os
import unittest
from unittest.mock import patch

from langchain_core.messages import AIMessage

from src.graph import IncompleteModelResponse, invoke_final_answer, invoke_model


class ModelDeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_deadline_cancels_inflight_model(self):
        cancelled = asyncio.Event()

        class SlowModel:
            async def ainvoke(self, messages):
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.set()

        with patch.dict(os.environ, {"AIOPS_MODEL_TIMEOUT_SECONDS": "0.01"}):
            with self.assertRaises(TimeoutError):
                await invoke_model(SlowModel(), [])
        self.assertTrue(cancelled.is_set())

    async def test_completed_response_is_preserved(self):
        answer = AIMessage(content="OK")

        class FastModel:
            async def ainvoke(self, messages):
                return answer

        self.assertIs(await invoke_model(FastModel(), []), answer)

    async def test_empty_and_truncated_responses_are_rejected(self):
        for answer in [AIMessage(content="  "),
                       AIMessage(content="Partial RCA", response_metadata={"finish_reason": "length"})]:
            with self.subTest(answer=answer.content):
                class Model:
                    async def ainvoke(self, messages):
                        return answer
                with self.assertRaises(IncompleteModelResponse):
                    await invoke_model(Model(), [])
                with self.assertRaises(IncompleteModelResponse):
                    await invoke_final_answer(Model(), {"messages": []}, "Analyze", 6, "Test")

    async def test_tool_only_response_is_valid(self):
        answer = AIMessage(content="", tool_calls=[
            {"name": "inspect_status", "args": {}, "id": "call-1"}])
        class Model:
            async def ainvoke(self, messages):
                return answer
        self.assertIs(await invoke_model(Model(), []), answer)

    def test_model_budget_configuration(self):
        from src.agent import build_model
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-only",
                                     "AIOPS_MODEL_MAX_TOKENS": "3072"}):
            # Equal budgets are supported; larger thinking budgets are capped.
            for requested, expected in ((1024, 1024), (3072, 3072), (4096, 3072)):
                with self.subTest(thinking_budget=requested):
                    with patch.dict(os.environ, {"AIOPS_MODEL_THINKING_TOKEN_BUDGET": str(requested)}):
                        model = build_model()
                        self.assertEqual(model.extra_body, {"thinking_token_budget": expected})
                        self.assertEqual(model.max_tokens, 3072)
            for invalid in (0, -1):
                with self.subTest(thinking_budget=invalid):
                    with patch.dict(os.environ, {"AIOPS_MODEL_THINKING_TOKEN_BUDGET": str(invalid)}):
                        with self.assertRaisesRegex(ValueError, "must be positive"):
                            build_model()
