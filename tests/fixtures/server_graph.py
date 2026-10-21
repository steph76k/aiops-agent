"""Actual application graph with a deterministic model; never calls a provider."""

from langchain_core.messages import AIMessage
from src.graph import build_basic_graph


class Model:
    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages):
        return AIMessage(content="RCA from test model. Confidence level: low")


def build_graph():
    return build_basic_graph(Model(), [], "Read-only troubleshooting.")
