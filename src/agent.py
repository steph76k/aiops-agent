#!/usr/bin/env python3

import os
from pathlib import Path
from typing import Any

from langchain_core.globals import set_debug
from langchain_core.messages import AIMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI

from src.graph import build_rca_graph, create_initial_state


def env_bool(
    name: str,
    default: bool = False,
) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


set_debug(env_bool("AIOPS_DEBUG"))


client = MultiServerMCPClient(
    {
        "kubernetes": {
            "transport": "streamable_http",
            "url": os.getenv(
                "KUBERNETES_MCP_URL",
                "http://kubernetes-mcp-server.rke2-cluster1.berger.ph/mcp",
            ),
        },
        "prometheus": {
            "transport": "streamable_http",
            "url": os.getenv(
                "PROMETHEUS_MCP_URL",
                "http://prometheus-mcp-server.rke2-cluster1.berger.ph/mcp",
            ),
        },
        "alertmanager": {
            "transport": "streamable_http",
            "url": os.getenv(
                "ALERTMANAGER_MCP_URL",
                "http://alertmanager-mcp-server.rke2-cluster1.berger.ph/mcp",
            ),
        },
    }
)


def load_system_prompt() -> str:
    prompt_path = Path(__file__).parent / "prompts" / "system.txt"
    return prompt_path.read_text()


def build_model() -> ChatOpenAI:
    return ChatOpenAI(
        model=os.getenv("AIOPS_MODEL", "openai/gpt-4.1-mini"),
        api_key=os.environ["OPENROUTER_API_KEY"],
        base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        temperature=0,
    )


def extract_user_question(payload: dict[str, Any]) -> str:
    messages = payload.get("messages", [])
    if not messages:
        return ""

    last_message = messages[-1]
    if isinstance(last_message, dict):
        return str(last_message.get("content", ""))

    return str(getattr(last_message, "content", ""))


class AIOpsGraphAgent:
    def __init__(
        self,
        graph: Any,
        max_tool_calls: int = 8,
    ) -> None:
        self.graph = graph
        self.max_tool_calls = max_tool_calls

    async def ainvoke(
        self,
        payload: dict[str, Any],
    ) -> dict[str, list[AIMessage]]:
        question = extract_user_question(payload)
        state = create_initial_state(
            question,
            max_tool_calls=self.max_tool_calls,
        )
        result = await self.graph.ainvoke(state)
        answer = result.get("final_answer", "No RCA result was generated.")

        return {
            "messages": [
                AIMessage(content=answer)
            ]
        }


async def build_agent() -> AIOpsGraphAgent:
    mcp_tools = await client.get_tools()
    tools = list(mcp_tools)
    system_prompt = load_system_prompt()
    llm = build_model()

    if env_bool("AIOPS_ENABLE_PYTHON_REPL"):
        from langchain_experimental.tools import PythonREPLTool

        tools.append(PythonREPLTool())

    print(f"Loaded {len(tools)} tools")
    print("\nAvailable tools:")
    for tool in tools:
        print(f"  - {tool.name}")

    if not env_bool("AIOPS_ENABLE_PYTHON_REPL"):
        print("\nPythonREPLTool disabled. Set AIOPS_ENABLE_PYTHON_REPL=true to enable.")

    graph = build_rca_graph(
        tools,
        model=llm,
        system_prompt=system_prompt,
    )

    return AIOpsGraphAgent(
        graph,
        max_tool_calls=int(os.getenv("AIOPS_MAX_TOOL_CALLS", "8")),
    )
