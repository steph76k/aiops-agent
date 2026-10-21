#!/usr/bin/env python3

import os
from typing import Any

from langchain_core.globals import set_debug
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from src.graph import build_basic_graph
from src.prompts import load_base_prompt


set_debug(False)


MCP_SERVERS = {
    "kubernetes": "KUBERNETES_MCP_URL",
    "prometheus": "PROMETHEUS_MCP_URL",
    "alertmanager": "ALERTMANAGER_MCP_URL",
    "falco": "FALCO_MCP_URL",
    "grafana": "GRAFANA_MCP_URL",
}

MUTATING_TOOLS = {
    "createSilence",
    "deleteSilence",
    "pods_delete",
    "pods_exec",
    "pods_run",
    "resources_create_or_update",
    "resources_delete",
    "resources_scale",
}

# Older MCP servers may not publish readOnlyHint. Explicit known readers retain
# compatibility; unknown tools must advertise themselves as read-only.
READ_ONLY_TOOLS = {
    "pods_get", "pods_list", "pods_list_in_namespace", "pods_log", "pods_top",
    "nodes_top", "nodes_log", "nodes_stats_summary", "events_list", "namespaces_list",
    "resources_get", "resources_list", "prod_execute_query", "prod_execute_range_query",
    "getAlerts", "getCriticalAlerts", "getAlertGroups", "getAlertHistory", "getAlertingSummary",
    "getAlertmanagerStatus", "getReceivers", "getSilences", "investigateAlert", "correlateAlerts",
    "query_falco_events", "falco_full_event_by_id", "query_loki_logs", "query_prometheus",
    "list_datasources", "get_datasource_by_uid", "get_datasource_by_name",
}

_agent_graph = None


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")

    return value


def build_mcp_client() -> MultiServerMCPClient:
    return MultiServerMCPClient(
        {
            server_name: {
                "transport": "streamable_http",
                "url": required_env(env_name),
            }
            for server_name, env_name in MCP_SERVERS.items()
        }
    )


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default

    return value.lower() in {"1", "true", "yes", "on"}


def filter_tools(tools: list[Any]) -> list[Any]:
    # Operator actions use a separate, scoped executor; never expose that
    # connection or grant global write privileges to ordinary model turns.
    if env_bool("AIOPS_ENABLE_MUTATING_TOOLS") and not os.getenv("AIOPS_ACTIONS_USERS"):
        return tools

    if os.getenv("AIOPS_ACTIONS_USERS"):
        return [tool for tool in tools if tool.name not in MUTATING_TOOLS
                and (tool.name in READ_ONLY_TOOLS or (getattr(tool, "metadata", None) or {}).get("readOnlyHint") is True)]

    return [tool for tool in tools if tool.name not in MUTATING_TOOLS]


def load_system_prompt() -> str:
    return load_base_prompt()


def build_model() -> ChatOpenAI:
    max_tokens = int(os.getenv("AIOPS_MODEL_MAX_TOKENS", "65536"))
    thinking_budget = os.getenv("AIOPS_MODEL_THINKING_TOKEN_BUDGET")
    extra_body = None
    if thinking_budget is not None:
        budget = int(thinking_budget)
        if budget <= 0:
            raise ValueError("Thinking token budget must be positive")
        # Allow the thinking budget up to the model max_tokens. If it exceeds
        # the configured max_tokens, cap it to avoid errors with some backends.
        if budget > max_tokens:
            budget = max_tokens
        extra_body = {"thinking_token_budget": budget}
    return ChatOpenAI(
        model=os.getenv("AIOPS_MODEL", "mistralai/mistral-medium-3-5"),
        api_key=required_env("OPENROUTER_API_KEY"),
        base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        temperature=0,
        max_tokens=max_tokens,
        extra_body=extra_body,
        timeout=float(os.getenv("AIOPS_MODEL_TIMEOUT_SECONDS", "180")),
        max_retries=0,
    )


async def build_agent():
    global _agent_graph

    if _agent_graph is not None:
        return _agent_graph

    client = build_mcp_client()
    mcp_tools = await client.get_tools()
    tools = filter_tools(list(mcp_tools))
    system_prompt = load_system_prompt()
    llm = build_model()

    print(f"Loaded {len(tools)} tools")
    print("\nAvailable tools:")
    for tool in tools:
        print(f"  - {tool.name}")

    if os.getenv("AIOPS_PRINT_TOOL_SCHEMAS", "").lower() in {"1", "true", "yes"}:
        for tool in tools:
            print("=" * 80)
            print(tool.name)
            print(tool.description)

            if hasattr(tool, "args_schema"):
                print(tool.args_schema)

    _agent_graph = build_basic_graph(
        llm=llm,
        tools=tools,
        system_prompt=system_prompt,
        max_tool_calls=int(os.getenv("AIOPS_MAX_TOOL_CALLS", "6")),
    )

    return _agent_graph
