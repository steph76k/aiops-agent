from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Literal

try:
    from typing import NotRequired, TypedDict
except ImportError:
    from typing_extensions import NotRequired, TypedDict

from langgraph.graph import END, StateGraph


ToolMap = dict[str, Any]


class RCAState(TypedDict):
    question: str

    scope_type: NotRequired[Literal[
        "cluster",
        "namespace",
        "workload",
        "pod",
        "node",
        "alert",
        "unknown",
    ]]
    namespace: NotRequired[str]
    workload: NotRequired[str]
    pod: NotRequired[str]
    node: NotRequired[str]
    alert_name: NotRequired[str]

    alerts_summary: NotRequired[Any]
    critical_alerts: NotRequired[Any]
    pod_summary: NotRequired[Any]
    warning_events: NotRequired[Any]
    prometheus_health: NotRequired[Any]
    log_findings: NotRequired[Any]

    findings: NotRequired[list[dict[str, str]]]
    likely_root_cause: NotRequired[str]
    impact: NotRequired[str]
    recommendations: NotRequired[list[str]]
    confidence: NotRequired[str]

    tool_calls_used: int
    max_tool_calls: int
    tool_trace: NotRequired[list[dict[str, Any]]]
    final_answer: NotRequired[str]


def create_initial_state(
    question: str,
    max_tool_calls: int = 8,
) -> RCAState:
    return {
        "question": question,
        "scope_type": "unknown",
        "findings": [],
        "tool_calls_used": 0,
        "max_tool_calls": max_tool_calls,
        "tool_trace": [],
    }


def can_call_tool(state: RCAState) -> bool:
    return state.get("tool_calls_used", 0) < state.get("max_tool_calls", 8)


def record_tool_call(
    state: RCAState,
    tool_name: str,
) -> None:
    state["tool_calls_used"] = state.get("tool_calls_used", 0) + 1
    state.setdefault("tool_trace", []).append(
        {
            "tool": tool_name,
            "number": state["tool_calls_used"],
        }
    )


def append_finding(
    state: RCAState,
    message: str,
    severity: str = "info",
) -> None:
    state.setdefault("findings", []).append(
        {
            "severity": severity,
            "message": message,
        }
    )


async def call_tool_with_budget(
    state: RCAState,
    tool_name: str,
    tool_func: Callable[..., Awaitable[Any]],
    *args: Any,
    **kwargs: Any,
) -> Any | None:
    if not can_call_tool(state):
        append_finding(
            state,
            f"Skipped {tool_name}: tool budget exhausted",
            "warning",
        )
        return None

    record_tool_call(state, tool_name)
    try:
        return await tool_func(*args, **kwargs)
    except Exception as exc:
        append_finding(
            state,
            f"{tool_name} failed: {type(exc).__name__}: {exc}",
            "warning",
        )
        return None


def tool_by_name(
    tools: ToolMap,
    name: str,
) -> Any | None:
    return tools.get(name)


async def invoke_tool(
    state: RCAState,
    tools: ToolMap,
    name: str,
    args: dict[str, Any] | None = None,
) -> Any | None:
    tool = tool_by_name(tools, name)
    if tool is None:
        append_finding(state, f"Tool {name} is not available", "warning")
        return None

    return await call_tool_with_budget(
        state,
        name,
        tool.ainvoke,
        args or {},
    )


def compact_result(
    value: Any,
    max_items: int = 20,
    max_chars: int = 6000,
) -> Any:
    if isinstance(value, list):
        return [compact_result(item, max_items, max_chars) for item in value[:max_items]]

    if isinstance(value, dict):
        return {
            key: compact_result(item, max_items, max_chars)
            for key, item in list(value.items())[:max_items]
        }

    text = str(value)
    if len(text) > max_chars:
        return text[:max_chars] + "...[truncated]"
    return value


def format_evidence(value: Any) -> str:
    if value is None:
        return "not collected"
    try:
        return json.dumps(value, indent=2, default=str)[:4000]
    except TypeError:
        return str(value)[:4000]


def extract_scope_from_question(state: RCAState) -> None:
    question = state["question"]

    namespace_match = re.search(
        r"(?:namespace|ns|-n)\s+([a-z0-9][a-z0-9.-]*)",
        question,
        re.IGNORECASE,
    )
    pod_match = re.search(
        r"\bpod\s+([a-z0-9][a-z0-9.-]*)",
        question,
        re.IGNORECASE,
    )
    node_match = re.search(
        r"\bnode\s+([a-z0-9][a-z0-9.-]*)",
        question,
        re.IGNORECASE,
    )

    if namespace_match:
        state["namespace"] = namespace_match.group(1)
        state["scope_type"] = "namespace"

    if pod_match:
        state["pod"] = pod_match.group(1)
        state["scope_type"] = "pod"

    if node_match:
        state["node"] = node_match.group(1)
        state["scope_type"] = "node"


def classify_scope(state: RCAState) -> RCAState:
    extract_scope_from_question(state)
    state["scope_type"] = state.get("scope_type", "unknown")
    return state


def build_collect_alerts_node(tools: ToolMap):
    async def collect_alerts(state: RCAState) -> RCAState:
        summary = await invoke_tool(state, tools, "getAlertingSummary")
        if summary is not None:
            state["alerts_summary"] = compact_result(summary, max_items=20)

        critical = await invoke_tool(state, tools, "getCriticalAlerts")
        if critical is not None:
            state["critical_alerts"] = compact_result(critical, max_items=20)

        return state

    return collect_alerts


def build_collect_k8s_overview_node(tools: ToolMap):
    async def collect_k8s_overview(state: RCAState) -> RCAState:
        namespace = state.get("namespace")
        if namespace:
            pods = await invoke_tool(
                state,
                tools,
                "pods_list_in_namespace",
                {"namespace": namespace},
            )
        else:
            pods = await invoke_tool(state, tools, "pods_list")

        if pods is not None:
            state["pod_summary"] = compact_result(pods, max_items=50)

        node_summary = await invoke_tool(state, tools, "nodes_stats_summary")
        if node_summary is not None:
            state["node_summary"] = compact_result(node_summary, max_items=20)

        return state

    return collect_k8s_overview


def build_collect_events_node(tools: ToolMap):
    async def collect_events(state: RCAState) -> RCAState:
        args = {}
        if state.get("namespace"):
            args["namespace"] = state["namespace"]

        events = await invoke_tool(state, tools, "events_list", args)
        if events is not None:
            state["warning_events"] = compact_result(events, max_items=50)

        return state

    return collect_events


def build_collect_prometheus_health_node(tools: ToolMap):
    async def collect_prometheus_health(state: RCAState) -> RCAState:
        health = await invoke_tool(state, tools, "prod_health_check")
        if health is not None:
            state["prometheus_health"] = compact_result(health, max_items=20)

        return state

    return collect_prometheus_health


def should_collect_logs(state: RCAState) -> str:
    if state.get("pod") or state.get("workload"):
        return "logs"
    return "analyze"


def build_collect_targeted_logs_node(tools: ToolMap):
    async def collect_targeted_logs(state: RCAState) -> RCAState:
        pod = state.get("pod")
        if not pod:
            return state

        args: dict[str, Any] = {
            "pod": pod,
            "tail_lines": 150,
        }
        if state.get("namespace"):
            args["namespace"] = state["namespace"]

        logs = await invoke_tool(state, tools, "pods_log", args)
        if logs is not None:
            state["log_findings"] = compact_result(logs, max_items=20, max_chars=6000)

        return state

    return collect_targeted_logs


async def analyze(state: RCAState) -> RCAState:
    findings = state.get("findings", [])
    collected = [
        key
        for key in (
            "alerts_summary",
            "critical_alerts",
            "pod_summary",
            "warning_events",
            "prometheus_health",
            "log_findings",
        )
        if state.get(key) is not None
    ]

    if findings:
        state["likely_root_cause"] = (
            "Es gibt Tool- oder Datenprobleme. Die RCA basiert auf den "
            "erfolgreich gesammelten Signalen."
        )
        state["confidence"] = "medium" if collected else "low"
    elif collected:
        state["likely_root_cause"] = (
            "Aus den gesammelten Signalen ableiten; konkrete Bewertung erfolgt "
            "im Evidence-Abschnitt."
        )
        state["confidence"] = "medium"
    else:
        state["likely_root_cause"] = "Es wurde keine belastbare Evidenz gesammelt."
        state["confidence"] = "low"

    state["impact"] = "Noch nicht sicher bestimmbar ohne Interpretation der Evidence."
    state["recommendations"] = [
        "Pruefe zuerst die genannten Alerts, Pods und Events.",
        "Fuehre danach nur gezielte Log- oder Metrik-Abfragen fuer betroffene Objekte aus.",
    ]
    return state


def build_analyze_node(
    model: Any | None,
    system_prompt: str,
):
    if model is None:
        return analyze

    async def analyze_with_model(state: RCAState) -> RCAState:
        evidence = {
            "question": state["question"],
            "scope_type": state.get("scope_type", "unknown"),
            "tool_calls_used": state.get("tool_calls_used", 0),
            "max_tool_calls": state.get("max_tool_calls", 8),
            "tool_trace": state.get("tool_trace", []),
            "alerts_summary": state.get("alerts_summary"),
            "critical_alerts": state.get("critical_alerts"),
            "pod_summary": state.get("pod_summary"),
            "warning_events": state.get("warning_events"),
            "prometheus_health": state.get("prometheus_health"),
            "log_findings": state.get("log_findings"),
            "findings": state.get("findings", []),
        }

        prompt = "\n".join(
            [
                "Create a concise Kubernetes RCA from this compact evidence.",
                "Use exactly these sections:",
                "- Summary",
                "- Evidence",
                "- Likely root cause",
                "- Impact",
                "- Recommended next steps",
                "- Confidence level",
                "",
                "Do not invent facts. If evidence is insufficient, say so.",
                "Do not suggest risky actions as already executed.",
                "",
                "Evidence JSON:",
                json.dumps(evidence, indent=2, default=str)[:12000],
            ]
        )

        try:
            response = await model.ainvoke(
                [
                    {
                        "role": "system",
                        "content": system_prompt,
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ]
            )
            state["final_answer"] = str(getattr(response, "content", response))
            state["confidence"] = state.get("confidence", "medium")
        except Exception as exc:
            append_finding(
                state,
                f"LLM analysis failed: {type(exc).__name__}: {exc}",
                "warning",
            )
            await analyze(state)

        return state

    return analyze_with_model


def render_response(state: RCAState) -> RCAState:
    if state.get("final_answer"):
        return state

    evidence_lines = [
        f"- Scope: {state.get('scope_type', 'unknown')}",
        f"- Tool calls used: {state.get('tool_calls_used', 0)}/{state.get('max_tool_calls', 8)}",
    ]

    if state.get("tool_trace"):
        trace = ", ".join(item["tool"] for item in state["tool_trace"])
        evidence_lines.append(f"- Tools: {trace}")

    for field, label in (
        ("alerts_summary", "Alert summary"),
        ("critical_alerts", "Critical alerts"),
        ("pod_summary", "Pod summary"),
        ("warning_events", "Warning events"),
        ("prometheus_health", "Prometheus health"),
        ("log_findings", "Targeted logs"),
    ):
        if state.get(field) is not None:
            evidence_lines.append(f"- {label}: {format_evidence(state[field])}")

    for finding in state.get("findings", []):
        evidence_lines.append(
            f"- {finding.get('severity', 'info')}: {finding.get('message', '')}"
        )

    state["final_answer"] = "\n".join(
        [
            "Summary",
            "Ich habe die Untersuchung ueber den RCA-Graphen in begrenzten Schritten ausgefuehrt.",
            "",
            "Evidence",
            *evidence_lines,
            "",
            "Likely root cause",
            state.get("likely_root_cause", "Unknown."),
            "",
            "Impact",
            state.get("impact", "Unknown."),
            "",
            "Recommended next steps",
            *[f"- {item}" for item in state.get("recommendations", [])],
            "",
            "Confidence level",
            state.get("confidence", "low"),
        ]
    )
    return state


def tools_to_map(tools: Sequence[Any]) -> ToolMap:
    return {tool.name: tool for tool in tools}


def build_rca_graph(
    tools: Sequence[Any],
    model: Any | None = None,
    system_prompt: str = "",
):
    tool_map = tools_to_map(tools)

    graph = StateGraph(RCAState)
    graph.add_node("classify_scope", classify_scope)
    graph.add_node("collect_alerts", build_collect_alerts_node(tool_map))
    graph.add_node("collect_k8s_overview", build_collect_k8s_overview_node(tool_map))
    graph.add_node("collect_events", build_collect_events_node(tool_map))
    graph.add_node(
        "collect_prometheus_health",
        build_collect_prometheus_health_node(tool_map),
    )
    graph.add_node("collect_targeted_logs", build_collect_targeted_logs_node(tool_map))
    graph.add_node("analyze", build_analyze_node(model, system_prompt))
    graph.add_node("render_response", render_response)

    graph.set_entry_point("classify_scope")
    graph.add_edge("classify_scope", "collect_alerts")
    graph.add_edge("collect_alerts", "collect_k8s_overview")
    graph.add_edge("collect_k8s_overview", "collect_events")
    graph.add_edge("collect_events", "collect_prometheus_health")
    graph.add_conditional_edges(
        "collect_prometheus_health",
        should_collect_logs,
        {
            "logs": "collect_targeted_logs",
            "analyze": "analyze",
        },
    )
    graph.add_edge("collect_targeted_logs", "analyze")
    graph.add_edge("analyze", "render_response")
    graph.add_edge("render_response", END)

    return graph.compile()
