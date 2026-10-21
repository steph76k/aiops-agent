"""Event/chat routing, profiled investigation loop, and incident delivery."""

from datetime import datetime, timezone
import asyncio
import os
import re

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition
from typing_extensions import NotRequired, TypedDict
from src.events import prepare_event
from src.incidents import record_incident, sync_servicenow
from src.lifecycle import prepare_lifecycle
from src.prompts import build_prompt_selector


class Scope(TypedDict):
    type: str
    cluster: NotRequired[str]
    namespace: NotRequired[str]
    pod: NotRequired[str]
    node: NotRequired[str]
    workload: NotRequired[str]
    alert: NotRequired[str]


class EvidenceItem(TypedDict):
    collected_at: str
    source: str
    category: str
    content: str
    tool_call_id: NotRequired[str]
    query: NotRequired[str]
    start: NotRequired[str]
    end: NotRequired[str]
    time: NotRequired[str]
    datasource_uid: NotRequired[str]


class InvestigationState(TypedDict):
    current_evidence: NotRequired[list[EvidenceItem]]
    historical_evidence: NotRequired[list[EvidenceItem]]
    last_checked_at: NotRequired[str]
    scope: NotRequired[Scope]
    alerts: NotRequired[list[EvidenceItem]]
    events: NotRequired[list[EvidenceItem]]
    metrics: NotRequired[list[EvidenceItem]]
    logs: NotRequired[list[EvidenceItem]]
    security_findings: NotRequired[list[EvidenceItem]]
    rca: NotRequired[str]
    confidence: NotRequired[str]
    turn_started_at_message_count: NotRequired[int]


class AgentState(MessagesState):
    """Graph state.

    MessagesState already contains:

        messages: list[BaseMessage]

    LangGraph appends new AIMessage and ToolMessage objects to this list.
    """

    investigation: NotRequired[InvestigationState]
    event_input: NotRequired[dict | None]
    analysis_input: NotRequired[dict | None]
    trigger_event: NotRequired[dict]
    incident_id: NotRequired[str]
    event_action: NotRequired[str | None]
    event_id: NotRequired[str]
    event_thread_id: NotRequired[str]
    ticket: NotRequired[dict]
    prompt_profile: NotRequired[str]
    prompt_version: NotRequired[str]
    selected_prompt: NotRequired[str]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def runtime_context() -> str:
    now = utc_now()
    return (
        f"Current investigation time: {now}. "
        "Cluster, alert, metric, and security data are live and may change between "
        "turns. Treat previous tool results as historical evidence, not current "
        "state, unless they were collected during this turn."
    )


def latest_human_content(state: AgentState) -> str:
    for message in reversed(state["messages"]):
        if isinstance(message, HumanMessage):
            return str(message.content)

    return ""


def infer_scope(text: str) -> Scope:
    scope: Scope = {"type": "unknown"}

    namespace_match = re.search(
        r"(?:namespace|ns|-n)\s+([a-z0-9][a-z0-9.-]*)",
        text,
        re.IGNORECASE,
    )
    pod_match = re.search(
        r"\bpod\s+([a-z0-9][a-z0-9.-]*)",
        text,
        re.IGNORECASE,
    )
    node_match = re.search(
        r"\bnode\s+([a-z0-9][a-z0-9.-]*)",
        text,
        re.IGNORECASE,
    )
    alert_match = re.search(
        r"\balert\s+([a-z0-9][a-z0-9_.:-]*)",
        text,
        re.IGNORECASE,
    )

    if namespace_match:
        scope["namespace"] = namespace_match.group(1)
        scope["type"] = "namespace"

    if pod_match:
        scope["pod"] = pod_match.group(1)
        scope["type"] = "pod"

    if node_match:
        scope["node"] = node_match.group(1)
        scope["type"] = "node"

    if alert_match:
        scope["alert"] = alert_match.group(1)
        scope["type"] = "alert"

    return scope


def prepare_investigation(state: AgentState):
    investigation = state.get("investigation", {})
    previous_current = investigation.get("current_evidence", [])
    historical = [
        *investigation.get("historical_evidence", []),
        *previous_current,
    ][-100:]

    scope = infer_scope(latest_human_content(state))
    event = state.get("trigger_event", {})
    if state.get("event_action") in {"investigate", "analysis"}:
        scope = {"type": "alert", "alert": event.get("event_type", "alert")}
        for key in ("cluster", "namespace", "pod", "node"):
            if event.get(key):
                scope[key] = event[key]
    elif scope["type"] == "unknown":
        scope = investigation.get("scope", scope)

    return {
        "investigation": {
            "current_evidence": [],
            "historical_evidence": historical,
            "last_checked_at": utc_now(),
            "scope": scope,
            "alerts": [],
            "events": [],
            "metrics": [],
            "logs": [],
            "security_findings": [],
            "rca": None,
            "confidence": None,
            "turn_started_at_message_count": len(state["messages"]),
        }
    }


def evidence_category(tool_name: str) -> str:
    if tool_name in {
        "correlateAlerts",
        "getAlertGroups",
        "getAlertHistory",
        "getAlertingSummary",
        "getAlertmanagerStatus",
        "getAlerts",
        "getCriticalAlerts",
        "getReceivers",
        "getSilences",
        "investigateAlert",
    }:
        return "alert"

    if tool_name == "events_list":
        return "event"

    if tool_name.startswith("prod_"):
        return "metric"

    if tool_name in {"nodes_log", "pods_log", "query_loki_logs"}:
        return "log"

    if tool_name in {"query_falco_events", "falco_full_event_by_id"}:
        return "security"

    return "evidence"


def tool_message_to_evidence(message: ToolMessage) -> EvidenceItem:
    tool_name = getattr(message, "name", None) or "tool"
    item: EvidenceItem = {
        "collected_at": utc_now(),
        "source": tool_name,
        "category": evidence_category(tool_name),
        "content": truncate_text(message.content, 3000),
    }

    tool_call_id = getattr(message, "tool_call_id", None)
    if tool_call_id:
        item["tool_call_id"] = tool_call_id

    return item


def record_tool_evidence(state: AgentState):
    investigation = state.get("investigation", {})
    start_index = investigation.get("turn_started_at_message_count", 0)
    existing_ids = {
        item.get("tool_call_id")
        for item in investigation.get("current_evidence", [])
        if item.get("tool_call_id")
    }
    existing_signatures = {
        (item["source"], item["content"])
        for item in investigation.get("current_evidence", [])
    }
    new_items = []
    calls = {call["id"]: call for message in state["messages"][start_index:]
             if isinstance(message, AIMessage) for call in message.tool_calls}

    for message in state["messages"][start_index:]:
        if not isinstance(message, ToolMessage):
            continue

        item = tool_message_to_evidence(message)
        args = calls.get(item.get("tool_call_id"), {}).get("args", {})
        # Persist only query/location parameters, never arbitrary tool arguments.
        for target, candidates in {"query": ("query", "expr", "logql"), "time": ("time",),
                                   "start": ("start", "startRfc3339"), "end": ("end", "endRfc3339"),
                                   "datasource_uid": ("datasourceUid", "datasource_uid")}.items():
            value = next((args[k] for k in candidates if isinstance(args.get(k), str)), None)
            if value is not None:
                item[target] = value
        tool_call_id = item.get("tool_call_id")
        if tool_call_id and tool_call_id in existing_ids:
            continue

        signature = (item["source"], item["content"])
        if signature in existing_signatures:
            continue

        new_items.append(item)
        existing_signatures.add(signature)

    current = [*investigation.get("current_evidence", []), *new_items]

    return {
        "investigation": {
            **investigation,
            "current_evidence": current,
            "alerts": [item for item in current if item["category"] == "alert"],
            "events": [item for item in current if item["category"] == "event"],
            "metrics": [item for item in current if item["category"] == "metric"],
            "logs": [item for item in current if item["category"] == "log"],
            "security_findings": [
                item for item in current if item["category"] == "security"
            ],
            "last_checked_at": utc_now(),
        }
    }


def infer_confidence(text: str) -> str | None:
    match = re.search(r"\b(low|medium|high)\b", text, re.IGNORECASE)
    if not match:
        return None

    return match.group(1).lower()


def capture_answer(state: AgentState):
    last_message = state["messages"][-1] if state["messages"] else None
    if not isinstance(last_message, AIMessage) or getattr(last_message, "tool_calls", []):
        return {}

    content = str(last_message.content)
    investigation = {**state.get("investigation", {})}
    investigation["rca"] = content
    investigation["confidence"] = infer_confidence(content)

    return {
        "investigation": investigation
    }


class IncompleteModelResponse(RuntimeError):
    """The model did not produce a complete answer or tool call."""


async def invoke_model(llm, messages):
    # Bound the entire call, including streaming; HTTP read timeouts alone
    # do not stop a model that keeps sending tokens indefinitely.
    response = await asyncio.wait_for(
        llm.ainvoke(messages),
        timeout=float(os.getenv("AIOPS_MODEL_TIMEOUT_SECONDS", "180")),
    )
    if response.response_metadata.get("finish_reason") == "length":
        raise IncompleteModelResponse("Model output was truncated at the token limit")
    has_text = bool(response.text.strip())
    if not has_text and not response.tool_calls:
        raise IncompleteModelResponse("Model returned no visible answer or tool call")
    return response


def build_agent_node(
    llm,
    system_prompt: str,
    final_llm,
    max_tool_calls: int,
):
    async def agent_node(state: AgentState):
        messages = [
            SystemMessage(
                content="\n\n".join([
                    state.get("selected_prompt", system_prompt),
                    runtime_context(),
                    state_summary(state),
                ])
            ),
            *state["messages"],
        ]

        try:
            response = await invoke_model(llm, messages)
        except Exception as exc:
            print(f"Agent model call failed: {type(exc).__name__}: {exc}")
            if count_tool_calls(state) == 0:
                raise

            response = await invoke_final_answer(
                final_llm,
                state,
                system_prompt,
                max_tool_calls,
                reason=(
                    "The model provider rejected the tool-call conversation, "
                    "so the answer is based on a sanitized evidence transcript."
                ),
            )

        return {
            "messages": [response],
        }

    return agent_node


def build_final_answer_node(
    llm,
    system_prompt: str,
    max_tool_calls: int,
):
    async def final_answer_node(state: AgentState):
        budget = tool_budget(state, max_tool_calls)
        response = await invoke_final_answer(
            llm,
            state,
            system_prompt,
            budget,
            reason=f"The tool budget of {budget} tool calls was reached.",
        )

        return {
            "messages": [response],
        }

    return final_answer_node


def count_tool_calls(state: AgentState) -> int:
    """Count completed tool calls in the current investigation turn."""
    investigation = state.get("investigation")
    if investigation is not None:
        return len(investigation.get("current_evidence", []))

    return sum(isinstance(message, ToolMessage) for message in state["messages"])


def truncate_text(value, max_chars: int = 3000) -> str:
    text = str(value)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "...[truncated]"


def evidence_transcript(state: AgentState, max_chars: int = 12000) -> str:
    parts = [state_summary(state)]

    for message in state["messages"]:
        if isinstance(message, HumanMessage):
            parts.append(f"User request:\n{truncate_text(message.content, 2000)}")
            continue

        if isinstance(message, AIMessage):
            tool_calls = getattr(message, "tool_calls", []) or []
            if tool_calls:
                calls = []
                for tool_call in tool_calls:
                    calls.append(
                        f"- {tool_call.get('name')}: "
                        f"{truncate_text(tool_call.get('args'), 1000)}"
                    )
                parts.append("Tool calls requested:\n" + "\n".join(calls))
            elif message.content:
                parts.append(f"Assistant draft:\n{truncate_text(message.content, 2000)}")
            continue

        if isinstance(message, ToolMessage):
            name = getattr(message, "name", None) or "tool"
            parts.append(
                f"Tool result from {name}:\n{truncate_text(message.content, 3000)}"
            )

    transcript = "\n\n".join(parts)
    return truncate_text(transcript, max_chars)


def state_summary(state: AgentState) -> str:
    investigation = state.get("investigation", {})
    scope = investigation.get("scope", {"type": "unknown"})
    current_count = len(investigation.get("current_evidence", []))
    historical_count = len(investigation.get("historical_evidence", []))
    last_checked_at = investigation.get("last_checked_at", "not checked in this turn")

    return (
        "Structured investigation state:\n"
        f"- scope: {scope}\n"
        f"- last_checked_at: {last_checked_at}\n"
        f"- current_evidence_items: {current_count}\n"
        f"- historical_evidence_items: {historical_count}\n"
        f"- alerts: {len(investigation.get('alerts', []))}\n"
        f"- events: {len(investigation.get('events', []))}\n"
        f"- metrics: {len(investigation.get('metrics', []))}\n"
        f"- logs: {len(investigation.get('logs', []))}\n"
        f"- security_findings: {len(investigation.get('security_findings', []))}\n"
        f"- confidence: {investigation.get('confidence') or 'unknown'}"
    )


def deterministic_final_answer(state: AgentState, reason: str, error: Exception) -> AIMessage:
    transcript = evidence_transcript(state, max_chars=9000)
    if state.get("prompt_profile") == "chat":
        return AIMessage(content=(
            f"I could not complete the answer because the model request failed "
            f"({type(error).__name__}). {reason}\n\n"
            f"Available context and evidence:\n{transcript}\n\n"
            "Please retry the question. No reliable conclusion is available yet."
        ))
    cause_heading = ("Security assessment" if state.get("prompt_profile") == "falco_security"
                     else "Likely root cause")
    content = (
        "Summary\n"
        f"- {reason}\n"
        f"- Final model call failed: {type(error).__name__}: {error}\n\n"
        "Evidence collected\n"
        f"{transcript or 'No tool evidence was collected.'}\n\n"
        f"{cause_heading}\n"
        "- Not enough reliable model output was available for a confident assessment.\n\n"
        "Recommended next steps\n"
        "- Review the evidence above and retry with a provider/model that accepts "
        "tool-call conversations, or keep this sanitized final-answer fallback enabled.\n\n"
        "Confidence level\n"
        "- low"
    )
    return AIMessage(content=content)


async def invoke_final_answer(
    llm,
    state: AgentState,
    system_prompt: str,
    max_tool_calls: int,
    reason: str,
) -> AIMessage:
    messages = [
        SystemMessage(
            content=(
                f"{state.get('selected_prompt', system_prompt)}\n\n"
                f"{runtime_context()}\n\n"
                "Do not call tools. Answer the current request using the active "
                "response profile and only "
                "the sanitized transcript in the user message. If evidence is "
                "incomplete, say what is known, what is uncertain, and what you "
                "would check next."
            )
        ),
        HumanMessage(
            content=(
                f"{reason}\n"
                f"Completed tool calls: {count_tool_calls(state)}/{max_tool_calls}\n\n"
                "Sanitized transcript:\n"
                f"{evidence_transcript(state)}"
            )
        ),
    ]

    try:
        return await invoke_model(llm, messages)
    except IncompleteModelResponse:
        # Keep failed RCAs visible as failed runs; do not deliver an empty or
        # truncated report to the incident/ticket pipeline.
        raise
    except Exception as exc:
        print(f"Final model call failed: {type(exc).__name__}: {exc}")
        return deterministic_final_answer(state, reason, exc)


def route_after_agent(state: AgentState):
    """Route to the tools node only when the last AI message has tool calls."""
    return tools_condition(state)


def build_route_after_tools(max_tool_calls: int):
    def route_after_tools(state: AgentState):
        budget = tool_budget(state, max_tool_calls)
        if count_tool_calls(state) >= budget:
            print(
                f"Tool budget reached "
                f"({count_tool_calls(state)}/{budget}). Finalizing."
            )
            return "final"

        return "agent"

    return route_after_tools


def tool_budget(state, default):
    if state.get("event_action") == "analysis":
        return max(default, min(20, int(os.getenv("AIOPS_DETAILED_MAX_TOOL_CALLS", "12"))))
    return default


def iter_ai_tool_calls(messages):
    for message in messages:
        if isinstance(message, AIMessage):
            for tool_call in getattr(message, "tool_calls", []) or []:
                yield tool_call


def build_basic_graph(
    llm,
    tools,
    system_prompt: str,
    max_tool_calls: int = 6,
):
    """Build the graph after tools and model are loaded at runtime."""
    model = llm.bind_tools(tools)

    graph = StateGraph(AgentState)
    graph.add_node("normalize_event", prepare_event)
    graph.add_node("prepare_lifecycle", prepare_lifecycle)
    graph.add_node("select_prompt", build_prompt_selector(system_prompt, max_tool_calls))
    graph.add_node("prepare", prepare_investigation)
    graph.add_node("agent", build_agent_node(model, system_prompt, llm, max_tool_calls))
    graph.add_node("final", build_final_answer_node(llm, system_prompt, max_tool_calls))
    graph.add_node("tools", ToolNode(tools))
    graph.add_node("record_evidence", record_tool_evidence)
    graph.add_node("capture_answer", capture_answer)
    graph.add_node("record_incident", record_incident)
    graph.add_node("sync_servicenow", sync_servicenow)

    graph.add_edge(START, "normalize_event")
    graph.add_edge("normalize_event", "prepare_lifecycle")
    graph.add_edge("prepare_lifecycle", "select_prompt")
    graph.add_conditional_edges(
        "select_prompt",
        lambda state: "resolved" if state.get("event_action") in {"resolved", "recurrence"} else "investigate",
        {"resolved": "record_incident", "investigate": "prepare"},
    )
    graph.add_edge("prepare", "agent")
    graph.add_conditional_edges(
        "agent",
        route_after_agent,
        {
            "tools": "tools",
            END: "capture_answer",
        },
    )
    graph.add_edge("tools", "record_evidence")
    graph.add_conditional_edges(
        "record_evidence",
        build_route_after_tools(max_tool_calls),
        {
            "agent": "agent",
            "final": "final",
        },
    )
    graph.add_edge("final", "capture_answer")
    graph.add_conditional_edges(
        "capture_answer",
        lambda state: "ticket" if state.get("event_action") == "investigate" else "end",
        {"ticket": "record_incident", "end": END},
    )
    graph.add_edge("record_incident", "sync_servicenow")
    graph.add_edge("sync_servicenow", END)

    return graph.compile()
