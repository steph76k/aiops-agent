"""Webhook ingress and chat facade for the Studio-connected Agent Server."""

import asyncio
from contextlib import asynccontextmanager, suppress
import os
import time
from typing import Any, Literal
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Request
import httpx
from langgraph_sdk import get_client
from pydantic import BaseModel, Field

from src.dispatcher import Dispatcher
from src.events import AlertmanagerWebhook, FalcoWebhook, event_identity, received_at
from src.inbox import Inbox
from src.incidents import IncidentStore, TicketWorker
from src.recovery import RecoveryWorker
from src.actions import ActionStore, ActionWorker
from src.action_routes import router as action_router

OPENAI_MODEL_ID = "aiops-agent"


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.inbox = await asyncio.to_thread(Inbox, os.getenv("AIOPS_INBOX_PATH", "data/inbox.sqlite3"))
    app.state.incidents = await asyncio.to_thread(IncidentStore, app.state.inbox.path)
    app.state.actions = await asyncio.to_thread(ActionStore, app.state.incidents)
    # No URL: SDK loopback transport inside Agent Server. Standalone Uvicorn
    # must set AIOPS_AGENT_SERVER_URL to a separate running Agent Server.
    async with get_client(url=os.getenv("AIOPS_AGENT_SERVER_URL"), timeout=30) as client:
        app.state.client = client
        worker = asyncio.create_task(Dispatcher(app.state.inbox, client).run())
        tickets = asyncio.create_task(TicketWorker(app.state.incidents).run())
        recovery = asyncio.create_task(RecoveryWorker(app.state.incidents).run())
        actions = asyncio.create_task(ActionWorker(app.state.actions, client).run())
        try:
            yield
        finally:
            worker.cancel()
            tickets.cancel()
            recovery.cancel()
            actions.cancel()
            with suppress(asyncio.CancelledError):
                await worker
            with suppress(asyncio.CancelledError):
                await tickets
            with suppress(asyncio.CancelledError):
                await recovery
            with suppress(asyncio.CancelledError):
                await actions


app = FastAPI(title="AIOps Agent", version="0.3.0", lifespan=lifespan)
app.include_router(action_router)


class OpenAIMessage(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: Any


class OpenAIChatCompletionRequest(BaseModel):
    model: str = OPENAI_MODEL_ID
    messages: list[OpenAIMessage] = Field(min_length=1)
    stream: bool = False
    temperature: float | None = None
    max_tokens: int | None = None
    thread_id: UUID | None = None


class ChatTurn(BaseModel):
    message: str = Field(min_length=1)
    thread_id: UUID | None = None


def envelope(source: str, raw: dict) -> dict:
    cluster = os.getenv("AIOPS_CLUSTER", "default")
    thread_id, event_id = event_identity(source, raw, cluster)
    return {"source": source, "raw": raw, "cluster": cluster,
            "thread_id": thread_id, "event_id": event_id, "received_at": received_at()}


@app.post("/prometheus", status_code=202)
async def prometheus(payload: AlertmanagerWebhook, request: Request):
    events = [envelope("prometheus", alert.model_dump(mode="json"))
              for alert in payload.alerts if alert.labels.get("alertname") != "Watchdog"]
    accepted = await asyncio.to_thread(request.app.state.inbox.accept, events)
    return {"status": "accepted", "source": "prometheus", "events": accepted,
            "ignored": len(payload.alerts) - len(events)}


@app.post("/falco", status_code=202)
async def falco(payload: FalcoWebhook, request: Request):
    accepted = await asyncio.to_thread(request.app.state.inbox.accept,
                                      [envelope("falco", payload.model_dump(mode="json"))])
    return {"status": "accepted", "source": "falco", "events": accepted}


@app.get("/events/{event_id}")
async def event_status(event_id: UUID, request: Request):
    row = await asyncio.to_thread(request.app.state.inbox.get, str(event_id))
    if row is None:
        raise HTTPException(404, "Event not found")
    store = getattr(request.app.state, "incidents", None)
    if store:
        row["ticket"] = await asyncio.to_thread(store.event_ticket, str(event_id))
    return row


@app.get("/incidents/{incident_id}")
async def incident_status(incident_id: UUID, request: Request):
    incident = await asyncio.to_thread(request.app.state.incidents.get, str(incident_id))
    if incident is None:
        raise HTTPException(404, "Incident not found")
    return incident


@app.post("/events/{event_id}/ticket/retry", status_code=202)
async def retry_ticket(event_id: UUID, request: Request):
    try:
        return await asyncio.to_thread(request.app.state.incidents.retry, str(event_id))
    except KeyError:
        raise HTTPException(404, "Ticket job not found") from None
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None


@app.get("/health")
async def health():
    return {"status": "healthy", "version": "0.3.0",
            "features": ["flapping", "recovery_checks", "evidence_links"]}


@app.get("/v1/models")
async def models():
    return {"object": "list", "data": [{"id": OPENAI_MODEL_ID, "object": "model", "owned_by": "aiops"}]}


async def start_chat(client, messages: list[dict], thread_id: str | None):
    if thread_id:
        await client.threads.get(thread_id)
    else:
        thread = await client.threads.create(metadata={"source": "chat"})
        thread_id = thread["thread_id"]
    run = await client.runs.create(thread_id, OPENAI_MODEL_ID,
        input={"messages": messages, "event_input": None, "event_action": None},
        metadata={"source": "chat"}, config={"recursion_limit": 50},
        multitask_strategy="enqueue", durability="sync")
    return {"thread_id": thread_id, "run_id": run["run_id"]}


def upstream_error(exc: Exception) -> HTTPException:
    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 404:
        return HTTPException(404, "Thread or run not found; wait for event dispatch before chatting")
    return HTTPException(502, "Agent Server request failed; inspect the thread/run before retrying")


@app.post("/chat", status_code=202)
async def chat_turn(payload: ChatTurn, request: Request):
    """Send one new message; history lives in the server thread."""
    try:
        return await start_chat(request.app.state.client,
            [{"role": "user", "content": payload.message}],
            str(payload.thread_id) if payload.thread_id else None)
    except Exception as exc:
        raise upstream_error(exc) from exc


@app.post("/v1/chat/completions")
async def chat(payload: OpenAIChatCompletionRequest, request: Request):
    if payload.model != OPENAI_MODEL_ID:
        raise HTTPException(404, "Model not found")
    if payload.stream:
        raise HTTPException(400, "Streaming is not supported; use the Agent Server streaming API")
    if payload.thread_id and (len(payload.messages) != 1 or payload.messages[0].role != "user"):
        raise HTTPException(422, "With thread_id send exactly one new user message")
    if not any(message.role == "user" for message in payload.messages):
        raise HTTPException(422, "messages must contain a user message")
    ids = None
    try:
        ids = await start_chat(request.app.state.client,
            [message.model_dump() for message in payload.messages],
            str(payload.thread_id) if payload.thread_id else None)
        await request.app.state.client.runs.join(ids["thread_id"], ids["run_id"])
        run = await request.app.state.client.runs.get(ids["thread_id"], ids["run_id"])
        if run["status"] != "success":
            raise HTTPException(502, {**ids, "status": run["status"]})
        # Select this run's checkpoint, even if another chat turn has started.
        history = await request.app.state.client.threads.get_history(
            ids["thread_id"], limit=1, metadata={"run_id": ids["run_id"]})
        if not history:
            raise HTTPException(502, {**ids, "error": "Run checkpoint not found"})
        messages = history[0]["values"].get("messages", [])
        answer = next((m.get("content", "") for m in reversed(messages)
                       if m.get("type") == "ai" and not m.get("tool_calls")), "")
    except HTTPException:
        raise
    except Exception as exc:
        if ids:
            raise HTTPException(502, {**ids, "error": "Could not read completed run; inspect before retrying"}) from exc
        raise upstream_error(exc) from exc
    return {"id": f"chatcmpl-{uuid4().hex}", "object": "chat.completion",
            "created": int(time.time()), "model": payload.model, **ids,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": answer}, "finish_reason": "stop"}]}
