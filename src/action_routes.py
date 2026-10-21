"""Authenticated browser forms. GET links never execute or approve an action."""

import asyncio
import hashlib
import hmac
from html import escape
import json
import os
import secrets
import time
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from src.actions import enabled, remediation_scope
from src.action_plans import prepare_plan

router = APIRouter()
auth = HTTPBasic()


def operator(credentials: HTTPBasicCredentials = Depends(auth)):
    try:
        users = json.loads(os.getenv("AIOPS_ACTIONS_USERS", "{}"))
        password = users.get(credentials.username)
        valid = isinstance(password, str) and secrets.compare_digest(credentials.password.encode(), password.encode())
    except (ValueError, AttributeError):
        valid = False
    if not valid or not enabled():
        raise HTTPException(401, "Operator-Anmeldung erforderlich", headers={"WWW-Authenticate": "Basic"})
    return credentials.username


def csrf(actor, path):
    expires = str(int(time.time()) + 600)
    secret = os.environ["AIOPS_ACTIONS_USERS"].encode()
    signature = hmac.new(secret, f"{actor}:{path}:{expires}".encode(), hashlib.sha256).hexdigest()
    return f"{expires}.{signature}"


async def form(request, actor):
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > 16000:
            raise HTTPException(413)
    try:
        values = {key: parts[-1] for key, parts in parse_qs(data.decode()).items()}
    except UnicodeError:
        raise HTTPException(400, "Ungültiges Formular") from None
    try:
        expires, signature = values.pop("csrf").split(".", 1)
        secret = os.environ["AIOPS_ACTIONS_USERS"].encode()
        expected = hmac.new(secret, f"{actor}:{request.url.path}:{expires}".encode(), hashlib.sha256).hexdigest()
        valid = time.time() < int(expires) <= time.time() + 601 and secrets.compare_digest(signature, expected)
    except (ValueError, KeyError):
        valid = False
    if not valid:
        raise HTTPException(403, "Formular abgelaufen oder ungültig. Seite neu laden.")
    return values


def page(title, body):
    return HTMLResponse('<!doctype html><html lang="de"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>{escape(title)}</title><body><main><h1>{escape(title)}</h1>{body}</main></body></html>',
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
                 "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
                 "X-Content-Type-Options": "nosniff"})


def hidden(actor, path):
    return f'<input type="hidden" name="csrf" value="{csrf(actor, path)}">'


def action_path(action_id):
    base_path = urlsplit(os.getenv("AIOPS_AGENT_PUBLIC_URL", "")).path.rstrip("/")
    return f"{base_path}/operator/actions/{action_id}"


@router.get("/incidents/{incident_id}/actions", response_class=HTMLResponse)
async def actions_page(incident_id: UUID, request: Request, actor=Depends(operator)):
    store = request.app.state.actions
    try:
        row = store.event(str(incident_id))
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from None
    event = json.loads(row["payload"])
    target = " / ".join(str(event.get(k) or "—") for k in ("cluster", "namespace", "pod"))
    body = f'<p>Incident: {escape(str(incident_id))}</p><p>Ziel: {escape(target)}</p>'
    body += (f'<form method="post">{hidden(actor, request.url.path)}'
             '<input type="hidden" name="kind" value="analysis">'
             '<h2>Weitere Analyse</h2>'
             '<label>Umfang <select name="access"><option value="standard">Lesende Fehleranalyse</option>'
             + ('<option value="extended">Erweiterte Analyse mit freigegebenem Plan</option>' if remediation_scope(event) else '')
             + '</select></label> <button>Analyse vorbereiten</button></form>'
             '<p>Neue Messwerte, Logs, alternative Ursachen und gezielte nächste Schritte. Ergebnis im selben Incident.</p>')
    if remediation_scope(event):
        body += (f'<h2 id="permissions">Remediation</h2><form method="post">{hidden(actor, request.url.path)}'
                 '<input type="hidden" name="kind" value="remediation">'
                 '<p>Der Agent schlägt alle nötigen Schritte vor, einschließlich Erstellen, Ändern, Skalieren und Löschen. '
                 'Vor der Ausführung prüfst und bestätigst du den vollständigen Plan einmal.</p>'
                 '<button>Remediation-Plan vorbereiten</button></form>'
                 '<p>Erweiterte Analyse kann Container-Befehle mit Nebenwirkungen enthalten. '
                 'Auch diese Schritte werden zuerst angezeigt und müssen bestätigt werden.</p>')
    else:
        body += '<p id="permissions">Eingriffe sind für dieses Ziel nicht eingerichtet. Ein begrenzter MCP-Zugang und eine Cluster-/Namespace-Freigabe sind erforderlich.</p>'
    with store.incidents.connect() as db:
        recent = db.execute("SELECT action_id,kind,status,actor FROM operator_actions WHERE incident_id=? ORDER BY created_at DESC LIMIT 20", (str(incident_id),)).fetchall()
    body += '<h2>Bisherige Aufträge</h2><ul>'
    for action in recent:
        body += f'<li><a href="{escape(action_path(action["action_id"]), quote=True)}">{escape(action["kind"])} — {escape(action["status"])}</a> ({escape(action["actor"])})</li>'
    return page("Incident-Aktionen", body + '</ul>')


@router.post("/incidents/{incident_id}/actions")
async def prepare_action(incident_id: UUID, request: Request, actor=Depends(operator)):
    values = await form(request, actor)
    try:
        store = request.app.state.actions
        kind = values.get("kind")
        if kind not in {"analysis", "remediation"} or values.get("access", "standard") not in {"standard", "extended"}:
            raise ValueError("Unbekannte Aktion.")
        if kind == "remediation" or values.get("access") == "extended":
            row = store.event(str(incident_id))
            event = json.loads(row["payload"])
            if not remediation_scope(event):
                raise ValueError("Pläne sind für diesen Cluster/Namespace nicht eingerichtet.")
            endpoint = os.environ["AIOPS_REMEDIATION_MCP_URL"]
            plan = await asyncio.wait_for(prepare_plan(event, store.evidence(str(incident_id)), kind), timeout=180)
            action = store.create(str(incident_id), actor, "plan", plan=plan, purpose=kind,
                                  event_id=row["event_id"], endpoint=endpoint)
        else:
            action = store.create(str(incident_id), actor, "analysis")
    except (ValueError, KeyError) as exc:
        raise HTTPException(422, str(exc)) from None
    except Exception:
        raise HTTPException(502, "Plan konnte nicht vorbereitet werden. Es wurde kein Schritt ausgeführt.") from None
    return RedirectResponse(action_path(action["action_id"]), status_code=303)


@router.get("/operator/actions/{action_id}", response_class=HTMLResponse)
async def action_page(action_id: UUID, request: Request, actor=Depends(operator)):
    action = request.app.state.actions.get(str(action_id))
    if not action:
        raise HTTPException(404, "Auftrag nicht gefunden")
    payload = json.loads(action["payload"])
    target = {k: payload["event"].get(k) for k in ("cluster", "namespace", "pod")}
    target.update(action=action["kind"], purpose=payload.get("purpose", "analysis"))
    body = f'<p>Status: {escape(action["status"])}</p><pre>{escape(json.dumps(target, ensure_ascii=False, indent=2))}</pre>'
    plan = payload.get("plan")
    if plan:
        body += f'<h2>Maßnahmenplan</h2><p>{escape(plan["summary"])}</p><p>Auswirkungen: {escape(plan["risks"])}</p><ol>'
        statuses = {row["step_index"]: row["status"] for row in request.app.state.actions.steps(str(action_id))}
        for index, step in enumerate(plan["steps"]):
            body += (f'<li><h3>{escape(step["title"])}</h3><p>{escape(step["tool"])} — {escape(step["phase"])} '
                     f'— {escape(statuses.get(index, "pending"))}</p>'
                     f'<pre>{escape(json.dumps(step["arguments"], ensure_ascii=False, indent=2))}</pre>'
                     f'<p>Erwartet: {escape(step["expected_result"])}</p></li>')
        body += '</ol><p>Alle Parameter sind festgelegt. Zusätzliche oder geänderte Schritte benötigen einen neuen Plan mit Bestätigung.</p>'
    if action["kind"] not in {"analysis", "plan"}:
        body += '<p>Dieser alte Einzelauftrag ist nicht mehr ausführbar. Bitte einen neuen Plan vorbereiten.</p>'
    elif action["status"] == "draft" and action["actor"] == actor:
        body += (f'<form method="post">{hidden(actor, request.url.path)}'
                 '<p>Dieser Auftrag gilt einmalig für das angezeigte Ziel. Freigabe verfällt nach 10 Minuten.</p>'
                 '<button>Alle angezeigten Schritte freigeben und starten</button></form>')
    else:
        body += '<p>Die Seite neu laden, um den aktuellen Status zu sehen.</p>'
    if action["result"]:
        body += f'<pre>{escape(action["result"])}</pre>'
    return page("Auftrag prüfen", body)


@router.post("/operator/actions/{action_id}")
async def confirm_action(action_id: UUID, request: Request, actor=Depends(operator)):
    await form(request, actor)
    try:
        request.app.state.actions.confirm(str(action_id), actor)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    return RedirectResponse(action_path(str(action_id)), status_code=303)
