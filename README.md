# AI-Ops Agent - Local Development

## Response profiles and Studio debugging

Prompts live in `src/prompts/`. `base.txt` contains shared evidence, tool-use,
data-handling, and language rules. Each turn combines it with one profile:

| File | Trigger | Response |
| --- | --- | --- |
| `chat.txt` | Chat message, including follow-ups in event threads | Conversational troubleshooting; RCA structure only when useful |
| `alertmanager_rca.txt` | New event with `source=prometheus` | Operational RCA: symptom, cause, impact, evidence, next steps |
| `falco_security.txt` | New event with `source=falco` | Security triage: observed behavior, attribution, contributing conditions, demonstrated versus potential impact |

The visible graph path is `normalize_event → select_prompt → prepare → agent`.
Resolved alerts still bypass the model and proceed to incident lifecycle handling.
Routing uses the current turn's event action and normalized source, not keywords
in event payloads or a trigger retained from an earlier turn. Chat follow-ups keep
the investigation context but select `chat` and do not deliver new ticket updates.

Inspect `prompt_profile`, `prompt_version` (SHA-256 of the composed prompt), and
`selected_prompt` in Studio state/checkpoint history. The exact prompt is saved
per turn so resuming a checkpoint after selection retains its original prompt.
Both the regular model loop and final-answer fallback use that snapshot.
`AIOPS_MAX_TOOL_CALLS` supplies the prompt's budget as well as graph enforcement.

Edit the text files and restart/reload the Agent Server to load changes for new
turns; existing checkpoints retain their original snapshots. A new process with
`--tunnel` may receive a new Studio base URL. `system.txt` is retained as a legacy
reference and is no longer loaded. No additional assistants are required.

Automated reports use English; chat follows the user's language. Prompts guide
the model but cannot guarantee correct attribution or replace enforced tool
permissions, event deduplication, and durable incident delivery.

## Required Environment

```bash
cd /home/tanzu/manifest/workspace/aiops/aiops-agent

export OPENROUTER_API_KEY="..."
```

## Recommended Environment

```bash
export OPENROUTER_BASE_URL="https://openrouter.ai/api/v1"
export AIOPS_MODEL="deepseek/deepseek-v4-pro"
export AIOPS_MAX_TOOL_CALLS="6"
export AIOPS_MODEL_MAX_TOKENS="2048"
export AIOPS_MODEL_TIMEOUT_SECONDS="180"

export LANGSMITH_TRACING=true
export LANGCHAIN_TRACING_V2=true
export LANGSMITH_PROJECT="aiops-agent"
export LANGCHAIN_PROJECT="aiops-agent"
export LANGSMITH_ENDPOINT="https://eu.api.smith.langchain.com"
export LANGSMITH_API_KEY="..."
```

### Local llama.cpp model

The agent can use the GPU-backed `qwen38/qwen38-27b` service through
`../qwen/agent-ingress.yaml`, using a dedicated hostname for its `/v1` API.

```bash
export OPENROUTER_BASE_URL="http://llamacpp.rke2-cluster1.berger.ph/v1"
export OPENROUTER_API_KEY="local"
export AIOPS_MODEL="/models/RVN-Q4_K_M.gguf"
unset AIOPS_MODEL_THINKING_TOKEN_BUDGET
export AIOPS_MODEL_MAX_TOKENS="8192"
export AIOPS_MODEL_TIMEOUT_SECONDS="300"
```

The legacy `OPENROUTER_*` variable names also configure local OpenAI-compatible
servers. Reasoning stays enabled by the model's chat template. The output limit
covers reasoning and visible text together; the vLLM-specific thinking budget
must be unset. Restart `langgraph dev` after changing `.env`.

### Local vLLM reasoning budget

For the local Qwen model with vLLM's `qwen3` reasoning parser, use:

```bash
export AIOPS_MODEL_THINKING_TOKEN_BUDGET="1024"
export AIOPS_MODEL_MAX_TOKENS="3072"
export AIOPS_MODEL_TIMEOUT_SECONDS="300"
```

Thinking remains enabled. The thinking budget is part of the total output limit,
leaving approximately 2048 tokens for the visible answer when the full thinking
budget is used. These limits apply per model call, including the final RCA.
The timeout covers the whole call, including streaming. No SDK retries are made.
Leave `AIOPS_MODEL_THINKING_TOKEN_BUDGET` unset for providers that do not support
vLLM's `thinking_token_budget` parameter.

Empty answers and output ending with `finish_reason=length` are rejected. If
evidence is available, the investigation can enter its existing final-answer
fallback; an empty or truncated final RCA fails the run before ticket delivery.

## MCP URLs

Set all five URLs in `.env`; `src/agent.py` requires them. The following are
example endpoints for the existing cluster.

```bash
export KUBERNETES_MCP_URL="http://kubernetes-mcp-server.rke2-cluster1.berger.ph/mcp"
export PROMETHEUS_MCP_URL="http://prometheus-mcp-server.rke2-cluster1.berger.ph/mcp"
export ALERTMANAGER_MCP_URL="http://alertmanager-mcp-server.rke2-cluster1.berger.ph/mcp"
export FALCO_MCP_URL="http://falco-mcp.rke2-cluster1.berger.ph/mcp"
export GRAFANA_MCP_URL="http://grafana-mcp.rke2-cluster1.berger.ph/mcp"
```

## Start FastAPI with Uvicorn

The recommended setup below starts FastAPI inside the LangGraph Agent Server.
Uvicorn is only an optional separate facade and now requires a running Agent
Server. Set `AIOPS_AGENT_SERVER_URL=http://127.0.0.1:2024` for that facade only;
do not set it for the integrated server. Use the same absolute inbox path if
both processes accept events on the same host.

```bash
cd /home/tanzu/manifest/workspace/aiops/aiops-agent
uv sync
export AIOPS_AGENT_SERVER_URL=http://127.0.0.1:2024
uv run uvicorn src.api:app --reload --host 0.0.0.0 --port 8000 --env-file .env
```

Quick checks:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/v1/models
```

## Start LangGraph Dev Mode for LangSmith Studio

This single server exposes `/prometheus`, `/falco`, `/chat`,
`/v1/chat/completions` and the standard LangGraph thread/run APIs.

```bash
cd /home/tanzu/manifest/workspace/aiops/aiops-agent
uv sync
unset AIOPS_AGENT_SERVER_URL
uv run langgraph dev --config langgraph.json --host 0.0.0.0 --port 2024 --allow-blocking
```

If Studio needs to reach the local server from outside the machine or network:

```bash
uv run langgraph dev --config langgraph.json --host 0.0.0.0 --port 2024 --allow-blocking --tunnel
```

Note: keep real API keys out of Git. Use `.env` locally or a secret manager.

## Event-driven RCA and troubleshooting chat

Optional `.env` settings:

```dotenv
AIOPS_CLUSTER=rke2-cluster1
AIOPS_INBOX_PATH=data/inbox.sqlite3
```

`AIOPS_CLUSTER` identifies the source cluster when the Alertmanager labels do
not include `cluster`; Falco uses this setting. Use one ingress per source
cluster for Falco. Keep the cluster identity stable across restarts.

Send an Alertmanager webhook (the route consumes the standard `alerts[]`
payload, including each alert's own status):

```bash
curl -sS http://localhost:2024/prometheus \
  -H 'Content-Type: application/json' \
  -d '{"alerts":[{"status":"firing","labels":{"alertname":"PodDown","namespace":"default","pod":"demo"},"annotations":{"summary":"Pod unavailable"},"startsAt":"2026-09-13T08:00:00Z","fingerprint":"demo-pod-down"}]}'
```

Falco uses the same JSON contract as the old `/falco` route:

```bash
curl -sS http://localhost:2024/falco \
  -H 'Content-Type: application/json' \
  -d '{"rule":"Terminal shell in container","priority":"Warning","time":"2026-09-13T08:00:00.123456789Z","output":"Shell opened in demo","hostname":"worker-1","output_fields":{"k8s.ns.name":"default","k8s.pod.name":"demo"}}'
```

Both return HTTP 202 **after SQLite commits the event**, with an `events` list
containing `event_id`, `thread_id`, `status`, `run_id` (initially null), and
`duplicate`. A worker creates the thread and background run on the Agent
Server. Poll `GET /events/{event_id}` until a run is assigned. `success` means
the graph completed, not that its RCA is necessarily confident or conclusive.

In Studio, connect to this server and select the returned `thread_id` in Graph
mode. You can inspect `normalize_event`, the original input, `trigger_event`,
the investigation scope, tool messages, evidence and RCA. Enter a new user
message in the **same thread** to continue troubleshooting. An unrelated
investigation should use a new thread.

For API chat, `/chat` accepts one new message and returns background run IDs:

```bash
curl -sS http://localhost:2024/chat \
  -H 'Content-Type: application/json' \
  -d '{"message":"Why are pods restarting in namespace default?"}'
```

Include `"thread_id":"<returned-thread-id>"` on subsequent calls, or use an
event's thread after its run has been assigned. Read state via
`GET /threads/{thread_id}/state`; wait for a particular run via
`GET /threads/{thread_id}/runs/{run_id}/join`. Runs on a busy thread are queued.

`/v1/chat/completions` still returns an OpenAI-shaped answer, now with
`thread_id` and `run_id`. With `thread_id`, send exactly **one new user message**;
history is already stored. Without it, the supplied message history starts a
new thread. Generic chat clients that do not preserve the extra field therefore
create a new Studio thread per request. `stream: true` remains unsupported;
use the standard Agent Server streaming API or Studio for streaming.

```bash
curl -sS http://localhost:2024/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"aiops-agent","thread_id":"<event-thread-id>","messages":[{"role":"user","content":"What should I check next?"}]}'
```

## Persistence, duplicates and recovery

- Alertmanager identity: cluster + fingerprint (or labels hash) + `startsAt`.
  Repeated firing notifications start one RCA per episode. `resolved` is a
  separate lifecycle event on the same thread and does not call the model.
  A new `startsAt` creates a new episode. `Watchdog` is ignored. Changed
  annotations on a repeated firing notification do not start another RCA.
- Falco identity: cluster + event `uuid`/`id` when supplied, otherwise a hash of
  the payload. Exact redeliveries are deduplicated; distinct events, even with
  sub-microsecond timestamps, remain distinct. Incident correlation below groups
  their tickets; each distinct event still gets its own RCA.
- Pending inbox entries survive restarts and are retried when the Agent Server
  becomes reachable. Accepted server runs are monitored. A local file lock
  ensures only one dispatcher serves a given SQLite inbox during reloads.
- If a process dies during submission, the lease expires after at most 120
  seconds. The worker finds an existing run through `event_id` metadata and
  records its ID. A lost HTTP response is reconciled the same way.
- If submission is ambiguous and no matching run can be found, status remains
  `uncertain`. The worker keeps checking but deliberately does not blindly
  create another run. Inspect the thread/run history before manual recovery.
  There is no cross-database exactly-once transaction between SQLite and the
  Agent Server. Graph errors/timeouts remain visible and are not retried as a
  fresh RCA automatically; inspect/resume their checkpoints in Studio.
- `data/inbox.sqlite3` is the ingress database; `.langgraph_api/` holds the local
  dev server's state. Keep both across development restarts. Neither belongs
  in Git. Do not delete server threads/runs while relying on inbox recovery.
- `langgraph dev` is a development runtime. For production use an Agent Server
  deployment with its PostgreSQL persistence and durable volumes, plus a
  durable volume for this inbox. This implementation targets a single host /
  ingress replica; multiple hosts require a shared transactional inbox such as
  PostgreSQL instead of SQLite and local file locking. Protect the ingress and
  thread APIs through the deployment's authentication/network controls.

## Automatic ServiceNow incidents

With `SERVICENOW_INSTANCE_URL` configured, webhook investigations continue through
two visible Studio nodes after `capture_answer`:

```text
RCA -> record_incident -> sync_servicenow -> end
```

Ticket creation and updates are automatic, with no approval step. Regular chat
turns do not write to ServiceNow. A completed RCA is copied into the initial
incident description and work notes. Each subsequent correlated event adds a
work note containing its event ID, source, scope, occurrence time, RCA and thread
ID. Resolved notifications append a lifecycle note without another model call;
they neither create an incident on their own nor automatically close a ticket.
If RCA fails before these nodes, inspect the failed run; no ticket is queued yet.

Work notes render RCA Markdown as HTML enclosed in ServiceNow `[code]` tags,
with status, scope, timestamps and the event/thread references. Raw HTML from
alerts or model responses is escaped; images are not embedded. The initial
description uses plain text. Recommended actions appear only in the RCA, without
duplicating the opening summary. Resolved notes contain only lifecycle details.
This requires ServiceNow's `glide.ui.security.allow_codetag` support. Set
`SERVICENOW_NOTE_FORMAT=text` for instances that disable it. No instance security
properties are changed by the agent. Existing journal entries are not rewritten.

### Recurring alerts, recovery verification and evidence links

Prometheus episodes are observed atomically with inbox acceptance. Three distinct
episodes of the same alert series within 30 minutes are marked `FLAPPING` in the
ticket. This uses alert start times, not delivery times, and does not count
duplicate notifications. A recent RCA of the exact series and severity can be
reused for further episodes; the shorter note references its original event and
explicitly says it has not been freshly revalidated. A changed severity, expired
analysis or different series still gets a full investigation. Falco events are
not suppressed. Observations begin when this version receives/processes events;
historical tickets are not replayed.

After a `resolved` notification, a durable worker checks once a minute using the
existing read-only `prod_execute_query` MCP tool, without another model call.
Confirmation requires all of the following on repeated checks across ten minutes:

- No matching firing/pending `ALERTS`, including the observed stability window.
- The original expression from `generatorURL` returns no results.
- Positive, fresh health samples (at most 120 seconds old) for the scoped pod,
  node or scrape target: `kube_pod_status_ready`, `kube_node_status_condition`, or `up`.

This verifies the checked scope, not every possible root cause. Empty health
data, missing expressions, unsupported scope or query errors never count as
recovery. The configured MCP must serve `AIOPS_RECOVERY_CLUSTER` (default:
`AIOPS_CLUSTER`, or `default`); other clusters remain unverified. A globally
scoped alert expression may conservatively block confirmation while another
resource still matches it. Test alerts without resource scope remain unverified.
Failures or sampling gaps longer than two check intervals reset the stability
window. Checks survive restarts; newer episodes cancel older checks immediately
on receipt. A result committed before a new episode but not yet delivered is
skipped by the ticket worker. After one hour without confirmation, one short
`RECOVERY NOT VERIFIED` note explains why. Success adds one `RECOVERY VERIFIED`
note through the normal durable outbox. Neither result creates a new incident,
reopens a closed ticket, or changes its state automatically. Check status and
the latest observations are exposed by `GET /incidents/{incident_id}`.

```dotenv
AIOPS_FLAP_THRESHOLD=3
AIOPS_FLAP_WINDOW_SECONDS=1800
AIOPS_RECOVERY_ENABLED=true
AIOPS_RECOVERY_INTERVAL_SECONDS=60
AIOPS_RECOVERY_STABLE_SECONDS=600
AIOPS_RECOVERY_MAX_SECONDS=3600
# Set only when different from AIOPS_CLUSTER:
# AIOPS_RECOVERY_CLUSTER=rke2-cluster1
```

Evidence links are constructed from captured tool queries and observation times,
not model-generated URLs. Range queries preserve their explicit time range;
instant-query links show five minutes around the query/observation time. The
alert timeline shows the episode with five minutes of context. The generator
URL supplies the Prometheus browser path when no public URL is configured.
Runbook annotations are retained. Grafana links require the actual datasource
UIDs; without a configured browser URL/UID the corresponding link is omitted.
`Explore pod logs` is a scoped follow-up query, not a claim that logs were read.
The agent link opens the existing thread state through the Agent Server API.

```dotenv
# Optional browser URLs; no credentials or access tokens in these values.
AIOPS_PROMETHEUS_PUBLIC_URL=https://prometheus.example.com
AIOPS_GRAFANA_PUBLIC_URL=https://grafana.example.com
AIOPS_GRAFANA_PROMETHEUS_UID=prometheus
AIOPS_GRAFANA_LOKI_UID=your-loki-uid
AIOPS_GRAFANA_ORG_ID=1
AIOPS_AGENT_PUBLIC_URL=https://agent.example.com
```

Restart after changing environment values. `/health` reports version `0.3.0`
and the supported feature names. Source code reload alone may not refresh the
parent process environment. Existing journal entries are not modified.

The existing bridge's environment variable names are supported:

```dotenv
SERVICENOW_INSTANCE_URL=https://your-instance.service-now.com
SERVICENOW_USER=your-integration-user
SERVICENOW_PASSWORD=your-password
SERVICENOW_DRY_RUN=true
SERVICENOW_NOTE_FORMAT=html
SERVICENOW_CORRELATION_FIELD=correlation_id
SERVICENOW_CATEGORY=inquiry
SERVICENOW_SUBCATEGORY=
SERVICENOW_ASSIGNMENT_GROUP=
AIOPS_INCIDENT_WINDOW_SECONDS=3600
```

No instance URL means disabled. `SERVICENOW_DRY_RUN` defaults to `true`: the full
local path is exercised, but no ServiceNow requests are sent. Set it to `false`
for live writes and restart the server after changing `.env`. Already completed
dry-run jobs are not replayed into ServiceNow when this flag changes; use a new
event to test live delivery. The integration requires HTTPS and a Basic Auth user
with incident read/create/update permissions, including the correlation field
and work notes. Authentication failures surface as HTTP 401 in ticket status.

### Event identity, incident correlation and tickets

These are separate layers:

1. The existing inbox rejects duplicate `event_id` values before RCA.
2. `record_incident` assigns distinct events to a persistent incident. The default
   key contains source, cluster, namespace, event type and the most specific
   available resource: pod, node, instance or service. If these are absent, an
   alert fingerprint or the event's own episode is used. A shared `job` alone
   never combines alerts from different hosts.
3. A new event with the same key joins an active local incident if it was seen
   within the last `AIOPS_INCIDENT_WINDOW_SECONDS` (default one hour), measured
   when the completed investigation is recorded. An existing Alertmanager episode
   remains attached for its later resolved notification, even beyond this window.
4. ServiceNow stores `aiops:<incident UUID>` in the configured correlation field.
   The local registry remembers the returned `sys_id` and incident number. When a
   later firing event encounters a resolved/closed/canceled ServiceNow ticket,
   it starts a new incident generation. Closed tickets are not reopened.

For intentional grouping across event types or sources, supply the same explicit
key and cluster identity:

- Alertmanager: label `aiops_incident_key`.
- Falco: output field `aiops.incident_key`.

Explicit keys are scoped by cluster; choose incident-specific values rather than
a broad namespace or application name. Set `AIOPS_CLUSTER` consistently for
events without their own cluster label. Automatic causal grouping across unrelated
signals is deliberately not inferred by the model. Existing RCA threads remain
separate by event/alert episode; several threads can be linked to one ticket.

### Persistence, status and recovery

The registry and `ticket_jobs` outbox share `AIOPS_INBOX_PATH`
(`data/inbox.sqlite3`). A local file lock serializes ServiceNow writers across the
graph and background worker. New tables are additive; previous completed RCA
runs are not automatically exported. Keep this database across restarts.

```bash
curl -sS http://localhost:2024/events/EVENT_UUID
curl -sS http://localhost:2024/incidents/INCIDENT_UUID
```

The event response includes a separate `ticket` object with `incident_id`,
`status`, `operation`, `attempts`, `sys_id`, `number` and `error`. The incident
response lists all linked events and threads. The graph state contains the ticket
result observed during that run; after background retries, these API endpoints
are the current delivery status. RCA `success` and ticket delivery `success` are
separate outcomes.

- `pending`: waiting or retrying a safe failure (for example rate limiting).
- `success`: ServiceNow confirmed the write or a lost create response was
  reconciled through its correlation ID.
- `dry_run`: locally completed without external writes.
- `error`: a configuration/API error requires operator attention. Correct the
  cause before retrying; later jobs for that incident wait to preserve ordering.
  After fixing configuration and restarting the server, use
  `POST /events/EVENT_UUID/ticket/retry` to retry that confirmed failure. This
  endpoint rejects `uncertain` writes and completed jobs with HTTP 409.
- `uncertain`: the write may have committed. Create operations are reconciled by
  lookup without another POST. Work-note updates with an unknown outcome are not
  automatically repeated; inspect the `[AIOPS-EVENT:<event UUID>]` marker in the
  ticket before manual reconciliation. This prevents duplicate journal entries.
- `skipped_closed`: a resolved notification targeted an already closed ticket.

The correlation field must exist and be readable/writable. This integration
fails closed on duplicate lookup results, missing correlation fields, and a
changed correlation ID on a linked ticket. A normal ServiceNow correlation field
is not inherently a uniqueness constraint: for multiple application instances or
other writers, enforce uniqueness/atomic idempotency in ServiceNow and use a
shared transactional job store. The current file lock is a single-host design.
Do not run the old direct bridge as a second ticket writer for the same events.

## Verification

```bash
uv run python -m unittest discover -s tests -v
```

Tests cover webhook validation, duplicate deliveries, lost submission responses,
offline recovery, alert lifecycle, evidence state and follow-up chat. The server
integration test starts an isolated local Agent Server with a deterministic
model, checks the real thread/run APIs, then restarts it and checks persistence.
It does not call live MCP endpoints or a model provider. ServiceNow tests use
MockTransport/fakes and temporary databases, plus a real local Agent Server in
dry-run mode. They cover automatic ticket creation, correlation, replay, resolved
updates, closed-ticket rotation, ambiguous writes and recovery after a restart.

References: [custom FastAPI routes](https://docs.langchain.com/langsmith/custom-routes),
[background runs](https://docs.langchain.com/langsmith/background-run),
[Studio observability](https://docs.langchain.com/langsmith/observability-studio).

---

# AI-Ops Agent Roadmap

## Phase 1 - Foundation (jetzt)

### Komponenten

- OpenRouter (GPT-4.1-mini)
- LangChain Agent
- Kubernetes MCP
- Prometheus MCP
- Alertmanager MCP
- Python Tool

### Ziel

- Tool Calling verstehen
- Kubernetes analysieren
- Prometheus abfragen
- Alerts lesen
- Erste RCA-Fragen beantworten

### Beispiele

- Show all namespaces
- Show pods in ai namespace
- Which node has highest CPU?
- Show active alerts

---

## Phase 2 - RCA Agent

### Komponenten

- LangChain Agent
- Kubernetes MCP
- Prometheus MCP
- Alertmanager MCP
- Python Tool

### Ziel

Der Agent kann beantworten:

- Why is OpenWebUI down?
- Why is this pod restarting?
- Why is CPU usage high?
- Which node has resource pressure?

### Ablauf

- Alert lesen
- Metriken sammeln
- Events sammeln
- Analyse durchführen
- RCA erstellen

### LangGraph?

- Noch nicht zwingend
- Agent entscheidet selbst, welche Tools er benutzt

---

## Phase 3 - Erster LangGraph Workflow

### Ziel

Den ersten strukturierten RCA Workflow bauen.

### State

- Alert
- Metrics
- Events
- Logs
- RCA
- Recommendation

### Nodes

- Get Alert
- Collect Metrics
- Collect Events
- Collect Logs
- Generate RCA
- Generate Recommendation

### Ablauf

```text
Alert
  |
  v
Collect Metrics
  |
  v
Collect Events
  |
  v
Collect Logs
  |
  v
Generate RCA
  |
  v
Generate Recommendation
```

### Ziel

- LangGraph lernen
- State Management verstehen
- Nodes und Edges verstehen
- RCA reproduzierbar machen

### Warum hier LangGraph?

Weil der Ablauf bereits bekannt und wiederholbar ist.

---

## Phase 4 - Investigation Logging

### Komponenten

- JSONL Logging
- PostgreSQL

### Speichern

- User Frage
- Tool Calls
- Tool Results
- RCA
- Empfehlungen

### Ziel

Investigation History

### Beispiele

- Show previous investigations
- Show previous RCA reports
- Continue previous investigation

---

## Phase 5 - Incident Management

### Komponenten

- PostgreSQL
- Incident Store

### Speichern

- Open Incidents
- Closed Incidents
- RCA
- Resolution
- Severity
- Owner

### Ziel

Der Agent kann:

- Incident erstellen
- Incident aktualisieren
- Incident schließen

---

## Phase 6 - Human Approval

### Komponenten

- Approval Queue

### Agent darf vorschlagen

- Restart Pod
- Scale Deployment
- Delete Failed Pod
- Rollback Deployment

### Agent darf NICHT direkt ausführen

### Ablauf

- Agent erstellt Empfehlung
- Mensch prüft
- Mensch genehmigt
- Aktion wird ausgeführt

### Ziel

Sichere Automatisierung

---

## Phase 7 - Event Driven AI-Ops

### Trigger

Nicht mehr der User.

Trigger sind:

- Alertmanager Alert
- Prometheus Alert
- Falco Alert
- Webhooks

### Workflow

```text
Alert
  |
  v
LangGraph Workflow
  |
  v
Metrics
  |
  v
Events
  |
  v
Logs
  |
  v
RCA
  |
  v
Incident
  |
  v
Human Approval
  |
  v
Remediation
```

### Warum LangGraph?

Jeder Alert durchläuft dieselben Schritte.

---

## Phase 8 - Falco Security Workflow

### Trigger

Falco Alert

### Workflow

- Kubernetes Kontext sammeln
- Related Events sammeln
- Analyse durchführen
- Klassifizieren

### Ergebnis

- False Positive
- Likely True Positive

### Wichtig

Nicht automatisch verwerfen.

Stattdessen:

- Classification
- Confidence Score
- Reasoning

### Beispiel

```text
Classification: likely_true_positive
Confidence: 0.91

Reason:
- production namespace
- unexpected shell
- no deployment activity
```

### Warum LangGraph?

Security Alerts haben ebenfalls einen festen Ablauf.

---

## Phase 9 - Long Term Memory

### PostgreSQL

Speichern von:

- Incidents
- Investigations
- Falco Findings
- RCA Reports
- Remediations

### Später

- pgvector

### Beispiele

- Have we seen this before?
- Show similar incidents
- Show similar Falco alerts

---

## Phase 10 - Autonomous Operations

### Zielbild

```text
Prometheus Alert oder Falco Alert
  |
  v
LangGraph Workflow
  |
  v
Metrics
  |
  v
Events
  |
  v
Logs
  |
  v
Analysis
  |
  v
RCA
  |
  v
Classification
  |
  v
Incident
  |
  v
Human Approval
  |
  v
Remediation
  |
  v
Memory
  |
  v
Learning
```

---

## Nächste 10 Tage

- Kubernetes MCP fertigstellen
- Read-Only Tool Filter einbauen
- Interaktive CLI bauen
- Prometheus MCP integrieren
- Alertmanager MCP integrieren
- Ersten LangGraph RCA Workflow bauen
- Investigation Logging (JSONL)
- PostgreSQL Incident Store
- Human Approval Workflow
- Alertmanager Webhook -> LangGraph Workflow
- Falco Webhook -> Security Workflow (PoC)

---

## Langfristiges Ziel

Ein AI-Ops Agent, der:

- Alerts automatisch entgegennimmt
- Kubernetes analysiert
- Prometheus analysiert
- Falco Security Events analysiert
- RCA erstellt
- Incidents erstellt
- Empfehlungen generiert
- Human Approval einholt
- Remediation ausführt
- Aus vergangenen Incidents lernt

Das ist aus meiner Sicht deutlich näher an einer echten zukünftigen AI-Ops Plattform als ein klassisches RAG-Projekt.

### Ticket buttons and operator approvals

HTML links in new work notes (including Markdown RCA links and evidence links)
request a new browser tab with `target="_blank"` and `rel="noopener noreferrer"`.
ServiceNow must preserve these attributes in its HTML sanitizer; text descriptions
retain plain URLs and their opening behavior is controlled by ServiceNow/browser
preferences. Existing journal entries are not rewritten.

Set the following to display **Weitere Analyse** and **Remediation planen**
links styled as buttons in newly generated work notes:

```bash
export AIOPS_AGENT_PUBLIC_URL="https://agent.example.com"
# Supply this JSON through a Secret/environment injection; use individual,
# strong random operator passwords, not the illustrative values below.
export AIOPS_ACTIONS_USERS='{"operator-name":"replace-with-a-long-random-password"}'
export AIOPS_DETAILED_MAX_TOOL_CALLS="12"
```

The buttons open an authenticated operator page. Browser HTTP Basic authentication
requires HTTPS at the ingress. All configured operators may approve actions for
all configured remediation namespaces. Keep the existing authentication/network
controls on Agent Server and its thread APIs. GET requests only display forms;
POST requests require an actor/path-bound, expiring CSRF token. A second page
shows the concrete action before confirmation. Each request expires ten minutes
after preparation and can be executed once; repeated confirmation does not replay
it. Only one queued/running operator action per incident is accepted.

Detailed analysis runs on the original thread with fresh evidence, the previous
RCA as context, an expanded report and a larger tool budget (default 12, capped
at 20 unless the ordinary budget is higher). It bypasses recurrence/RCA reuse and
writes its result through the existing ServiceNow outbox into the same incident.
It does not change the alarm lifecycle or automatically close the ticket.

There are two operator workflows:

- **Weitere Analyse**: the existing read-only investigation, or an explicitly
  selected extended analysis plan. Extended analysis may include approved
  container commands for diagnosis; those commands can have side effects and
  are displayed in full before confirmation. Known mutating resource tools are
  rejected in analysis plans (reading scale without setting it is allowed).
- **Remediation planen**: generate one complete plan from the incident and recent
  reports. All tools exposed by the configured remediation MCP server may be
  proposed, including create/update, scale, exec, and delete. There are no
  separate restart/exec executors or buttons.

Both privileged workflows use **one general plan executor**. Preparation only
lists MCP tool definitions and asks the model for structured steps; it does not
invoke those tools. The proposal includes the purpose, cluster, impact, exact
arguments/manifests/commands, expected results and a final read-only verification
step for remediation. The authenticated review page shows every step in full.
One confirmation approves that immutable plan, not future model decisions.
No output interpolation, automatic replanning or additional tool calls take place
inside the executor. If a target can only be identified through further analysis,
prepare an analysis plan first and then a new remediation plan with fresh evidence.

Configure a **separate**, network-restricted MCP server pinned to a **single
cluster/context**, with the Kubernetes permissions needed for approved plans.
The ordinary model MCP connections remain read-only at the server/RBAC level.
The repository's existing reader Helm values are not changed by this workflow.

```bash
export AIOPS_REMEDIATION_MCP_URL="https://private-remediation-mcp.example.com/mcp"
export AIOPS_REMEDIATION_CLUSTER="cluster1"
export AIOPS_REMEDIATION_NAMESPACES="application-a,application-b"
# Use "*" to allow plans for incidents in every namespace, including cluster-scoped incidents.
```

The namespace setting selects which incidents can use plans; Kubernetes RBAC on
this endpoint is the authoritative boundary for each step's resource access.
All supported action types are available; this does not itself grant Kubernetes
permissions. Typical RBAC includes get/list/watch for diagnosis, create/update/
patch/delete on managed resources, get/update/patch on scale subresources, and
create (transport-dependent get) on pods/exec. Enable cluster-scoped resources
only on an endpoint whose account is intended to manage them. A ticket approval
never modifies RBAC. Exec remains unrestricted inside the selected container;
its declared diagnostic purpose is not a sandbox. Namespace arguments must be
explicit when the tool supports them. Resource manifests must include their
intended target information. Do not change a server's context during a plan.

The executor validates the entire plan against current tool schemas and the
saved tool-contract fingerprints before the first call. It rechecks expiry,
operator access, incident state, cluster and endpoint before each step. A failed
or ambiguous call stops the plan; completed steps are never automatically
replayed and subsequent steps are skipped. Existing legacy restart/exec drafts
or queued actions cannot execute after this upgrade; prepare a new plan instead.

Plans and operator identities are persisted in `operator_actions`; the additive
`operator_action_steps` table records pending/running/completed/uncertain/skipped
states. Preparation and completion notes go through the existing outbox into the
same ticket. Ticket-size limits may truncate a long plan, so its direct review
link opens the full saved plan. Tool outputs are held only in memory, bounded,
and passed to a model without tools for an evidence-based report; raw outputs
are not written to the action journal. Do not put secrets in arguments, manifests
or commands because the complete approved parameters are stored and displayed.
The report distinguishes successful tool calls from verified recovery; if report
generation fails, the completed calls remain recorded and the UI requests manual
verification. Tickets are not automatically closed by plan execution.

A plan expires ten minutes after preparation and starts only once. Each tool call
has a 120-second timeout; the full execution/report has a 600-second timeout.
A timeout or restart leaves the result uncertain, with no automatic retry or
rollback. Inspect the step journal and cluster before approving a replacement
plan. As with the inbox/outbox, this worker supports one local SQLite host;
multiple replicas must not use independent databases for the same incidents.

When operator actions are configured, the global `AIOPS_ENABLE_MUTATING_TOOLS`
override is ignored and ordinary model turns only receive known readers or tools
with `readOnlyHint=true` (known mutators remain excluded).

These changes require deployment and MCP/RBAC configuration. Tests use mock
models and MCP calls; they do not perform live Kubernetes or ServiceNow writes.
