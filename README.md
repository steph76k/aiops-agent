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
