"""Deterministic investigation links; URLs are not invented by the model."""

from datetime import datetime, timezone
import json
import os
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit, quote

from src.lifecycle import timestamp


def safe_url(value):
    if not isinstance(value, str) or len(value) > 3000 or any(c.isspace() for c in value):
        return None
    try:
        u = urlsplit(value)
        if u.scheme in {"http", "https"} and u.hostname and not u.username and not u.password:
            return value
    except ValueError:
        pass
    return None


def selector(metric, labels):
    return metric + "{" + ",".join(f"{key}={json.dumps(str(value), ensure_ascii=False)}"
        for key, value in sorted(labels.items()) if value is not None and re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", key)) + "}"


def alert_selector(event):
    # Webhook labels can include external labels absent from local Prometheus.
    keys = ("namespace", "pod", "node", "instance", "job", "service", "container", "reason", "integration")
    labels = {k: event.get("labels", {}).get(k) or event.get(k) for k in keys}
    labels["alertname"] = event.get("event_type")
    return selector("ALERTS", labels)


def _range(event):
    start = timestamp(event.get("starts_at") or event.get("event_time"))
    end = timestamp(event.get("ends_at"))
    checked = timestamp(event.get("ingest_time"))
    start = start if start is not None else checked
    if start is None:
        return None
    end = max(start, end or 0, checked or 0)
    return int((start-300)*1000), int((end+300)*1000)


def _prometheus_url(event, query, bounds):
    base = safe_url(os.getenv("AIOPS_PROMETHEUS_PUBLIC_URL", ""))
    if base:
        base = base.rstrip("/") + "/graph"
    else:
        base = safe_url(event.get("generator_url"))
    if not base:
        return None
    url = urlsplit(base)
    args = {k: v for k, v in parse_qsl(url.query) if not k.startswith("g0.")}
    args.update({"g0.expr": query, "g0.tab": "0"})
    if bounds:
        args["g0.end_input"] = datetime.fromtimestamp(bounds[1]/1000, timezone.utc).isoformat()
        args["g0.range_input"] = str(max(1, (bounds[1]-bounds[0])//1000)) + "s"
    return urlunsplit((url.scheme, url.netloc, url.path, urlencode(args), ""))


def _explore(query, kind, uid, bounds):
    base = safe_url(os.getenv("AIOPS_GRAFANA_PUBLIC_URL", ""))
    if not base or not uid or not bounds:
        return None
    ds = {"uid": uid, "type": kind}
    pane = {"datasource": uid, "queries": [{"refId": "A", "datasource": ds, "expr": query}],
            "range": {"from": str(bounds[0]), "to": str(bounds[1])}}
    return base.rstrip("/") + "/explore?" + urlencode({"schemaVersion": "1",
        "orgId": os.getenv("AIOPS_GRAFANA_ORG_ID", "1"), "panes": json.dumps({"aiops": pane}, separators=(",", ":"))})


def build_links(event, thread_id, evidence=()):
    links = []
    bounds = _range(event)

    def add(label, url, collected_at=None):
        if safe_url(url) and url not in {item["url"] for item in links}:
            links.append({"label": label, "url": url, "collected_at": collected_at})

    add("Runbook", event.get("annotations", {}).get("runbook_url"))
    if event.get("source") == "prometheus":
        add("Prometheus alert timeline", _prometheus_url(event, alert_selector(event), bounds))
    for item in evidence:
        query = item.get("query")
        if not query or len(query) > 1500:
            continue
        # Keep each observed query's own time window if supplied.
        start, end = timestamp(item.get("start")), timestamp(item.get("end"))
        instant = timestamp(item.get("time") or item.get("collected_at"))
        item_bounds = ((int(start*1000), int(end*1000)) if start and end else
                       (int((instant-300)*1000), int((instant+300)*1000)) if instant else bounds)
        if item.get("category") == "metric":
            add("Prometheus evidence", _prometheus_url(event, query, item_bounds), item.get("collected_at"))
            add("Grafana metrics", _explore(query, "prometheus", os.getenv("AIOPS_GRAFANA_PROMETHEUS_UID"), item_bounds), item.get("collected_at"))
        elif item.get("category") == "log":
            add("Grafana Loki evidence", _explore(query, "loki", item.get("datasource_uid") or os.getenv("AIOPS_GRAFANA_LOKI_UID"), item_bounds), item.get("collected_at"))
        if len(links) >= 6:
            break
    # This is a scoped follow-up query, explicitly not presented as collected evidence.
    if event.get("namespace") and event.get("pod"):
        query = selector("", {"namespace": event["namespace"], "pod": event["pod"]})
        add("Explore pod logs", _explore(query, "loki", os.getenv("AIOPS_GRAFANA_LOKI_UID"), bounds))
    base = safe_url(os.getenv("AIOPS_AGENT_PUBLIC_URL", ""))
    if base:
        add("Agent thread state", base.rstrip("/") + "/threads/" + quote(thread_id, safe="") + "/state")
    return links[:8]
