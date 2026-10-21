"""Render RCA Markdown for ServiceNow journal and plain description fields."""

from html import escape
from html.parser import HTMLParser
import json
import re
import os
from urllib.parse import quote

from markdown_it import MarkdownIt
from src.evidence_links import safe_url


def _markdown(text):
    # Model/alert content is text, never trusted HTML or embedded media.
    md = MarkdownIt("commonmark", {"html": False}).disable("image")
    def link_open(tokens, idx, options, env):
        tokens[idx].attrSet("target", "_blank")
        tokens[idx].attrSet("rel", "noopener noreferrer")
        return md.renderer.renderToken(tokens, idx, options, env)
    md.renderer.rules["link_open"] = link_open
    return md.render(text)


class _PlainText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "li":
            self.parts.append("• ")
        elif tag == "br":
            self.parts.append("\n")
        elif tag == "a":
            self.links.append(dict(attrs).get("href", ""))

    def handle_endtag(self, tag):
        if tag == "a" and self.links:
            self.parts.append(f" ({self.links.pop()})")
        if tag in {"p", "li", "pre", "blockquote", "h1", "h2", "h3", "h4", "h5", "h6"}:
            self.parts.append("\n")

    def handle_data(self, data):
        self.parts.append(data)


def _plain(html):
    parser = _PlainText()
    parser.feed(html)
    return "\n".join(line.rstrip() for line in "".join(parser.parts).splitlines()).strip()


def format_note(row, *, html=True):
    event = json.loads(row["payload"])
    resolved = row["phase"] == "resolved"
    recovery = event.get("recovery", {})
    recovery_status = event.get("recovery_status", "pending")
    recurrence = event.get("recurrence", {})
    status = {"resolved": "RESOLVED — awaiting verification", "recovery_verified": "RECOVERY VERIFIED",
              "recovery_unverified": "RECOVERY NOT VERIFIED"}.get(row["phase"], row["phase"].upper())
    if recurrence.get("flapping") and row["phase"] == "firing":
        status += " — FLAPPING"
    if resolved and recovery_status != "pending":
        status = "RESOLVED — not independently verified"
    title = f"{str(event.get('event_type') or 'Event')[:160]} — {status}"
    fields = [("Source", event.get("source")), ("Cluster", event.get("cluster")),
              ("Namespace", event.get("namespace")), ("Pod", event.get("pod")),
              ("Node", event.get("node")), ("Severity", event.get("severity")),
              ("Started", event.get("starts_at") or event.get("event_time")),
              ("Resolved", event.get("ends_at") if resolved else None),
              ("Received", event.get("ingest_time"))]
    metadata = "".join(f"<p><strong>{key}:</strong> {escape(str(value)[:80])}</p>"
                       for key, value in fields if value and not str(value).startswith("0001-"))
    rca = (row.get("rca") or "").strip()
    if recovery:
        if recovery["status"] == "verified":
            rca = (f"Scoped recovery checks passed across {recovery['samples']} observations over "
                   f"{recovery['stable_seconds']} seconds. No matching alert activity was observed in that window; "
                   "the original alert expression returned no results and resource health was positive and fresh. "
                   "This verifies the checked scope, not every possible underlying cause. The incident is not automatically closed.")
        else:
            rca = "Recovery could not be verified within the configured check period. " + recovery["reason"] + " The incident remains open for review."
        rca += "\n\nChecked at: " + recovery["checked_at"]
    elif resolved:
        rca = "Alertmanager reported this alert as resolved. Recovery is not yet independently verified. The incident is not automatically closed."
        if recovery_status == "disabled":
            rca += " Automatic verification is disabled or not supported for this event."
        elif recovery_status == "superseded":
            rca += " A newer alarm episode superseded this notification."
    elif event.get("rca_reused_from"):
        rca = ("This alert has recurred. The recent analysis remains available in this incident "
               f"under event {event['rca_reused_from']}. A repeated full RCA was skipped; "
               "the previous cause has not been freshly revalidated.")
    elif not rca:
        rca = "No root cause analysis available."
    if recurrence.get("flapping"):
        rca = (f"Recurring alert: {recurrence['episodes']} alarm episodes within "
               f"{recurrence['window_seconds']//60} minutes.\n\n" + rca)
    marker = f"[AIOPS-EVENT:{row['event_id']}]"
    footer = f"<p>Thread: {escape(str(row.get('thread_id', 'unknown')))}</p><p>{escape(marker)}</p>"
    link_parts = []
    for link in event.get("evidence_links", [])[:8]:
        url = safe_url(link.get("url"))
        if url:
            observed = f" — observed {escape(str(link['collected_at']))}" if link.get("collected_at") else ""
            link_parts.append(f'<li><a href="{escape(url, quote=True)}" target="_blank" rel="noopener noreferrer">{escape(link["label"])}</a>{observed}</li>')

    actions = ""
    base = safe_url(os.getenv("AIOPS_AGENT_PUBLIC_URL", ""))
    if base and row.get("incident_id") and os.getenv("AIOPS_ACTIONS_USERS"):
        url = base.rstrip("/") + "/incidents/" + quote(str(row["incident_id"]), safe="") + "/actions"
        for label, suffix in (("Weitere Analyse", ""), ("Remediation planen", "#permissions")):
            actions += (f'<p><a href="{escape(url + suffix, quote=True)}" target="_blank" rel="noopener noreferrer" '
                        'style="display:inline-block;padding:10px 16px;background:#155eef;color:#fff;border-radius:4px;text-decoration:none">'
                        f'{label}</a></p>')

    def links_html():
        return "<h4>Evidence and investigation links</h4><ul>" + "".join(link_parts) + "</ul>" if link_parts else ""

    def render(body):
        output = f"<h3>{escape(title)}</h3>{metadata}{_markdown(body)}{links_html()}{actions}{footer}"
        if html:
            # Prevent untrusted text from opening/closing ServiceNow's code wrapper.
            output = output.replace("[", "&#91;").replace("]", "&#93;")
            # Keep the exact trusted event marker for journal reconciliation.
            output = output.replace(escape(marker).replace("[", "&#91;").replace("]", "&#93;"), escape(marker))
            return "[code]" + output + "[/code]"
        # Plain work notes must not accidentally contain active code wrappers either.
        return re.sub(r"\[(/?code)\]", r"[ \1 ]", _plain(output), flags=re.I)

    # Leave enough space for the analysis when Explore URLs are unusually long.
    while link_parts and len(render("")) > 4500:
        link_parts.pop()
    note = render(rca)
    if len(note) <= 8000:
        return note
    # Truncate source text, never serialized HTML/tags or the reconciliation marker.
    low, high = 0, len(rca)
    while low < high:
        middle = (low + high + 1) // 2
        if len(render(rca[:middle] + "\n\n[Analysis truncated; full result is available in the agent thread.]")) <= 8000:
            low = middle
        else:
            high = middle - 1
    return render(rca[:low] + "\n\n[Analysis truncated; full result is available in the agent thread.]")
