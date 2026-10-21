"""Versioned prompt snapshots selected once per graph turn."""

from hashlib import sha256
from pathlib import Path

PROMPT_DIR = Path(__file__).parent
PROFILES = ("chat", "alertmanager_rca", "falco_security")


def load_base_prompt() -> str:
    return (PROMPT_DIR / "base.txt").read_text(encoding="utf-8")


def build_prompt_selector(base: str, max_tool_calls: int):
    # Load once at graph construction. Each turn checkpoints the exact composed
    # prompt, so a resumed turn also retains its original text after deployment.
    prompts = {}
    for profile in PROFILES:
        instructions = (PROMPT_DIR / f"{profile}.txt").read_text(encoding="utf-8")
        text = (f"{base.strip()}\n\nActive response profile: {profile}\n\n"
                f"{instructions.strip()}\n\n"
                f"Tool budget for this turn: {max_tool_calls} tool calls. "
                "Stop earlier when sufficient evidence is available. If the budget "
                "is exhausted, answer using existing evidence and state uncertainty.")
        prompts[profile] = (text, "sha256:" + sha256(text.encode()).hexdigest())

    def select_prompt(state):
        # trigger_event survives chat follow-ups; only a NEW event selects an
        # event profile. Never route on free text in labels/logs/chat messages.
        profile = "chat"
        if state.get("event_action") in {"investigate", "resolved", "analysis"}:
            source = state.get("trigger_event", {}).get("source")
            profile = {"prometheus": "alertmanager_rca", "falco": "falco_security"}[source]
        text, version = prompts[profile]
        if state.get("event_action") == "analysis":
            from src.graph import tool_budget
            text += ("\n\nOperator-requested detailed analysis: collect fresh evidence and test alternative "
                     "hypotheses. Expand the report as needed; distinguish facts, hypotheses and missing checks. "
                     "Do not reuse an old RCA without revalidation. Remain read-only. "
                     f"The tool budget for this detailed turn is {tool_budget(state, max_tool_calls)} calls.")
            version = "sha256:" + sha256(text.encode()).hexdigest()
        return {"prompt_profile": profile, "prompt_version": version,
                "selected_prompt": text}

    return select_prompt
