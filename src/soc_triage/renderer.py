"""Markdown / Slack / Teams rendering of triage records.

Uses Jinja2 templates (bundled in the package). The brief asks for
"Jinja2 to render the suggestion into a Slack / Teams message" — we
ship three formats: full Markdown (for the dashboard), Slack-friendly
(short with markdown), Teams-friendly (similar, fewer features).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"], disabled_extensions=("md", "txt")),
        keep_trailing_newline=True,
    )


def render_markdown(record: dict[str, Any]) -> str:
    """Render a triage record as Markdown (for the dashboard / GitHub)."""
    return _env().get_template("triage.md.j2").render(**_view(record))


def render_slack(record: dict[str, Any]) -> str:
    """Render a triage record as Slack mrkdwn.

    Slack's mrkdwn is a subset of Markdown — we use *bold* and `code`
    rather than **bold** and ```code blocks```.
    """
    return _env().get_template("triage.slack.j2").render(**_view(record))


def render_teams(record: dict[str, Any]) -> str:
    """Render a triage record as a Teams Adaptive Card text payload."""
    return _env().get_template("triage.teams.j2").render(**_view(record))


# ---------------------------------------------------------------------------
# View helper
# ---------------------------------------------------------------------------


def _view(record: dict[str, Any]) -> dict[str, Any]:
    """Build the template context from a triage record dict."""
    return {
        "alert_id": record.get("alert_id", ""),
        "ts": record.get("ts", ""),
        "host": record.get("host", ""),
        "user": record.get("user", ""),
        "src_ip": record.get("src_ip", ""),
        "event_type": record.get("event_type", ""),
        "severity": record.get("severity", "") or "unknown",
        "summary": record.get("summary", ""),
        "next_steps": record.get("next_steps", []),
        "confidence_pct": int(round((record.get("confidence", 0.0) or 0.0) * 100)),
        "mitre_attack": record.get("mitre_attack", []),
        "rationale": record.get("rationale", ""),
        "needs_human_review": bool(record.get("needs_human_review")),
        "triage_status": record.get("triage_status", ""),
        "model_provider": record.get("model_provider", ""),
        "model_name": record.get("model_name", ""),
        "latency_ms": record.get("latency_ms", 0),
        "rendered_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }