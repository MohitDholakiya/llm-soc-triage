"""FastAPI server for the SOC triage assistant.

Endpoints:
    GET  /health           — liveness check
    GET  /stats            — store stats (counts, severity, MITRE, confidence histogram)
    GET  /kill             — read kill-switch state + audit log
    POST /kill             — arm the switch (with optional reason + operator)
    DELETE /kill           — disarm the switch
    POST /triage           — process a single alert (JSON body)
    POST /triage/batch     — process a batch (JSON array)
    GET  /triage/{id}      — fetch one triage record
    GET  /triages          — list recent triage records
    POST /triages/{id}/feedback — record analyst thumbs up/down
    GET  /prompt-bank      — list few-shot examples
    POST /prompt-bank      — add a few-shot example from a triage_id

The server is read-only against any SIEM — it never modifies alerts.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from soc_triage.alert_source import Alert, AlertSource, StubSource
from soc_triage.kill_switch import KillSwitch, install_signal_handler
from soc_triage.llm_provider import LLMProvider, provider_from_env
from soc_triage.renderer import render_markdown, render_slack, render_teams
from soc_triage.store import TriageStore
from soc_triage.triage import TriageOrchestrator


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class AlertIn(BaseModel):
    alert_id: str = Field(..., min_length=1, max_length=200)
    timestamp: str = Field(default_factory=lambda: _now_iso())
    source: str = ""
    host: str = ""
    user: str = ""
    src_ip: str = ""
    event_type: str = ""
    severity: str = ""
    message: str = ""
    raw: dict = Field(default_factory=dict)


class TriageRequest(BaseModel):
    alert: AlertIn
    model_name: str = ""


class BatchTriageRequest(BaseModel):
    alerts: list[AlertIn]
    model_name: str = ""


class KillRequest(BaseModel):
    reason: str = ""
    operator: str = ""


class FeedbackRequest(BaseModel):
    verdict: str = Field(..., pattern=r"^(up|down)$")
    comment: str = ""
    operator: str = ""


class PromptBankEntry(BaseModel):
    alert_type: str = Field(..., min_length=1, max_length=100)
    summary: str = Field(..., min_length=1)
    severity: str = Field(..., pattern=r"^(low|medium|high|critical)$")
    next_steps: list[str] = Field(..., min_length=1)
    confidence: float = Field(..., ge=0.0, le=1.0)
    mitre_attack: list[str] = Field(default_factory=list)
    rationale: str = ""
    source_triage_id: int | None = None


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_app(
    provider: Optional[LLMProvider] = None,
    store: Optional[TriageStore] = None,
    kill_switch: Optional[KillSwitch] = None,
    alert_source: Optional[AlertSource] = None,
) -> FastAPI:
    """Build a FastAPI app wired to the configured dependencies."""
    data_dir = Path(os.environ.get("SOC_TRIAGE_DATA", "./data"))
    data_dir.mkdir(parents=True, exist_ok=True)

    if provider is None:
        provider = provider_from_env()
    if store is None:
        store = TriageStore(
            db_path=data_dir / "triage.db",
            jsonl_path=data_dir / "triage.jsonl",
        )
    if kill_switch is None:
        kill_switch = KillSwitch(data_dir=data_dir)
    if alert_source is None:
        alert_source = StubSource()

    orchestrator = TriageOrchestrator(
        provider=provider,
        store=store,
        kill_switch=kill_switch,
    )

    # Install signal handlers so Ctrl-C / SIGTERM arms the switch
    install_signal_handler(kill_switch)

    app = FastAPI(
        title="SOC Triage Assistant",
        description="Read-only LLM-powered SOC triage with a kill switch.",
        version="0.1.0",
    )
    app.state.provider = provider
    app.state.store = store
    app.state.kill_switch = kill_switch
    app.state.alert_source = alert_source
    app.state.orchestrator = orchestrator

    # ---- routes ---------------------------------------------------------

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "version": app.version,
            "provider": provider.name,
            "kill_switch_armed": kill_switch.is_armed(),
        }

    @app.get("/stats")
    def stats():
        return {
            "total_triaged": store.count_triage(status="triaged"),
            "total_errors": store.count_triage(status="error"),
            "total_skipped_kill_switch": store.count_triage(status="skipped_kill_switch"),
            "needs_human_review": store.count_triage(),  # all that need review
            "severity_counts": store.severity_counts(),
            "mitre_counts": store.mitre_counts(),
            "feedback_stats": store.feedback_stats(),
            "confidence_histogram": store.confidence_histogram(),
            "kill_switch_armed": kill_switch.is_armed(),
            "model_provider": provider.name,
        }

    # ---- kill switch ---------------------------------------------------

    @app.get("/kill")
    def get_kill():
        return {
            "armed": kill_switch.is_armed(),
            "history": kill_switch.history(),
        }

    @app.post("/kill")
    def arm_kill(req: KillRequest):
        kill_switch.arm(source="rest", reason=req.reason, operator=req.operator)
        return {"armed": True, "armed_at": _now_iso()}

    @app.delete("/kill")
    def disarm_kill(req: KillRequest = KillRequest()):
        kill_switch.disarm(source="rest", reason=req.reason, operator=req.operator)
        return {"armed": False}

    # ---- triage --------------------------------------------------------

    @app.post("/triage")
    def triage_one(req: TriageRequest):
        alert = Alert(
            alert_id=req.alert.alert_id,
            timestamp=req.alert.timestamp,
            source=req.alert.source,
            host=req.alert.host,
            user=req.alert.user,
            src_ip=req.alert.src_ip,
            event_type=req.alert.event_type,
            severity=req.alert.severity,
            message=req.alert.message,
            raw=req.alert.raw,
        )
        row_id = orchestrator.triage(alert, model_name=req.model_name)
        record = store.fetch_one(row_id)
        return {
            "id": row_id,
            "record": record,
            "markdown": render_markdown(record) if record else "",
        }

    @app.post("/triage/batch")
    def triage_batch(req: BatchTriageRequest):
        alerts = [
            Alert(
                alert_id=a.alert_id,
                timestamp=a.timestamp,
                source=a.source,
                host=a.host,
                user=a.user,
                src_ip=a.src_ip,
                event_type=a.event_type,
                severity=a.severity,
                message=a.message,
                raw=a.raw,
            )
            for a in req.alerts
        ]
        ids = orchestrator.triage_batch(alerts, model_name=req.model_name)
        records = [r for r in (store.fetch_one(i) for i in ids) if r is not None]
        return {
            "ids": ids,
            "records": records,
        }

    @app.get("/triage/{triage_id}")
    def get_triage(triage_id: int):
        rec = store.fetch_one(triage_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="triage record not found")
        return rec

    @app.get("/triages")
    def list_triages(limit: int = 50):
        rows = store.fetch_all(limit=limit)
        return {"records": rows, "count": len(rows)}

    @app.get("/triages/{triage_id}/render/{fmt}")
    def render_triage(triage_id: int, fmt: str):
        rec = store.fetch_one(triage_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="triage record not found")
        if fmt == "markdown":
            return {"format": "markdown", "body": render_markdown(rec)}
        if fmt == "slack":
            return {"format": "slack", "body": render_slack(rec)}
        if fmt == "teams":
            return {"format": "teams", "body": render_teams(rec)}
        raise HTTPException(status_code=400, detail=f"unknown format: {fmt}")

    # ---- feedback ------------------------------------------------------

    @app.post("/triages/{triage_id}/feedback")
    def post_feedback(triage_id: int, req: FeedbackRequest):
        rec = store.fetch_one(triage_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="triage record not found")
        fid = store.insert_feedback(
            triage_id=triage_id,
            verdict=req.verdict,
            comment=req.comment,
            operator=req.operator,
        )
        # If the analyst marked it good, save it as a few-shot example
        if req.verdict == "up":
            store.add_to_prompt_bank(
                alert_type=rec.get("event_type", ""),
                prompt_text=json.dumps({
                    "summary": rec.get("summary", ""),
                    "severity": rec.get("severity", ""),
                    "next_steps": rec.get("next_steps", []),
                    "confidence": rec.get("confidence", 0.5),
                    "mitre_attack": rec.get("mitre_attack", []),
                    "rationale": rec.get("rationale", ""),
                }),
                source_triage_id=triage_id,
            )
        return {"feedback_id": fid}

    # ---- prompt bank ---------------------------------------------------

    @app.get("/prompt-bank")
    def get_prompt_bank(alert_type: Optional[str] = None, limit: int = 20):
        return {"entries": store.few_shot_prompts(alert_type=alert_type, limit=limit)}

    @app.post("/prompt-bank")
    def post_prompt_bank(entry: PromptBankEntry):
        nid = store.add_to_prompt_bank(
            alert_type=entry.alert_type,
            prompt_text=json.dumps({
                "summary": entry.summary,
                "severity": entry.severity,
                "next_steps": entry.next_steps,
                "confidence": entry.confidence,
                "mitre_attack": entry.mitre_attack,
                "rationale": entry.rationale,
            }),
            source_triage_id=entry.source_triage_id,
        )
        return {"prompt_bank_id": nid}

    # ---- alert source (demo: pull from configured source) ---------------

    @app.get("/alerts/fetch")
    def fetch_alerts(limit: int = 10):
        """Fetch alerts from the configured source (demo helper)."""
        return {"alerts": [a.to_dict() for a in alert_source.fetch(limit=limit)]}

    return app


# Module-level app for `uvicorn soc_triage.server:app`
app = create_app()