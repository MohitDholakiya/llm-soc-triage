"""Triage orchestration — the read-only pipeline.

Pipeline per alert:
    1. Check kill switch — if armed, record a passthrough entry and stop.
    2. Build a structured prompt from the alert + few-shot examples.
    3. Call the LLM provider.
    4. Validate the LLM response against TRIAGE_SCHEMA (the brief:
       "never trust free-form LLM output into a SOC UI").
    5. Apply the confidence threshold: if model confidence < 0.6, flag
       for human review.
    6. Persist the triage record (SQLite + JSONL).
    7. Return the SQLite row id.

The orchestrator never:
  - Modifies the source alert
  - Calls external systems (other than the configured LLM)
  - Acknowledges or dismisses alerts in the SIEM
  - Takes any "action" beyond writing a triage note to its own store
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict

from soc_triage.alert_source import Alert
from soc_triage.kill_switch import KillSwitch
from soc_triage.llm_provider import LLMError, LLMProvider, LLMUnavailable, TriageSchemaError
from soc_triage.schema import (
    DEFAULT_LOW_CONFIDENCE_THRESHOLD,
    is_low_confidence,
)
from soc_triage.store import TriageRecord, TriageStore


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------


SYSTEM_PROMPT = """You are a SOC triage assistant. Your job is to read an alert and \
produce a STRICT JSON object describing it. You NEVER take any action on the alert — \
you only classify and recommend. You NEVER invent facts not present in the alert.

Output format (strict JSON, no prose, no markdown fences):
{
  "summary": "<1-2 sentence plain-English summary>",
  "severity": "low" | "medium" | "high" | "critical",
  "next_steps": ["<action 1>", "<action 2>", ...],
  "confidence": <0.0 to 1.0>,
  "mitre_attack": ["Txxxx", ...],
  "rationale": "<why this severity>"
}

Rules:
- severity must be one of low, medium, high, critical
- next_steps must be 1-5 concrete actions an analyst should take
- confidence reflects how sure you are; if unsure, set it below 0.6
- mitre_attack should be technique IDs (Txxxx) — omit if none apply
- if you don't have enough information, set confidence < 0.6 and recommend human review"""


def build_user_prompt(alert: Alert, few_shot: list[dict] | None = None) -> str:
    """Build the user-message prompt from an Alert + optional few-shot examples.

    Each few_shot entry is a row from the prompt_bank table — it has
    keys `alert_type` and `prompt_text` (a JSON string). We parse
    `prompt_text` back to a dict before rendering.
    """
    parts: list[str] = []
    parts.append("Triage this SOC alert:")
    parts.append("")
    parts.append("```json")
    parts.append(json.dumps(asdict(alert), indent=2, ensure_ascii=False))
    parts.append("```")
    if few_shot:
        parts.append("")
        parts.append("Examples of good triage for similar alert types:")
        for ex in few_shot:
            # Support both formats:
            #   1. Old/hand-built: dict with keys summary, severity, next_steps, etc.
            #   2. Prompt-bank row: dict with alert_type + prompt_text (JSON string)
            if "summary" in ex or "next_steps" in ex:
                ex_parsed = ex  # already a parsed dict
            else:
                prompt_text = ex.get("prompt_text", "")
                try:
                    ex_parsed = json.loads(prompt_text) if isinstance(prompt_text, str) else prompt_text
                except json.JSONDecodeError:
                    continue
            parts.append("")
            parts.append(f"Alert type: {ex.get('alert_type', '?')}")
            parts.append("Triage:")
            parts.append("```json")
            parts.append(json.dumps({
                "summary": ex_parsed.get("summary", ""),
                "severity": ex_parsed.get("severity", ""),
                "next_steps": ex_parsed.get("next_steps", []),
                "confidence": ex_parsed.get("confidence", 0.5),
                "mitre_attack": ex_parsed.get("mitre_attack", []),
                "rationale": ex_parsed.get("rationale", ""),
            }, indent=2, ensure_ascii=False))
            parts.append("```")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class TriageOrchestrator:
    """Read-only triage pipeline."""

    def __init__(
        self,
        provider: LLMProvider,
        store: TriageStore,
        kill_switch: KillSwitch,
        low_confidence_threshold: float = DEFAULT_LOW_CONFIDENCE_THRESHOLD,
    ) -> None:
        self.provider = provider
        self.store = store
        self.kill_switch = kill_switch
        self.low_confidence_threshold = low_confidence_threshold

    def triage(self, alert: Alert, model_name: str = "") -> int:
        """Run one alert through the pipeline. Returns the SQLite row id."""
        # 1. Kill-switch check (every step must check — never trust
        #    an early "I checked it once" — the operator may arm
        #    mid-batch)
        if self.kill_switch.trip_if_armed():
            return self._record_skip(alert, model_name)

        # 2. Build prompt with few-shot examples
        few_shot = self.store.few_shot_prompts(alert_type=alert.event_type, limit=3)
        prompt = build_user_prompt(alert, few_shot if few_shot else None)

        # 3. Call LLM
        t0 = time.perf_counter()
        try:
            parsed = self.provider.complete(prompt, SYSTEM_PROMPT)
        except (TriageSchemaError, LLMUnavailable, LLMError) as e:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            return self._record_error(alert, e, model_name, latency_ms)
        except Exception as e:
            # Catch-all for unexpected provider errors (network drops, library
            # bugs, etc.). The triage layer must never raise uncaught —
            # the brief is explicit: the assistant is fail-safe.
            latency_ms = int((time.perf_counter() - t0) * 1000)
            return self._record_error(alert, e, model_name, latency_ms)

        latency_ms = int((time.perf_counter() - t0) * 1000)

        # 4. Build the record — schema was already validated inside
        #    provider.complete(). We re-read defensively in case of bugs.
        confidence = float(parsed.get("confidence", 0.0))
        return self.store.insert_triage(TriageRecord(
            alert_id=alert.alert_id,
            ts=alert.timestamp,
            source=alert.source,
            host=alert.host,
            user=alert.user,
            src_ip=alert.src_ip,
            event_type=alert.event_type,
            raw_severity=alert.severity,
            summary=str(parsed.get("summary", "")),
            severity=str(parsed.get("severity", "")),
            next_steps=list(parsed.get("next_steps", [])),
            confidence=confidence,
            mitre_attack=list(parsed.get("mitre_attack", [])),
            rationale=str(parsed.get("rationale", "")),
            needs_human_review=is_low_confidence(confidence, self.low_confidence_threshold),
            triage_status="triaged",
            model_provider=self.provider.name,
            model_name=model_name,
            latency_ms=latency_ms,
        ))

    def triage_batch(self, alerts: list[Alert], model_name: str = "") -> list[int]:
        """Triage a batch. Returns list of SQLite row ids.

        Kill-switch is checked once per alert — if the operator arms
        the switch mid-batch, subsequent alerts short-circuit to
        passthrough records.
        """
        return [self.triage(a, model_name=model_name) for a in alerts]

    # ---- helpers ---------------------------------------------------------

    def _record_skip(self, alert: Alert, model_name: str) -> int:
        return self.store.insert_triage(TriageRecord(
            alert_id=alert.alert_id,
            ts=alert.timestamp,
            source=alert.source,
            host=alert.host,
            user=alert.user,
            src_ip=alert.src_ip,
            event_type=alert.event_type,
            raw_severity=alert.severity,
            triage_status="skipped_kill_switch",
            model_provider=self.provider.name,
            model_name=model_name,
        ))

    def _record_error(self, alert: Alert, err: Exception, model_name: str, latency_ms: int) -> int:
        return self.store.insert_triage(TriageRecord(
            alert_id=alert.alert_id,
            ts=alert.timestamp,
            source=alert.source,
            host=alert.host,
            user=alert.user,
            src_ip=alert.src_ip,
            event_type=alert.event_type,
            raw_severity=alert.severity,
            triage_status="error",
            model_provider=self.provider.name,
            model_name=model_name,
            latency_ms=latency_ms,
            error_message=f"{type(err).__name__}: {err}",
        ))