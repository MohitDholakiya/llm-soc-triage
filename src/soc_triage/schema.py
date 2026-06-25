"""Strict JSON schemas for the LLM triage contract.

The brief is explicit: "Wrap the LLM behind a strict JSON schema:
{summary, severity, next_steps[]}. Validate it on the way out — never
trust free-form LLM output into a SOC UI."

We use jsonschema for validation. The LLM provider MUST return a dict
matching this schema (or raise TriageSchemaError). The triage layer
also adds a `confidence` field downstream — the model can suggest
confidence, but we don't trust it without a sanity check.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Outbound schema — what the LLM is asked to produce
# ---------------------------------------------------------------------------
# `summary`       — 1-2 sentence plain-English summary of the alert
# `severity`      — one of "low", "medium", "high", "critical"
# `next_steps`    — array of 1-5 concrete actions an analyst should take
# `confidence`    — model self-rated confidence in [0.0, 1.0]
# `mitre_attack`  — optional array of MITRE ATT&CK technique IDs (Txxxx)
# `rationale`     — short explanation of why the LLM chose this severity

TRIAGE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SocTriageOutput",
    "type": "object",
    "required": ["summary", "severity", "next_steps", "confidence"],
    "additionalProperties": True,
    "properties": {
        "summary": {
            "type": "string",
            "minLength": 10,
            "maxLength": 1000,
            "description": "1-2 sentence plain-English summary of the alert.",
        },
        "severity": {
            "type": "string",
            "enum": ["low", "medium", "high", "critical"],
        },
        "next_steps": {
            "type": "array",
            "minItems": 1,
            "maxItems": 5,
            "items": {
                "type": "string",
                "minLength": 5,
                "maxLength": 500,
            },
            "description": "Concrete actions an analyst should take.",
        },
        "confidence": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
            "description": "Model self-rated confidence in this triage.",
        },
        "mitre_attack": {
            "type": "array",
            "items": {
                "type": "string",
                "pattern": r"^T\d{4}$",
            },
            "description": "MITRE ATT&CK technique IDs (Txxxx).",
        },
        "rationale": {
            "type": "string",
            "maxLength": 1000,
            "description": "Why the model chose this severity.",
        },
    },
}


# Confidence threshold below which a triage is flagged for human review.
# The brief: "if model confidence < 0.6, mark the alert for human review."
DEFAULT_LOW_CONFIDENCE_THRESHOLD = 0.6


def validate_triage(obj: dict[str, Any]) -> None:
    """Raise jsonschema.ValidationError if `obj` doesn't match TRIAGE_SCHEMA.

    Import is deferred so the module loads even without jsonschema
    installed (it's a runtime dependency).
    """
    import jsonschema  # noqa: WPS433 — intentional deferred import

    jsonschema.validate(obj, TRIAGE_SCHEMA)


def is_low_confidence(confidence: float, threshold: float = DEFAULT_LOW_CONFIDENCE_THRESHOLD) -> bool:
    """True if the model confidence is below the threshold.

    Triages below this mark get a `needs_human_review` flag on the record.
    """
    return confidence < threshold