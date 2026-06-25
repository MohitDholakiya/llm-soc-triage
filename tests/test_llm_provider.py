"""Tests for LLM providers — focused on the stub + JSON extraction."""

import json

import pytest

from soc_triage.llm_provider import (
    LLMProvider,
    StubProvider,
    TriageSchemaError,
    _extract_json,
)


# ---- _extract_json -------------------------------------------------------


def test_extract_pure_json():
    raw = '{"summary": "hello world", "severity": "low"}'
    obj = _extract_json(raw)
    assert obj == {"summary": "hello world", "severity": "low"}


def test_extract_json_with_markdown_fences():
    raw = '```json\n{"summary": "hello", "severity": "low"}\n```'
    obj = _extract_json(raw)
    assert obj == {"summary": "hello", "severity": "low"}


def test_extract_json_with_prose_prefix():
    raw = 'Sure, here is the triage:\n{"summary": "hello", "severity": "low"}'
    obj = _extract_json(raw)
    assert obj == {"summary": "hello", "severity": "low"}


def test_extract_json_with_trailing_prose():
    raw = '{"summary": "hello", "severity": "low"}\nLet me know if you need more.'
    obj = _extract_json(raw)
    assert obj == {"summary": "hello", "severity": "low"}


def test_extract_json_no_brace():
    assert _extract_json("no json here") is None


def test_extract_json_empty():
    assert _extract_json("") is None


def test_extract_json_truncated():
    raw = '{"summary": "hello", "severity":'
    assert _extract_json(raw) is None


# ---- StubProvider --------------------------------------------------------


def test_stub_returns_valid_schema_for_ssh_brute_force():
    p = StubProvider()
    obj = p.complete(
        "ssh brute force: 47 failed logins for root from 203.0.113.42",
        "system prompt",
    )
    assert obj["severity"] == "high"
    assert "T1110" in obj.get("mitre_attack", [])
    assert obj["confidence"] >= 0.6


def test_stub_returns_valid_schema_for_sql_injection():
    p = StubProvider()
    obj = p.complete(
        "sql injection attempt against /api/login",
        "system prompt",
    )
    assert obj["severity"] == "critical"
    assert obj["confidence"] >= 0.6


def test_stub_returns_low_confidence_for_unknown():
    p = StubProvider()
    obj = p.complete(
        "some unusual alert we don't recognise",
        "system prompt",
    )
    assert obj["confidence"] < 0.6  # below threshold → flagged for human review


def test_stub_provider_name():
    assert StubProvider().name == "stub"


def test_complete_validates_against_schema():
    """The full complete() pipeline must raise TriageSchemaError on bad output."""
    p = StubProvider()
    # All three known patterns produce schema-valid output, so this is a smoke test
    for prompt in [
        "ssh brute force",
        "sql injection attempt",
        "port scan",
        "weird unknown alert",
    ]:
        obj = p.complete(prompt, "system")
        # round-trip to dict and re-validate
        from soc_triage.schema import validate_triage
        validate_triage(obj)  # should not raise


# ---- Mock provider that returns invalid output ----------------------------


class BadProvider(LLMProvider):
    """Provider that always returns a schema-invalid dict."""

    name = "bad"

    def _call_raw(self, prompt, system):
        return json.dumps({"summary": "short"})  # missing required fields


def test_bad_provider_raises_schema_error():
    p = BadProvider()
    with pytest.raises(TriageSchemaError):
        p.complete("anything", "system")


class ProseOnlyProvider(LLMProvider):
    name = "prose-only"

    def _call_raw(self, prompt, system):
        return "I think this is a low severity alert, no JSON for you."


def test_prose_only_provider_raises_schema_error():
    p = ProseOnlyProvider()
    with pytest.raises(TriageSchemaError):
        p.complete("anything", "system")