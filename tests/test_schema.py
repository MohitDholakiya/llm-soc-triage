"""Tests for the strict JSON schema."""

import pytest

from soc_triage.schema import (
    TRIAGE_SCHEMA,
    is_low_confidence,
    validate_triage,
)


def test_validate_minimal_valid():
    obj = {
        "summary": "SSH brute force from a single source IP.",
        "severity": "high",
        "next_steps": ["Block the source IP", "Check for successful logins"],
        "confidence": 0.9,
    }
    validate_triage(obj)


def test_validate_full_valid():
    obj = {
        "summary": "SQL injection attempts blocked by WAF.",
        "severity": "critical",
        "next_steps": ["Confirm WAF rule fired", "Review endpoint", "Block IP"],
        "confidence": 0.95,
        "mitre_attack": ["T1190"],
        "rationale": "SQLi patterns in HTTP request payloads.",
    }
    validate_triage(obj)


def test_validate_rejects_short_summary():
    with pytest.raises(Exception):
        validate_triage({
            "summary": "short",  # < 10 chars
            "severity": "low",
            "next_steps": ["step"],
            "confidence": 0.5,
        })


def test_validate_rejects_bad_severity():
    with pytest.raises(Exception):
        validate_triage({
            "summary": "this is a valid length summary",
            "severity": "extreme",  # not in enum
            "next_steps": ["step"],
            "confidence": 0.5,
        })


def test_validate_rejects_empty_next_steps():
    with pytest.raises(Exception):
        validate_triage({
            "summary": "this is a valid length summary",
            "severity": "low",
            "next_steps": [],  # minItems 1
            "confidence": 0.5,
        })


def test_validate_rejects_too_many_next_steps():
    with pytest.raises(Exception):
        validate_triage({
            "summary": "this is a valid length summary",
            "severity": "low",
            "next_steps": [f"step {i}" for i in range(10)],  # maxItems 5
            "confidence": 0.5,
        })


def test_validate_rejects_out_of_range_confidence():
    with pytest.raises(Exception):
        validate_triage({
            "summary": "this is a valid length summary",
            "severity": "low",
            "next_steps": ["step"],
            "confidence": 1.5,  # > 1.0
        })


def test_validate_rejects_negative_confidence():
    with pytest.raises(Exception):
        validate_triage({
            "summary": "this is a valid length summary",
            "severity": "low",
            "next_steps": ["step"],
            "confidence": -0.1,  # < 0.0
        })


def test_validate_rejects_bad_mitre_format():
    with pytest.raises(Exception):
        validate_triage({
            "summary": "this is a valid length summary",
            "severity": "low",
            "next_steps": ["step"],
            "confidence": 0.5,
            "mitre_attack": ["INVALID"],  # doesn't match ^T\d{4}$
        })


# ---- is_low_confidence ---------------------------------------------------


def test_low_confidence_below_threshold():
    assert is_low_confidence(0.59) is True


def test_low_confidence_at_threshold():
    assert is_low_confidence(0.60) is False


def test_low_confidence_high():
    assert is_low_confidence(0.95) is False


def test_low_confidence_custom_threshold():
    assert is_low_confidence(0.5, threshold=0.6) is True
    assert is_low_confidence(0.7, threshold=0.6) is False