"""Tests for the TriageStore (SQLite + JSONL dual write)."""

import json
import sqlite3
from pathlib import Path

import pytest

from soc_triage.store import TriageRecord, TriageStore


@pytest.fixture
def store(tmp_path: Path) -> TriageStore:
    return TriageStore(
        db_path=tmp_path / "test.db",
        jsonl_path=tmp_path / "test.jsonl",
    )


def _basic_record(**overrides) -> TriageRecord:
    defaults = dict(
        alert_id="a1",
        ts="2026-06-24T10:00:00Z",
        source="wazuh",
        host="h1",
        user="alice",
        src_ip="1.2.3.4",
        event_type="ssh_brute_force",
        raw_severity="10",
        summary="SSH brute force",
        severity="high",
        next_steps=["Block IP"],
        confidence=0.9,
        mitre_attack=["T1110"],
        rationale="repeated fails",
        needs_human_review=False,
        triage_status="triaged",
        model_provider="stub",
        model_name="",
        latency_ms=150,
        error_message="",
    )
    defaults.update(overrides)
    return TriageRecord(**defaults)


# ---- insert + read ------------------------------------------------------


def test_insert_triage_returns_row_id(store: TriageStore):
    rid = store.insert_triage(_basic_record())
    assert rid >= 1
    assert store.count_triage() == 1


def test_insert_writes_jsonl(store: TriageStore):
    store.insert_triage(_basic_record(alert_id="a-xyz"))
    assert store.jsonl_path.exists()
    line = store.jsonl_path.read_text().strip()
    assert "a-xyz" in line


def test_fetch_all_returns_record(store: TriageStore):
    store.insert_triage(_basic_record(alert_id="a1"))
    store.insert_triage(_basic_record(alert_id="a2"))
    rows = store.fetch_all()
    assert len(rows) == 2
    # newest first
    assert rows[0]["alert_id"] == "a2"


def test_fetch_all_decodes_json_columns(store: TriageStore):
    store.insert_triage(_basic_record())
    rows = store.fetch_all()
    assert isinstance(rows[0]["next_steps"], list)
    assert rows[0]["next_steps"] == ["Block IP"]
    assert isinstance(rows[0]["mitre_attack"], list)


def test_fetch_all_decodes_needs_human_review_as_bool(store: TriageStore):
    store.insert_triage(_basic_record(needs_human_review=True))
    rows = store.fetch_all()
    assert rows[0]["needs_human_review"] is True


def test_count_triage_by_status(store: TriageStore):
    store.insert_triage(_basic_record(triage_status="triaged"))
    store.insert_triage(_basic_record(triage_status="error", error_message="x"))
    store.insert_triage(_basic_record(triage_status="skipped_kill_switch"))
    assert store.count_triage() == 3
    assert store.count_triage(status="triaged") == 1
    assert store.count_triage(status="error") == 1
    assert store.count_triage(status="skipped_kill_switch") == 1


# ---- feedback ------------------------------------------------------------


def test_insert_feedback(store: TriageStore):
    rid = store.insert_triage(_basic_record())
    fid = store.insert_feedback(rid, "up", comment="good", operator="alice")
    assert fid >= 1
    rows = store.feedback_for(rid)
    assert len(rows) == 1
    assert rows[0]["verdict"] == "up"


def test_insert_feedback_rejects_invalid_verdict(store: TriageStore):
    rid = store.insert_triage(_basic_record())
    with pytest.raises(ValueError):
        store.insert_feedback(rid, "maybe")


def test_feedback_stats(store: TriageStore):
    rid = store.insert_triage(_basic_record())
    store.insert_feedback(rid, "up")
    store.insert_feedback(rid, "up")
    store.insert_feedback(rid, "down")
    stats = store.feedback_stats()
    assert stats == {"up": 2, "down": 1}


# ---- prompt bank --------------------------------------------------------


def test_add_to_prompt_bank(store: TriageStore):
    nid = store.add_to_prompt_bank(
        alert_type="ssh_brute_force",
        prompt_text=json.dumps({"summary": "test"}),
    )
    assert nid >= 1
    entries = store.few_shot_prompts(alert_type="ssh_brute_force")
    assert len(entries) == 1


def test_few_shot_prompts_filtered(store: TriageStore):
    store.add_to_prompt_bank(alert_type="ssh_brute_force", prompt_text="x")
    store.add_to_prompt_bank(alert_type="sql_injection", prompt_text="y")
    ssh = store.few_shot_prompts(alert_type="ssh_brute_force")
    assert len(ssh) == 1
    assert ssh[0]["alert_type"] == "ssh_brute_force"


def test_few_shot_prompts_limit(store: TriageStore):
    for i in range(10):
        store.add_to_prompt_bank(alert_type="x", prompt_text=f"entry{i}")
    out = store.few_shot_prompts(limit=3)
    assert len(out) == 3


# ---- analytics ----------------------------------------------------------


def test_severity_counts(store: TriageStore):
    store.insert_triage(_basic_record(severity="high"))
    store.insert_triage(_basic_record(severity="high"))
    store.insert_triage(_basic_record(severity="low"))
    counts = store.severity_counts()
    assert counts == {"high": 2, "low": 1}


def test_mitre_counts(store: TriageStore):
    store.insert_triage(_basic_record(mitre_attack=["T1110", "T1078"]))
    store.insert_triage(_basic_record(mitre_attack=["T1110"]))
    counts = store.mitre_counts()
    assert counts == {"T1110": 2, "T1078": 1}


def test_confidence_histogram(store: TriageStore):
    store.insert_triage(_basic_record(confidence=0.55))
    store.insert_triage(_basic_record(confidence=0.85))
    store.insert_triage(_basic_record(confidence=0.92))
    hist = store.confidence_histogram(buckets=10)
    # bucket = floor(confidence * 10)
    counts = {row["bucket"]: row["n"] for row in hist}
    assert counts[5] == 1  # 0.55 → bucket 5
    assert counts[8] == 1  # 0.85 → bucket 8
    assert counts[9] == 1  # 0.92 → bucket 9


# ---- reopen persistence -------------------------------------------------


def test_store_survives_reopen(tmp_path: Path):
    db = tmp_path / "persist.db"
    s1 = TriageStore(db_path=db, jsonl_path=tmp_path / "x.jsonl")
    s1.insert_triage(_basic_record(alert_id="persist-1"))
    s2 = TriageStore(db_path=db, jsonl_path=tmp_path / "x.jsonl")
    assert s2.count_triage() == 1
    rows = s2.fetch_all()
    assert rows[0]["alert_id"] == "persist-1"


# ---- error records ------------------------------------------------------


def test_insert_error_record(store: TriageStore):
    store.insert_triage(_basic_record(
        triage_status="error",
        error_message="LLM unavailable",
        summary="",
        severity="",
        confidence=0.0,
        needs_human_review=True,
    ))
    rows = store.fetch_all()
    assert rows[0]["triage_status"] == "error"
    assert rows[0]["error_message"] == "LLM unavailable"