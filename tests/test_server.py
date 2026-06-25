"""Tests for the FastAPI server."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from soc_triage.alert_source import Alert, StubSource
from soc_triage.kill_switch import KillSwitch
from soc_triage.llm_provider import StubProvider
from soc_triage.server import create_app
from soc_triage.store import TriageStore


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    app = create_app(
        provider=StubProvider(),
        store=TriageStore(db_path=tmp_path / "test.db", jsonl_path=tmp_path / "test.jsonl"),
        kill_switch=KillSwitch(data_dir=tmp_path),
        alert_source=StubSource(),
    )
    return TestClient(app)


# ---- health / meta ------------------------------------------------------


def test_health(client: TestClient):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body
    assert "provider" in body
    assert "kill_switch_armed" in body


# ---- kill switch --------------------------------------------------------


def test_get_kill_default_disarmed(client: TestClient):
    r = client.get("/kill")
    assert r.status_code == 200
    body = r.json()
    assert body["armed"] is False
    assert isinstance(body["history"], list)


def test_post_kill_arms(client: TestClient):
    r = client.post("/kill", json={"reason": "operator arm", "operator": "alice"})
    assert r.status_code == 200
    assert r.json()["armed"] is True
    # Confirm via GET
    r = client.get("/kill")
    assert r.json()["armed"] is True


def test_delete_kill_disarms(client: TestClient):
    client.post("/kill", json={"reason": "test"})
    r = client.delete("/kill")
    assert r.status_code == 200
    assert r.json()["armed"] is False


def test_kill_arm_history_recorded(client: TestClient):
    client.post("/kill", json={"reason": "test arm", "operator": "bob"})
    history = client.get("/kill").json()["history"]
    assert any(h["action"] == "armed" and h["operator"] == "bob" for h in history)


# ---- triage -------------------------------------------------------------


def test_triage_one_alert(client: TestClient):
    r = client.post("/triage", json={
        "alert": {
            "alert_id": "test-1",
            "host": "web-prod-01",
            "src_ip": "203.0.113.42",
            "event_type": "ssh_brute_force",
            "severity": "10",
            "message": "47 SSH failed logins from 203.0.113.42",
        }
    })
    assert r.status_code == 200
    body = r.json()
    assert body["id"] >= 1
    assert body["record"]["severity"] == "high"
    assert "markdown" in body
    assert "🚨" in body["markdown"] or "SOC Triage" in body["markdown"]


def test_triage_batch(client: TestClient):
    r = client.post("/triage/batch", json={
        "alerts": [
            {"alert_id": "b1", "event_type": "ssh_brute_force", "src_ip": "1.1.1.1", "message": "ssh brute"},
            {"alert_id": "b2", "event_type": "sql_injection", "src_ip": "2.2.2.2", "message": "sql injection"},
        ]
    })
    assert r.status_code == 200
    body = r.json()
    assert len(body["ids"]) == 2
    assert len(body["records"]) == 2


def test_triage_validation_missing_alert_id(client: TestClient):
    r = client.post("/triage", json={"alert": {"message": "no id"}})
    assert r.status_code == 422


def test_triage_validation_bad_severity_in_prompt_bank(client: TestClient):
    """The /prompt-bank POST validates severity enum."""
    r = client.post("/prompt-bank", json={
        "alert_type": "x",
        "summary": "test summary",
        "severity": "extreme",  # not in enum
        "next_steps": ["step"],
        "confidence": 0.5,
    })
    assert r.status_code == 422


# ---- feedback -----------------------------------------------------------


def test_feedback_up_creates_prompt_bank_entry(client: TestClient):
    # First triage one alert
    r = client.post("/triage", json={
        "alert": {"alert_id": "fb-1", "event_type": "ssh_brute_force", "message": "x"}
    })
    triage_id = r.json()["id"]
    # Now record feedback
    r = client.post(f"/triages/{triage_id}/feedback", json={"verdict": "up", "operator": "alice"})
    assert r.status_code == 200
    # Prompt bank should now have an entry
    r = client.get("/prompt-bank", params={"alert_type": "ssh_brute_force"})
    entries = r.json()["entries"]
    assert len(entries) == 1


def test_feedback_down_does_not_create_prompt_bank_entry(client: TestClient):
    r = client.post("/triage", json={
        "alert": {"alert_id": "fb-2", "event_type": "ssh_brute_force", "message": "x"}
    })
    triage_id = r.json()["id"]
    client.post(f"/triages/{triage_id}/feedback", json={"verdict": "down"})
    r = client.get("/prompt-bank", params={"alert_type": "ssh_brute_force"})
    assert r.json()["entries"] == []


def test_feedback_rejects_invalid_verdict(client: TestClient):
    r = client.post("/triage", json={"alert": {"alert_id": "fb-3"}})
    triage_id = r.json()["id"]
    r = client.post(f"/triages/{triage_id}/feedback", json={"verdict": "maybe"})
    assert r.status_code == 422


# ---- renders ------------------------------------------------------------


def test_render_markdown(client: TestClient):
    r = client.post("/triage", json={
        "alert": {"alert_id": "r-1", "event_type": "ssh_brute_force", "message": "ssh brute"}
    })
    tid = r.json()["id"]
    r = client.get(f"/triages/{tid}/render/markdown")
    assert r.status_code == 200
    assert "markdown" in r.json()["body"].lower() or "triage" in r.json()["body"].lower()


def test_render_slack(client: TestClient):
    r = client.post("/triage", json={
        "alert": {"alert_id": "r-2", "event_type": "ssh_brute_force", "message": "ssh brute"}
    })
    tid = r.json()["id"]
    r = client.get(f"/triages/{tid}/render/slack")
    assert r.status_code == 200


def test_render_teams(client: TestClient):
    r = client.post("/triage", json={
        "alert": {"alert_id": "r-3", "event_type": "ssh_brute_force", "message": "ssh brute"}
    })
    tid = r.json()["id"]
    r = client.get(f"/triages/{tid}/render/teams")
    assert r.status_code == 200


def test_render_unknown_format_400(client: TestClient):
    r = client.post("/triage", json={"alert": {"alert_id": "r-4"}})
    tid = r.json()["id"]
    r = client.get(f"/triages/{tid}/render/xml")
    assert r.status_code == 400


# ---- kill switch integration -------------------------------------------


def test_triage_while_killed_returns_skip_record(client: TestClient):
    client.post("/kill", json={"reason": "test"})
    r = client.post("/triage", json={
        "alert": {"alert_id": "killed-1", "event_type": "ssh_brute_force", "message": "ssh brute"}
    })
    body = r.json()
    assert body["record"]["triage_status"] == "skipped_kill_switch"


def test_stats_endpoint(client: TestClient):
    client.post("/triage", json={"alert": {"alert_id": "s-1", "event_type": "ssh_brute_force", "message": "x"}})
    client.post("/triage", json={"alert": {"alert_id": "s-2", "event_type": "sql_injection", "message": "y"}})
    r = client.get("/stats")
    body = r.json()
    assert body["total_triaged"] == 2
    assert body["total_errors"] == 0
    assert "severity_counts" in body
    assert "mitre_counts" in body
    assert body["model_provider"] == "stub"


def test_get_triage_by_id(client: TestClient):
    r = client.post("/triage", json={"alert": {"alert_id": "by-id-1"}})
    tid = r.json()["id"]
    r = client.get(f"/triage/{tid}")
    assert r.status_code == 200
    assert r.json()["alert_id"] == "by-id-1"


def test_get_triage_by_id_404(client: TestClient):
    r = client.get("/triage/9999")
    assert r.status_code == 404


def test_list_triages(client: TestClient):
    client.post("/triage", json={"alert": {"alert_id": "l-1"}})
    client.post("/triage", json={"alert": {"alert_id": "l-2"}})
    r = client.get("/triages")
    body = r.json()
    assert body["count"] == 2
    assert len(body["records"]) == 2


def test_fetch_alerts_endpoint(client: TestClient):
    r = client.get("/alerts/fetch")
    assert r.status_code == 200
    body = r.json()
    assert "alerts" in body
    assert isinstance(body["alerts"], list)


# ---- prompt bank direct POST -------------------------------------------


def test_prompt_bank_post(client: TestClient):
    r = client.post("/prompt-bank", json={
        "alert_type": "ssh_brute_force",
        "summary": "Stored few-shot example",
        "severity": "high",
        "next_steps": ["Step 1", "Step 2"],
        "confidence": 0.9,
        "mitre_attack": ["T1110"],
        "rationale": "Example rationale",
    })
    assert r.status_code == 200
    assert r.json()["prompt_bank_id"] >= 1