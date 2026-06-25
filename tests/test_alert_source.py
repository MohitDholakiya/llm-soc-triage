"""Tests for alert source adapters."""

import json
from pathlib import Path

import pytest

from soc_triage.alert_source import (
    Alert,
    JsonlFileSource,
    StubSource,
    SyslogSource,
    _syslog_ts_to_iso,
)


def test_stub_source_returns_hand_crafted_alerts():
    src = StubSource()
    alerts = src.fetch(limit=10)
    assert len(alerts) >= 1
    assert all(isinstance(a, Alert) for a in alerts)


def test_stub_source_includes_ssh_brute_force():
    src = StubSource()
    alerts = src.fetch(limit=10)
    ssh_alerts = [a for a in alerts if "ssh" in a.event_type]
    assert ssh_alerts
    assert ssh_alerts[0].src_ip != ""


# ---- JsonlFileSource -----------------------------------------------------


def test_jsonl_source_loads_sample_file(tmp_path: Path):
    f = tmp_path / "alerts.jsonl"
    f.write_text('{"alert_id": "a1", "timestamp": "2026-06-24T10:00:00Z", "source": "test", "host": "h1"}\n'
                 '{"alert_id": "a2", "timestamp": "2026-06-24T11:00:00Z", "source": "test", "host": "h2"}\n')
    src = JsonlFileSource(f)
    alerts = src.fetch()
    assert len(alerts) == 2
    assert alerts[0].alert_id == "a1"
    assert alerts[0].host == "h1"


def test_jsonl_source_handles_normalised_payload(tmp_path: Path):
    f = tmp_path / "alerts.jsonl"
    payload = {"alert_id": "x1", "timestamp": "2026-06-24T10:00:00Z", "host": "web", "src_ip": "1.2.3.4"}
    f.write_text(json.dumps(payload) + "\n")
    src = JsonlFileSource(f)
    alerts = src.fetch()
    assert len(alerts) == 1
    assert alerts[0].src_ip == "1.2.3.4"


def test_jsonl_source_handles_unnormalised_payload(tmp_path: Path):
    f = tmp_path / "alerts.jsonl"
    payload = {"id": "y1", "@timestamp": "2026-06-24T10:00:00Z", "hostname": "db", "srcip": "5.6.7.8"}
    f.write_text(json.dumps(payload) + "\n")
    src = JsonlFileSource(f)
    alerts = src.fetch()
    assert len(alerts) == 1
    assert alerts[0].host == "db"
    assert alerts[0].src_ip == "5.6.7.8"


def test_jsonl_source_skips_blank_lines_and_garbage(tmp_path: Path):
    f = tmp_path / "alerts.jsonl"
    f.write_text('\n{"alert_id":"ok"}\nNOT_JSON\n\n{"alert_id":"ok2"}\n')
    src = JsonlFileSource(f)
    alerts = src.fetch()
    assert len(alerts) == 2


def test_jsonl_source_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        JsonlFileSource(tmp_path / "does_not_exist.jsonl")


def test_jsonl_source_respects_limit(tmp_path: Path):
    f = tmp_path / "alerts.jsonl"
    lines = [
        json.dumps({"alert_id": f"id{i}", "timestamp": f"2026-06-24T10:0{i}:00Z"})
        for i in range(10)
    ]
    f.write_text("\n".join(lines) + "\n")
    src = JsonlFileSource(f)
    alerts = src.fetch(limit=3)
    assert len(alerts) == 3


def test_jsonl_source_respects_since_filter(tmp_path: Path):
    f = tmp_path / "alerts.jsonl"
    f.write_text(
        json.dumps({"alert_id": "old", "timestamp": "2026-06-01T00:00:00Z"}) + "\n" +
        json.dumps({"alert_id": "new", "timestamp": "2026-06-24T10:00:00Z"}) + "\n"
    )
    src = JsonlFileSource(f)
    alerts = src.fetch(since="2026-06-15T00:00:00Z")
    assert len(alerts) == 1
    assert alerts[0].alert_id == "new"


# ---- SyslogSource ---------------------------------------------------------


def test_syslog_ts_to_iso_current_year():
    from datetime import datetime, timezone
    iso = _syslog_ts_to_iso("Jun 24 10:23:45")
    assert iso.startswith(str(datetime.now(timezone.utc).year))


def test_syslog_ts_to_iso_year_wrapping():
    """If the parsed date is in the future, subtract a year."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    # January 5 — "Dec 30" must be previous year
    if now.month <= 6:
        iso = _syslog_ts_to_iso("Dec 30 10:23:45")
        # should be previous year
        assert iso.startswith(str(now.year - 1))


def test_syslog_source_returns_empty_for_missing_file(tmp_path: Path):
    src = SyslogSource(tmp_path / "no_such_log")
    assert src.fetch() == []


def test_syslog_source_parses_ssh_failed_login(tmp_path: Path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Jun 24 10:23:45 server sshd[1234]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2\n"
        "Jun 24 10:23:46 server sshd[1234]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2\n"
        "Jun 24 10:23:47 server sshd[1234]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2\n"
        "Jun 24 10:23:48 server sshd[1234]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2\n"
        "Jun 24 10:23:49 server sshd[1234]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2\n"
    )
    src = SyslogSource(log)
    alerts = src.fetch()
    # All 5 should be flagged as brute force (>= 5 from same IP)
    ssh_alerts = [a for a in alerts if a.event_type in ("ssh_failed_login", "ssh_brute_force")]
    assert len(ssh_alerts) >= 5
    brute = [a for a in ssh_alerts if a.event_type == "ssh_brute_force"]
    assert brute
    assert brute[0].severity == "high"
    assert brute[0].src_ip == "1.2.3.4"


def test_syslog_source_handles_unparseable_lines(tmp_path: Path):
    log = tmp_path / "auth.log"
    log.write_text("garbage line\nJun 24 10:23:45 server sshd[1234]: Failed password for alice from 5.6.7.8 port 22 ssh2\nmore garbage\n")
    src = SyslogSource(log)
    alerts = src.fetch()
    # only the valid ssh line should be parsed
    assert len(alerts) == 1
    assert alerts[0].src_ip == "5.6.7.8"