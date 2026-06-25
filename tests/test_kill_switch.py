"""Tests for the kill switch."""

from pathlib import Path

import pytest

from soc_triage.kill_switch import KillSwitch


def test_kill_switch_initially_disarmed(tmp_path: Path):
    ks = KillSwitch(data_dir=tmp_path)
    assert ks.is_armed() is False


def test_kill_switch_arm_disarm(tmp_path: Path):
    ks = KillSwitch(data_dir=tmp_path)
    ks.arm(source="rest", reason="test")
    assert ks.is_armed() is True
    ks.disarm(source="rest")
    assert ks.is_armed() is False


def test_kill_switch_arm_creates_audit_entry(tmp_path: Path):
    ks = KillSwitch(data_dir=tmp_path)
    ks.arm(source="rest", reason="manual", operator="alice")
    history = ks.history()
    assert len(history) == 1
    assert history[0]["action"] == "armed"
    assert history[0]["source"] == "rest"
    assert history[0]["operator"] == "alice"
    assert history[0]["reason"] == "manual"


def test_kill_switch_disarm_logs(tmp_path: Path):
    ks = KillSwitch(data_dir=tmp_path)
    ks.arm()
    ks.disarm(reason="all clear")
    history = ks.history()
    assert len(history) == 2
    assert history[0]["action"] == "armed"
    assert history[1]["action"] == "disarmed"
    assert history[1]["reason"] == "all clear"


def test_kill_switch_trip_logs_event_when_armed(tmp_path: Path):
    ks = KillSwitch(data_dir=tmp_path)
    ks.arm()
    tripped = ks.trip_if_armed()
    assert tripped is True
    history = ks.history()
    assert any(h["action"] == "tripped" for h in history)


def test_kill_switch_trip_no_op_when_disarmed(tmp_path: Path):
    ks = KillSwitch(data_dir=tmp_path)
    tripped = ks.trip_if_armed()
    assert tripped is False
    assert ks.history() == []


def test_kill_switch_rearm_logs_new_arm_event(tmp_path: Path):
    ks = KillSwitch(data_dir=tmp_path)
    ks.arm()
    ks.disarm()
    ks.arm(reason="second arm")
    history = ks.history()
    actions = [h["action"] for h in history]
    assert actions == ["armed", "disarmed", "armed"]


def test_kill_switch_disarm_when_not_armed_logs_anyway(tmp_path: Path):
    """Even if not armed, disarm() is a no-op but should still be logged."""
    ks = KillSwitch(data_dir=tmp_path)
    ks.disarm(reason="defensive")
    history = ks.history()
    assert len(history) == 1
    assert history[0]["action"] == "disarmed"


def test_kill_switch_data_dir_created(tmp_path: Path):
    new_dir = tmp_path / "fresh" / "nested"
    ks = KillSwitch(data_dir=new_dir)
    assert new_dir.exists()
    ks.arm()
    assert (new_dir / "KILL_SWITCH").exists()