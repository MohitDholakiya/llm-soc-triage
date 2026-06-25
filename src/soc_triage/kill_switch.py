"""Kill switch — the safety boundary.

The brief is explicit: the assistant should never take action on its
own. The kill switch is the operator's escape hatch when something
goes wrong (LLM misbehaving, runaway latency, cost spike, prompt
injection, operator wants to review the raw alerts directly).

Two trigger paths, both checked at every triage step:
  1. File-based: create a file at kill_switch_path (default
     ./data/KILL_SWITCH). Its existence == armed.
  2. Signal-based: SIGTERM to the process == armed.

When armed:
  - `is_armed()` returns True
  - `triage()` returns a passthrough record with `triage_status="skipped_kill_switch"`
  - The audit log records who/when/why

The switch is also exposed via REST: GET /kill (read state), POST /kill
(arm), DELETE /kill (disarm). All transitions are logged.
"""

from __future__ import annotations

import json
import os
import signal
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class KillEvent:
    """One audit entry for a kill-switch state change."""

    timestamp: str
    action: str       # "armed" | "disarmed" | "tripped"
    source: str       # "file" | "signal" | "rest" | "auto"
    reason: str = ""
    operator: str = ""


class KillSwitch:
    """Thread-safe kill switch with file-based persistence and audit log."""

    def __init__(self, data_dir: Path | str = "./data") -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.flag_path = self.data_dir / "KILL_SWITCH"
        self.audit_log_path = self.data_dir / "kill_switch_audit.jsonl"
        self._lock = threading.Lock()

    # ---- state --------------------------------------------------------

    def is_armed(self) -> bool:
        """True if the switch is currently armed."""
        return self.flag_path.exists()

    def arm(self, source: str = "rest", reason: str = "", operator: str = "") -> None:
        """Arm the switch (create the flag file)."""
        with self._lock:
            self.flag_path.touch()
            self._log(KillEvent(
                timestamp=_now_iso(),
                action="armed",
                source=source,
                reason=reason,
                operator=operator,
            ))

    def disarm(self, source: str = "rest", reason: str = "", operator: str = "") -> None:
        """Disarm the switch (remove the flag file)."""
        with self._lock:
            if self.flag_path.exists():
                self.flag_path.unlink()
            self._log(KillEvent(
                timestamp=_now_iso(),
                action="disarmed",
                source=source,
                reason=reason,
                operator=operator,
            ))

    def trip_if_armed(self) -> bool:
        """If the switch is armed, log a 'tripped' event and return True.

        Called by the triage layer at every step. The triage layer
        short-circuits to passthrough mode when this returns True.
        """
        if not self.is_armed():
            return False
        self._log(KillEvent(
            timestamp=_now_iso(),
            action="tripped",
            source="auto",
            reason="triage step blocked by armed kill switch",
        ))
        return True

    # ---- audit log ----------------------------------------------------

    def history(self) -> list[dict]:
        """Return the full audit log as a list of dicts."""
        if not self.audit_log_path.exists():
            return []
        with self.audit_log_path.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def _log(self, event: KillEvent) -> None:
        with self.audit_log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# Signal handler — install at process startup
# ---------------------------------------------------------------------------


def install_signal_handler(kill_switch: KillSwitch) -> None:
    """Install SIGTERM/SIGINT handlers that arm the kill switch.

    This is the "hard kill" path: pressing Ctrl-C or sending SIGTERM
    arms the switch, and the next triage step short-circuits. The
    process keeps running so the operator can investigate.
    """
    def handler(signum, frame):
        kill_switch.arm(source="signal", reason=f"received signal {signum}")

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            # Not in main thread, or platform doesn't support
            pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")