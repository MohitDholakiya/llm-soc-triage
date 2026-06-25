"""Storage for triage records, feedback verdicts, and the few-shot prompt bank.

Two backends, written in tandem:
  - SQLite (WAL mode) — for analytics queries and the dashboard
  - JSONL — append-only, for offline forensics

Schema:
  triage_records(
    id, alert_id, ts, source, host, user, src_ip,
    event_type, raw_severity,
    summary, severity, next_steps, confidence,
    mitre_attack, rationale,
    needs_human_review, triage_status,       -- "triaged" | "skipped_kill_switch" | "error"
    model_provider, model_name,
    latency_ms, error_message
  )
  feedback(
    id, triage_id, verdict,                -- "up" | "down"
    comment, ts, operator
  )
  prompt_bank(
    id, alert_type, prompt_text, source_triage_id, ts
  )
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


_SCHEMA = """
CREATE TABLE IF NOT EXISTS triage_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    source TEXT,
    host TEXT,
    user TEXT,
    src_ip TEXT,
    event_type TEXT,
    raw_severity TEXT,
    summary TEXT,
    severity TEXT,
    next_steps TEXT,             -- JSON array
    confidence REAL,
    mitre_attack TEXT,           -- JSON array
    rationale TEXT,
    needs_human_review INTEGER,  -- 0/1
    triage_status TEXT,          -- 'triaged' | 'skipped_kill_switch' | 'error'
    model_provider TEXT,
    model_name TEXT,
    latency_ms INTEGER,
    error_message TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_triage_alert_id ON triage_records(alert_id);
CREATE INDEX IF NOT EXISTS idx_triage_ts ON triage_records(ts);
CREATE INDEX IF NOT EXISTS idx_triage_severity ON triage_records(severity);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    triage_id INTEGER NOT NULL,
    verdict TEXT NOT NULL,       -- 'up' | 'down'
    comment TEXT,
    ts TEXT NOT NULL,
    operator TEXT,
    FOREIGN KEY (triage_id) REFERENCES triage_records(id)
);
CREATE INDEX IF NOT EXISTS idx_feedback_triage_id ON feedback(triage_id);

CREATE TABLE IF NOT EXISTS prompt_bank (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    prompt_text TEXT NOT NULL,
    source_triage_id INTEGER,
    ts TEXT NOT NULL,
    FOREIGN KEY (source_triage_id) REFERENCES triage_records(id)
);
"""


@dataclass
class TriageRecord:
    """One persisted triage record — either triaged, skipped, or errored."""

    alert_id: str
    ts: str
    source: str = ""
    host: str = ""
    user: str = ""
    src_ip: str = ""
    event_type: str = ""
    raw_severity: str = ""
    summary: str = ""
    severity: str = ""
    next_steps: list[str] = field(default_factory=list)
    confidence: float = 0.0
    mitre_attack: list[str] = field(default_factory=list)
    rationale: str = ""
    needs_human_review: bool = False
    triage_status: str = "triaged"  # "triaged" | "skipped_kill_switch" | "error"
    model_provider: str = ""
    model_name: str = ""
    latency_ms: int = 0
    error_message: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))

    @property
    def id(self) -> int | None:
        """The SQLite row ID — None until inserted."""
        return getattr(self, "_id", None)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("_id", None)
        return d


class TriageStore:
    """Thread-safe dual SQLite + JSONL store."""

    def __init__(self, db_path: Path | str, jsonl_path: Path | str | None = None) -> None:
        self.db_path = Path(db_path)
        self.jsonl_path = Path(jsonl_path) if jsonl_path else None
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(_SCHEMA)

    # ---- triage writes --------------------------------------------------

    def insert_triage(self, r: TriageRecord) -> int:
        """Persist a triage record. Returns the SQLite row id."""
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO triage_records (
                        alert_id, ts, source, host, user, src_ip,
                        event_type, raw_severity,
                        summary, severity, next_steps, confidence,
                        mitre_attack, rationale,
                        needs_human_review, triage_status,
                        model_provider, model_name,
                        latency_ms, error_message,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        r.alert_id, r.ts, r.source, r.host, r.user, r.src_ip,
                        r.event_type, r.raw_severity,
                        r.summary, r.severity, json.dumps(r.next_steps), r.confidence,
                        json.dumps(r.mitre_attack), r.rationale,
                        1 if r.needs_human_review else 0, r.triage_status,
                        r.model_provider, r.model_name,
                        r.latency_ms, r.error_message,
                        r.created_at,
                    ),
                )
                row_id = cur.lastrowid
            if self.jsonl_path is not None:
                self._append_jsonl(r, row_id)
            return row_id

    def _append_jsonl(self, r: TriageRecord, row_id: int) -> None:
        d = r.to_dict()
        d["id"] = row_id
        with self.jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")

    # ---- feedback -------------------------------------------------------

    def insert_feedback(self, triage_id: int, verdict: str, comment: str = "", operator: str = "") -> int:
        if verdict not in ("up", "down"):
            raise ValueError(f"verdict must be 'up' or 'down', got {verdict!r}")
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO feedback (triage_id, verdict, comment, ts, operator) VALUES (?, ?, ?, ?, ?)",
                (
                    triage_id,
                    verdict,
                    comment,
                    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    operator,
                ),
            )
            return cur.lastrowid

    def feedback_for(self, triage_id: int) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM feedback WHERE triage_id = ? ORDER BY id DESC", (triage_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def feedback_stats(self) -> dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT verdict, COUNT(*) AS n FROM feedback GROUP BY verdict"
            ).fetchall()
        return {r["verdict"]: r["n"] for r in rows}

    # ---- prompt bank ---------------------------------------------------

    def add_to_prompt_bank(self, alert_type: str, prompt_text: str, source_triage_id: int | None = None) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO prompt_bank (alert_type, prompt_text, source_triage_id, ts) VALUES (?, ?, ?, ?)",
                (
                    alert_type,
                    prompt_text,
                    source_triage_id,
                    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                ),
            )
            return cur.lastrowid

    def few_shot_prompts(self, alert_type: str | None = None, limit: int = 5) -> list[dict[str, Any]]:
        sql = "SELECT * FROM prompt_bank"
        params: list[Any] = []
        if alert_type:
            sql += " WHERE alert_type = ?"
            params.append(alert_type)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ---- analytics -----------------------------------------------------

    def count_triage(self, status: str | None = None) -> int:
        sql = "SELECT COUNT(*) AS n FROM triage_records"
        params: list[Any] = []
        if status:
            sql += " WHERE triage_status = ?"
            params.append(status)
        with self._connect() as conn:
            row = conn.execute(sql, params).fetchone()
        return int(row["n"])

    def confidence_histogram(self, buckets: int = 10) -> list[dict[str, Any]]:
        """Return histogram of confidence values."""
        sql = f"""
            SELECT CAST(confidence * {buckets} AS INTEGER) AS bucket,
                   COUNT(*) AS n
            FROM triage_records
            WHERE triage_status = 'triaged' AND confidence IS NOT NULL
            GROUP BY bucket
            ORDER BY bucket
        """
        with self._connect() as conn:
            rows = conn.execute(sql).fetchall()
        return [{"bucket": int(r["bucket"]), "n": r["n"]} for r in rows]

    def mitre_counts(self) -> dict[str, int]:
        """Count of triages by MITRE ATT&CK technique."""
        out: dict[str, int] = {}
        with self._connect() as conn:
            for row in conn.execute(
                "SELECT mitre_attack FROM triage_records WHERE triage_status = 'triaged'"
            ):
                try:
                    techniques = json.loads(row["mitre_attack"])
                except (json.JSONDecodeError, TypeError):
                    continue
                for t in techniques:
                    out[t] = out.get(t, 0) + 1
        return out

    def severity_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        with self._connect() as conn:
            for row in conn.execute(
                "SELECT severity FROM triage_records WHERE triage_status = 'triaged'"
            ):
                sev = row["severity"] or "unknown"
                out[sev] = out.get(sev, 0) + 1
        return out

    def fetch_all(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM triage_records ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["next_steps"] = json.loads(d["next_steps"])
            except (json.JSONDecodeError, TypeError):
                d["next_steps"] = []
            try:
                d["mitre_attack"] = json.loads(d["mitre_attack"])
            except (json.JSONDecodeError, TypeError):
                d["mitre_attack"] = []
            d["needs_human_review"] = bool(d["needs_human_review"])
            out.append(d)
        return out

    def fetch_one(self, triage_id: int) -> dict[str, Any] | None:
        rows = self.fetch_all(limit=10_000)
        for r in rows:
            if r["id"] == triage_id:
                return r
        return None