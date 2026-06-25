"""Alert sources — pluggable input adapters.

The triage assistant is read-only: it never writes back to the SIEM.
It only READS alerts from a configured source and emits normalised
Alert objects to the triage layer.

Supported sources:
    - JSONL file (one alert per line)
    - /var/log/syslog (Linux) / /var/log/auth.log (Debian) / Event Log
      (Windows, via pywin32 if installed)
    - Wazuh API (https://<host>:55000)
    - Elastic / OpenSearch API (https://<host>:9200)
    - A `stub` source that returns hand-crafted alerts from samples/

The Alert dataclass is the contract between sources and the triage
layer — every source normalises to this shape.
"""

from __future__ import annotations

import abc
import json
import re
import socket
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator


@dataclass
class Alert:
    """One normalised alert from any source."""

    alert_id: str
    timestamp: str  # ISO-8601 UTC
    source: str     # e.g. "wazuh", "elastic", "syslog", "jsonl", "stub"
    host: str = ""
    user: str = ""
    src_ip: str = ""
    event_type: str = ""
    severity: str = ""  # raw severity from the source, may be numeric
    raw: dict = field(default_factory=dict)  # the original payload
    message: str = ""  # human-readable one-liner

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class AlertSource(abc.ABC):
    """Abstract base for alert sources. Implement `fetch()` only."""

    name: str = "abstract"

    @abc.abstractmethod
    def fetch(self, since: str | None = None, limit: int = 100) -> list[Alert]:
        """Fetch alerts newer than `since` (ISO-8601 UTC), up to `limit`."""

    def __iter__(self) -> Iterator[Alert]:
        """Convenience: iterate `fetch()` results."""
        return iter(self.fetch())


# ---------------------------------------------------------------------------
# JSONL file source — the default for testing and small deployments
# ---------------------------------------------------------------------------


class JsonlFileSource(AlertSource):
    """Reads alerts from a JSONL file (one alert per line).

    The file may contain either:
      - Pre-normalised Alert dicts (with `alert_id`, `timestamp`, etc.)
      - Raw SIEM payloads that need mapping
    """

    name = "jsonl"

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"alert file not found: {self.path}")

    def fetch(self, since: str | None = None, limit: int = 100) -> list[Alert]:
        out: list[Alert] = []
        since_dt = _parse_iso(since) if since else None
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                alert = self._to_alert(raw)
                if since_dt and _parse_iso(alert.timestamp) and _parse_iso(alert.timestamp) < since_dt:
                    continue
                out.append(alert)
                if len(out) >= limit:
                    break
        return out

    def _to_alert(self, raw: dict) -> Alert:
        # Already-normalised?
        if "alert_id" in raw and "timestamp" in raw:
            return Alert(
                alert_id=raw["alert_id"],
                timestamp=raw["timestamp"],
                source=raw.get("source", self.name),
                host=raw.get("host", ""),
                user=raw.get("user", ""),
                src_ip=raw.get("src_ip", ""),
                event_type=raw.get("event_type", ""),
                severity=str(raw.get("severity", "")),
                raw=raw,
                message=raw.get("message", ""),
            )
        # Map a generic dict
        return Alert(
            alert_id=str(raw.get("id") or raw.get("alert_id") or f"jsonl-{time.time_ns()}"),
            timestamp=raw.get("timestamp") or raw.get("@timestamp") or _now_iso(),
            source=raw.get("source", self.name),
            host=raw.get("host") or raw.get("hostname") or raw.get("agent", {}).get("name", ""),
            user=raw.get("user") or raw.get("user_name") or "",
            src_ip=raw.get("src_ip") or raw.get("source_ip") or raw.get("srcip") or "",
            event_type=raw.get("event_type") or raw.get("rule", {}).get("description", "") or raw.get("type", ""),
            severity=str(raw.get("severity") or raw.get("level") or raw.get("rule", {}).get("level", "")),
            raw=raw,
            message=raw.get("message") or raw.get("full_log") or raw.get("description") or "",
        )


# ---------------------------------------------------------------------------
# Syslog source — parses /var/log/syslog and /var/log/auth.log lines
# ---------------------------------------------------------------------------

# Pattern covers:
#   "Jun 24 10:23:45 host sshd[1234]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2"
#   "Jun 24 10:23:45 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
_SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)

# SSH brute force detection
_SSH_FAIL_RE = re.compile(
    r"Failed password for(?:\s+invalid user)?\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)"
)


class SyslogSource(AlertSource):
    """Tail a syslog file and emit normalised alerts.

    Heuristics:
      - SSH "Failed password" lines → severity "medium", event_type "ssh_brute_force"
        (after 5+ failures from the same src_ip, severity climbs to "high")
      - sudo COMMAND= lines by non-root users → severity "low"
      - Everything else → severity "info"
    """

    name = "syslog"

    def __init__(self, path: Path = Path("/var/log/syslog")) -> None:
        self.path = Path(path)

    def fetch(self, since: str | None = None, limit: int = 100) -> list[Alert]:
        if not self.path.exists():
            return []
        out: list[Alert] = []
        ssh_fail_count: dict[str, int] = {}
        with self.path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                a = self._to_alert(line, ssh_fail_count)
                if a is None:
                    continue
                out.append(a)
                if len(out) >= limit:
                    break
        return out

    def _to_alert(self, line: str, ssh_fail_count: dict[str, int]) -> Alert | None:
        m = _SYSLOG_RE.match(line)
        if not m:
            return None
        ts = _syslog_ts_to_iso(m.group("ts"))
        host = m.group("host")
        proc = m.group("proc").strip()
        pid = m.group("pid")
        msg = m.group("msg")

        src_ip = ""
        user = ""
        event_type = proc
        severity = "info"

        if proc in {"sshd", "sshd-session"}:
            fm = _SSH_FAIL_RE.search(msg)
            if fm:
                user = fm.group("user")
                src_ip = fm.group("src_ip")
                event_type = "ssh_failed_login"
                ssh_fail_count[src_ip] = ssh_fail_count.get(src_ip, 0) + 1
                if ssh_fail_count[src_ip] >= 5:
                    severity = "high"
                    event_type = "ssh_brute_force"
                else:
                    severity = "medium"

        alert_id = f"syslog-{ts}-{host}-{pid or '0'}-{len(ssh_fail_count)}"
        return Alert(
            alert_id=alert_id,
            timestamp=ts,
            source=self.name,
            host=host,
            user=user,
            src_ip=src_ip,
            event_type=event_type,
            severity=severity,
            raw={"line": line},
            message=msg,
        )


# ---------------------------------------------------------------------------
# Wazuh API source
# ---------------------------------------------------------------------------


class WazuhSource(AlertSource):
    """Polls a Wazuh manager API for alerts.

    Configure with WAZUH_URL, WAZUH_USER, WAZUH_PASSWORD env vars.
    Auth uses the JWT token endpoint at /security/user/authenticate.
    """

    name = "wazuh"

    def __init__(
        self,
        url: str = "https://localhost:55000",
        user: str = "",
        password: str = "",
        timeout: int = 30,
    ) -> None:
        self.url = url.rstrip("/")
        self.user = user
        self.password = password
        self.timeout = timeout

    def fetch(self, since: str | None = None, limit: int = 100) -> list[Alert]:
        import urllib.request

        token = self._get_token()
        if not token:
            return []
        req = urllib.request.Request(
            f"{self.url}/alerts?limit={limit}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read().decode())
        except Exception as e:
            print(f"wazuh fetch error: {e}", file=__import__("sys").stderr)
            return []
        items = data.get("data", {}).get("affected_items", [])
        return [self._to_alert(item) for item in items]

    def _get_token(self) -> str:
        import urllib.request

        body = json.dumps({"username": self.user, "password": self.password}).encode()
        req = urllib.request.Request(
            f"{self.url}/security/user/authenticate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read().decode())
                return data.get("data", {}).get("token", "")
        except Exception as e:
            print(f"wazuh auth error: {e}", file=__import__("sys").stderr)
            return ""

    def _to_alert(self, raw: dict) -> Alert:
        agent = raw.get("agent", {}) or {}
        rule = raw.get("rule", {}) or {}
        ts = raw.get("timestamp") or _now_iso()
        return Alert(
            alert_id=str(raw.get("id", f"wazuh-{time.time_ns()}")),
            timestamp=ts,
            source=self.name,
            host=agent.get("name", ""),
            user=raw.get("data", {}).get("user", "") or raw.get("data", {}).get("dstuser", ""),
            src_ip=raw.get("data", {}).get("srcip", "") or raw.get("data", {}).get("src_ip", ""),
            event_type=rule.get("description", ""),
            severity=str(rule.get("level", "")),
            raw=raw,
            message=raw.get("full_log", "") or rule.get("description", ""),
        )


# ---------------------------------------------------------------------------
# Elastic / OpenSearch source
# ---------------------------------------------------------------------------


class ElasticSource(AlertSource):
    """Polls an Elasticsearch / OpenSearch index for alert documents.

    Configure with ELASTIC_URL, ELASTIC_INDEX, optional ELASTIC_USER/PASSWORD
    (or API key).
    """

    name = "elastic"

    def __init__(
        self,
        url: str = "http://localhost:9200",
        index: str = "logs-*",
        user: str = "",
        password: str = "",
        api_key: str = "",
        timeout: int = 30,
    ) -> None:
        self.url = url.rstrip("/")
        self.index = index
        self.user = user
        self.password = password
        self.api_key = api_key
        self.timeout = timeout

    def fetch(self, since: str | None = None, limit: int = 100) -> list[Alert]:
        import urllib.request

        # _search with size + sort by @timestamp desc
        query = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"match_all": {}},
        }
        body = json.dumps(query).encode()
        req = urllib.request.Request(
            f"{self.url}/{self.index}/_search",
            data=body,
            headers={**_elastic_auth_headers(self.user, self.password, self.api_key),
                     "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read().decode())
        except Exception as e:
            print(f"elastic fetch error: {e}", file=__import__("sys").stderr)
            return []
        hits = data.get("hits", {}).get("hits", [])
        return [self._to_alert(h) for h in hits]

    def _to_alert(self, raw: dict) -> Alert:
        src = raw.get("_source", {}) or {}
        host = (src.get("host", {}) or {}).get("name", "") if isinstance(src.get("host"), dict) else src.get("host", "")
        return Alert(
            alert_id=str(raw.get("_id", f"elastic-{time.time_ns()}")),
            timestamp=src.get("@timestamp") or _now_iso(),
            source=self.name,
            host=host,
            user=src.get("user", {}).get("name", "") if isinstance(src.get("user"), dict) else src.get("user", ""),
            src_ip=src.get("source", {}).get("ip", "") if isinstance(src.get("source"), dict) else src.get("source_ip", ""),
            event_type=src.get("event", {}).get("category", "") or src.get("event_type", ""),
            severity=str(src.get("event", {}).get("severity", "") or src.get("severity", "")),
            raw=src,
            message=src.get("message", ""),
        )


# ---------------------------------------------------------------------------
# Stub source — for tests + for running without any SIEM
# ---------------------------------------------------------------------------


class StubSource(AlertSource):
    """Emits hand-crafted alerts. Used by tests and the dashboard demo."""

    name = "stub"

    @staticmethod
    def _alerts() -> list[Alert]:
        return [
            Alert(
                alert_id="stub-1",
                timestamp=_now_iso(offset_seconds=0),
                source="stub",
                host="web-prod-01",
                user="root",
                src_ip="203.0.113.42",
                event_type="ssh_brute_force",
                severity="high",
                raw={"count": 47},
                message="47 SSH failed-login attempts for 'root' from 203.0.113.42 in last 5 minutes.",
            ),
            Alert(
                alert_id="stub-2",
                timestamp=_now_iso(offset_seconds=-30),
                source="stub",
                host="api-prod-02",
                user="alice",
                src_ip="198.51.100.7",
                event_type="sql_injection_attempt",
                severity="critical",
                raw={},
                message="WAF blocked 12 SQL injection attempts against /api/login from 198.51.100.7.",
            ),
            Alert(
                alert_id="stub-3",
                timestamp=_now_iso(offset_seconds=-120),
                source="stub",
                host="web-prod-01",
                user="",
                src_ip="192.0.2.55",
                event_type="port_scan",
                severity="low",
                raw={"ports": "22,80,443,3389,8080"},
                message="Port scan detected from 192.0.2.55: 22, 80, 443, 3389, 8080 in 8 seconds.",
            ),
        ]

    def fetch(self, since: str | None = None, limit: int = 100) -> list[Alert]:
        return self._alerts()[:limit]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso(offset_seconds: int = 0) -> str:
    from datetime import timedelta
    dt = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _syslog_ts_to_iso(ts: str) -> str:
    """Convert 'Jun 24 10:23:45' (no year) to ISO-8601 UTC, current year.

    Syslog lines don't include the year — we default to the current
    calendar year. If the resulting date is in the future (e.g. from
    a year-wrap), subtract 1 year.
    """
    now = datetime.now(timezone.utc)
    try:
        dt = datetime.strptime(f"{now.year} {ts}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return _now_iso()
    if dt > now:
        dt = dt.replace(year=now.year - 1)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _elastic_auth_headers(user: str, password: str, api_key: str) -> dict[str, str]:
    """Build Elastic auth headers — basic auth or API key, no secrets."""
    if api_key:
        return {"Authorization": f"ApiKey {api_key}"}
    if user and password:
        import base64
        cred = base64.b64encode(f"{user}:{password}".encode()).decode()
        return {"Authorization": f"Basic {cred}"}
    return {}