"""LLM providers — pluggable backends behind a strict JSON-schema interface.

Supports:
  - Ollama   (local HTTP API at http://localhost:11434)
  - vLLM     (local HTTP API; OpenAI-compatible)
  - OpenAI-compatible endpoints (any provider exposing /v1/chat/completions)
  - Stub     (deterministic, used for tests + offline development)

The provider contract:
    provider.complete(prompt) -> dict
        Returns a dict matching soc_triage.schema.TRIAGE_SCHEMA.
        Raises TriageSchemaError on schema validation failure.
        Raises LLMUnavailable on connection / HTTP error.

The schema validation here is the CRITICAL safety boundary. The brief
is explicit: "never trust free-form LLM output into a SOC UI." Every
provider MUST call validate_triage() before returning.
"""

from __future__ import annotations

import abc
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from soc_triage.schema import validate_triage


class LLMError(Exception):
    """Base class for LLM provider errors."""


class TriageSchemaError(LLMError):
    """The LLM returned something that doesn't match TRIAGE_SCHEMA."""


class LLMUnavailable(LLMError):
    """The LLM provider is unreachable (network error, model not loaded, etc.)."""


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class LLMProvider(abc.ABC):
    """Abstract base for LLM providers."""

    name: str = "abstract"

    @abc.abstractmethod
    def _call_raw(self, prompt: str, system: str) -> str:
        """Call the LLM and return the raw text response."""

    def complete(self, prompt: str, system: str = "") -> dict[str, Any]:
        """Run the LLM, parse JSON out of the response, validate schema.

        Returns a dict matching TRIAGE_SCHEMA. Raises:
          - TriageSchemaError if JSON is malformed or schema doesn't match
          - LLMUnavailable on network/HTTP failure
        """
        raw = self._call_raw(prompt, system)
        parsed = _extract_json(raw)
        if parsed is None:
            raise TriageSchemaError(
                f"{self.name}: could not extract JSON from response (first 200 chars): {raw[:200]!r}"
            )
        try:
            validate_triage(parsed)
        except Exception as e:
            raise TriageSchemaError(f"{self.name}: schema validation failed: {e}; raw={parsed!r}") from e
        return parsed


# ---------------------------------------------------------------------------
# Ollama provider — local HTTP API
# ---------------------------------------------------------------------------


class OllamaProvider(LLMProvider):
    """Ollama local HTTP API.

    Default endpoint: http://localhost:11434/api/generate
    Default model:    llama3.1 (also try qwen2.5:7b, mistral:7b)

    See https://github.com/ollama/ollama/blob/main/docs/api.md
    """

    name = "ollama"

    def __init__(
        self,
        url: str = "http://localhost:11434",
        model: str = "llama3.1",
        timeout: int = 60,
    ) -> None:
        self.url = url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def _call_raw(self, prompt: str, system: str) -> str:
        body = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {"temperature": 0.1},
        }).encode()
        req = urllib.request.Request(
            f"{self.url}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read().decode())
        except urllib.error.URLError as e:
            raise LLMUnavailable(f"ollama unreachable at {self.url}: {e}") from e
        except Exception as e:
            raise LLMUnavailable(f"ollama call failed: {e}") from e
        return data.get("response", "")


# ---------------------------------------------------------------------------
# OpenAI-compatible provider — vLLM and any /v1/chat/completions endpoint
# ---------------------------------------------------------------------------


class OpenAICompatibleProvider(LLMProvider):
    """Any HTTP endpoint that speaks the OpenAI /v1/chat/completions API.

    This includes vLLM, llama.cpp's server mode, LM Studio, Together,
    OpenRouter, etc. We send a JSON-mode-style prompt and parse the
    assistant message as JSON.

    Set OPENAI_API_KEY env var for hosted endpoints (Together, OpenRouter).
    For vLLM/llama.cpp running locally, no key is required.
    """

    name = "openai-compatible"

    def __init__(
        self,
        url: str = "http://localhost:8000/v1",
        model: str = "Qwen/Qwen2.5-7B-Instruct",
        api_key: str = "",
        timeout: int = 60,
    ) -> None:
        self.url = url.rstrip("/")
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.timeout = timeout

    def _call_raw(self, prompt: str, system: str) -> str:
        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        }).encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(
            f"{self.url}/chat/completions",
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read().decode())
        except urllib.error.URLError as e:
            raise LLMUnavailable(f"openai-compatible endpoint unreachable at {self.url}: {e}") from e
        except Exception as e:
            raise LLMUnavailable(f"openai-compatible call failed: {e}") from e
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")


# ---------------------------------------------------------------------------
# Stub provider — deterministic, for tests + offline development
# ---------------------------------------------------------------------------


class StubProvider(LLMProvider):
    """Returns hand-crafted triage output based on alert content.

    This is what you get when no Ollama / vLLM is running. It uses
    simple keyword matching to produce plausible triage records. NOT
    real AI — explicitly so, and explicitly labelled as such in any
    output it produces.
    """

    name = "stub"

    def _call_raw(self, prompt: str, system: str) -> str:
        t = prompt.lower()

        # SSH brute force
        if "ssh" in t and ("brute" in t or "failed password" in t or "failed_login" in t or "failed login" in t):
            return json.dumps({
                "summary": "SSH brute-force attempt detected: multiple failed login attempts from a single source IP.",
                "severity": "high",
                "next_steps": [
                    "Block the source IP at the perimeter firewall.",
                    "Check /var/log/auth.log for successful logins from the same IP.",
                    "Confirm the targeted account(s) and rotate credentials if any login succeeded.",
                    "Enable fail2ban if not already active.",
                ],
                "confidence": 0.92,
                "mitre_attack": ["T1110"],
                "rationale": "Repeated failed SSH logins from a single source IP match the canonical brute-force pattern.",
            })

        # SQL injection
        if "sql" in t and ("injection" in t or "select" in t or "union" in t):
            return json.dumps({
                "summary": "SQL injection attempts blocked by WAF.",
                "severity": "critical",
                "next_steps": [
                    "Confirm WAF rule fired and the payload did not reach the application.",
                    "Pull the WAF logs and identify the targeted endpoint and parameter.",
                    "Have appsec review the endpoint for code-level SQLi risk.",
                    "Add a temporary block on the source IP.",
                ],
                "confidence": 0.95,
                "mitre_attack": ["T1190"],
                "rationale": "SQLi patterns observed in HTTP request payloads against an authenticated endpoint.",
            })

        # Port scan
        if "port scan" in t or "portsc" in t:
            return json.dumps({
                "summary": "Network port scan detected.",
                "severity": "low",
                "next_steps": [
                    "Note the source IP for correlation with future alerts.",
                    "If the source IP is internal, identify the host and the user running the scan.",
                    "Confirm exposed services are intentional and patched.",
                ],
                "confidence": 0.8,
                "mitre_attack": ["T1046"],
                "rationale": "Multiple ports probed in a short window from a single source.",
            })

        # Generic fallback
        return json.dumps({
            "summary": "Alert received but did not match a known pattern. Recommend human review.",
            "severity": "low",
            "next_steps": [
                "Open the alert in the SIEM to see the raw payload.",
                "Correlate with other recent alerts from the same host or user.",
                "Mark as benign or escalate based on context.",
            ],
            "confidence": 0.4,
            "mitre_attack": [],
            "rationale": "Stub provider — heuristic did not match a known attack pattern.",
        })


# ---------------------------------------------------------------------------
# JSON extraction — robust to common LLM failure modes
# ---------------------------------------------------------------------------


def _extract_json(raw: str) -> dict[str, Any] | None:
    """Extract the first JSON object from `raw`.

    Handles three common LLM output failure modes:
      1. JSON wrapped in ```json ... ``` fences
      2. JSON preceded by explanatory prose ("Sure, here is...")
      3. JSON trailing prose after the closing brace

    Strategy: scan for the first `{` and try to decode from there
    with progressively-larger substrings, picking the longest valid
    decode.
    """
    if not raw:
        return None
    s = raw.strip()
    # Strip markdown code fences
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```\s*$", "", s)
    s = s.strip()

    # Find the first '{' and try to decode the longest valid prefix
    idx = s.find("{")
    if idx == -1:
        return None
    candidate = s[idx:]
    # Try full string, then progressively shorter
    for end in range(len(candidate), 0, -1):
        try:
            obj = json.loads(candidate[:end])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None


def provider_from_env() -> LLMProvider:
    """Pick a provider based on environment variables.

    Order:
      SOC_TRIAGE_PROVIDER=ollama|vllm|stub (explicit override)
      else: ollama if OLLAMA_URL reachable, else vllm if VLLM_URL reachable, else stub
    """
    explicit = os.environ.get("SOC_TRIAGE_PROVIDER", "").lower()
    if explicit == "stub":
        return StubProvider()
    if explicit == "ollama":
        return OllamaProvider(
            url=os.environ.get("OLLAMA_URL", "http://localhost:11434"),
            model=os.environ.get("OLLAMA_MODEL", "llama3.1"),
        )
    if explicit in ("vllm", "openai-compatible", "openai"):
        return OpenAICompatibleProvider(
            url=os.environ.get("VLLM_URL", os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1")),
            model=os.environ.get("VLLM_MODEL", os.environ.get("OPENAI_MODEL", "Qwen/Qwen2.5-7B-Instruct")),
            api_key=os.environ.get("OPENAI_API_KEY", ""),
        )
    # Auto-detect
    for name, url in (
        ("ollama", os.environ.get("OLLAMA_URL", "http://localhost:11434")),
        ("vllm", os.environ.get("VLLM_URL", "http://localhost:8000/v1")),
    ):
        try:
            req = urllib.request.Request(f"{url}/" + ("api/tags" if name == "ollama" else "models"))
            with urllib.request.urlopen(req, timeout=2):
                pass
            if name == "ollama":
                return OllamaProvider(url=url)
            return OpenAICompatibleProvider(url=url)
        except Exception:
            continue
    return StubProvider()