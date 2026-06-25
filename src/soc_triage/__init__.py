"""LLM-Powered SOC Triage Assistant — read-only, with a kill switch.

A FastAPI service that watches a SIEM / log pipeline, fans each alert to
a local LLM (Ollama or vLLM, or a stub for testing), and returns a
Markdown triage note. The assistant NEVER takes action on its own —
it only reads, classifies, and drafts. A kill switch drops it back to
passthrough mode instantly.
"""

__version__ = "0.1.0"