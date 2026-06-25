# Architecture

## Data flow

```
                    ┌────────────────────────────────────────────┐
   SIEM / log       │                                            │
   sources          │  AlertSource (read-only)                  │
   (Wazuh, Elastic, ├────────────────────────────┐               │
    syslog, JSONL)  │                            │               │
                    │   Alert (normalised)       ▼               │
                    └────────────────────────────────────────────┘
                                                         │
                                                         ▼
                    ┌────────────────────────────────────────────┐
                    │  TriageOrchestrator.triage(alert)          │
                    │                                            │
                    │  1. kill_switch.trip_if_armed() ─────────► │ skip
                    │  2. build_user_prompt(alert, few_shot)     │
                    │  3. provider.complete(prompt, system) ───► │ ┌─────────────────┐
                    │  4. validate against TRIAGE_SCHEMA         │ │ LLMProvider     │
                    │  5. apply confidence threshold              │ │ (Ollama/vLLM/   │
                    │  6. persist TriageRecord (SQLite + JSONL)  │ │  Stub)          │
                    │                                            │ │                 │
                    │  Returns: row_id (int)                     │ │ STRICT JSON out │
                    └────────────────────────────────────────────┘ │ └─────────────────┘
                                                         │
                                                         ▼
                    ┌────────────────────────────────────────────┐
                    │  TriageStore (SQLite WAL + JSONL)          │
                    │                                            │
                    │   triage_records  ◄─── source of truth     │
                    │   feedback        ◄─── analyst 👍 / 👎     │
                    │   prompt_bank     ◄─── 👍 → auto-populate   │
                    └────────────────────────────────────────────┘
                                                         │
                                                         ▼
                    ┌────────────────────────────────────────────┐
                    │  Renderer (Jinja2)                          │
                    │                                            │
                    │   Markdown  → for dashboard / GitHub       │
                    │   Slack    → for chat ops alerts           │
                    │   Teams    → for MS Teams Adaptive Cards   │
                    └────────────────────────────────────────────┘
                                                         │
                                                         ▼
                    ┌────────────────────────────────────────────┐
                    │  KillSwitch (file + signal + audit)       │
                    │                                            │
                    │   data/KILL_SWITCH  ◄─── arm by touching    │
                    │   kill_switch_audit.jsonl  ◄─── every     │
                    │                              transition     │
                    └────────────────────────────────────────────┘
```

## Component map

| Module | Role |
|---|---|
| `soc_triage/alert_source.py` | Pluggable alert sources (JsonlFile, Syslog, Wazuh, Elastic, Stub). All read-only. |
| `soc_triage/llm_provider.py` | Pluggable LLM backends (Ollama, OpenAI-compatible / vLLM, Stub). All providers validate against `TRIAGE_SCHEMA`. |
| `soc_triage/schema.py` | The strict JSON schema the LLM MUST produce. `is_low_confidence()` for the 0.6 threshold. |
| `soc_triage/kill_switch.py` | File-based + signal-based kill switch with full audit trail. |
| `soc_triage/store.py` | SQLite (WAL) + JSONL dual store. Analytics helpers. |
| `soc_triage/triage.py` | The orchestrator. Read-only pipeline: alert → prompt → LLM → validate → record. |
| `soc_triage/renderer.py` | Jinja2 templates for Markdown, Slack mrkdwn, Teams Adaptive Card. |
| `soc_triage/server.py` | FastAPI app. REST endpoints, kill switch REST, feedback REST. |
| `soc_triage/dashboard.py` | Streamlit operator dashboard. |

## Schema (the safety boundary)

The brief is explicit: "Wrap the LLM behind a strict JSON schema. Validate it on the way out — never trust free-form LLM output into a SOC UI."

```json
{
  "summary":      "1-2 sentence plain-English summary",
  "severity":     "low" | "medium" | "high" | "critical",
  "next_steps":   ["action 1", "action 2", ...],   // 1-5 items
  "confidence":   0.0..1.0,
  "mitre_attack": ["Txxxx", ...],                   // optional
  "rationale":    "why this severity"
}
```

Every LLM provider runs the output through `jsonschema.validate()` before returning. Anything that doesn't match raises `TriageSchemaError`, which is logged as `triage_status="error"`.

## Confidence threshold

The brief: "Add a 'confidence' field: if model confidence < 0.6, mark the alert for human review."

```python
DEFAULT_LOW_CONFIDENCE_THRESHOLD = 0.6

def is_low_confidence(confidence, threshold=DEFAULT_LOW_CONFIDENCE_THRESHOLD):
    return confidence < threshold
```

The orchestrator sets `needs_human_review=True` on the record when the LLM's self-rated confidence is below the threshold. The dashboard highlights these rows.

## Feedback loop → prompt bank

The brief: "Add a feedback loop: analysts click 👍/👎, store the verdicts, use them to build a few-shot prompt bank."

```
analyst 👍 ──► feedback table (verdict='up')
            └► prompt_bank table (the triage becomes a few-shot example)

next triage ──► fetch_prompt_bank(alert_type=...) ──► 0-3 examples
                                                  ──► appended to user prompt
```

The next triage of a similar alert type automatically pulls up to 3 few-shot examples from the prompt bank and prepends them to the user message. This is a basic form of in-context learning — no model retraining required.

## Threat model

**Out of scope** (this is a defensive portfolio piece, not production SIEM):

- Adversarial prompts designed to make the LLM produce valid JSON but dangerous `next_steps` (e.g. "block the production database"). Mitigation: the `next_steps` field is text only; nothing in this codebase executes the steps. The operator reads them.
- LLM hallucination in the `mitre_attack` field — could misattribute a technique. Mitigation: the dashboard shows the field as text; an analyst reviews before using it for ATT&CK Navigator export.
- Prompt injection via alert content (an attacker plants text in a log line that reaches the LLM as part of the prompt). Mitigation: the alert is rendered as JSON inside a markdown code block in the prompt, and the system prompt explicitly tells the model not to act on alert content as instructions.

**In scope** (the actual point of the project):

- Triage latency: time from alert arrival to triage record persisted
- False-positive rate: tracked via 👍/👎 feedback on the prompt bank
- Analyst agreement: % of 👍 verdicts on triages the model produced (used to measure the "comparison table" the brief asks for)

## Failure modes

| Failure | What happens |
|---|---|
| Kill switch armed | Every subsequent triage records `skipped_kill_switch` and returns immediately. LLM is never called. |
| LLM returns invalid JSON | TriageSchemaError. Record stored as `triage_status="error"`. |
| LLM returns valid JSON but schema fails | Same as above — the orchestrator re-runs `validate_triage()` defensively. |
| LLM provider unreachable (Ollama down) | LLMUnavailable. Record stored as `error`. The dashboard shows the error count. |
| LLM times out | Treated as LLMUnavailable. |
| SQLite write fails | The triage is lost. The dashboard surfaces the error count to the operator. |
| JSONL write fails | The SQLite row is still persisted; the line goes to stderr. |
| Confidence below threshold | `needs_human_review=True` — the row is highlighted in the dashboard. |

## Schema evolution

When you change `TRIAGE_SCHEMA`, the validation layer catches drift automatically:

1. Add a new required field → old LLMs that don't produce it will start raising `TriageSchemaError`. Update the system prompt and the stub provider.
2. Add a new severity value → old triages keep working (Pydantic + jsonschema both treat unknown as additional-properties-allowed by default).
3. Remove a field → existing triages keep the field in the SQLite row as NULL. The dashboard's `to_dict()` handles missing keys.

## Performance notes

- Local Ollama with `llama3.1:8b`: typical triage ~1-3 seconds on M1/M2, depends on prompt length
- Stub provider: ~1ms (no I/O)
- SQLite WAL: hundreds of writes per second on a single connection; the orchestrator is single-threaded but FastAPI runs it on a worker thread per request
- JSONL append: O(1), ~1µs per line

The dashboard refreshes every time the user clicks "Refresh". For live monitoring, the brief's stretch goal #1 (reward hacking analysis) would need a separate process tailing the JSONL.