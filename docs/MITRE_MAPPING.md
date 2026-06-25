# MITRE ATT&CK Mapping Notes

This doc explains how the assistant maps alerts to MITRE ATT&CK technique IDs, and what to do with the output.

## What the model produces

The `mitre_attack` field in the triage output is a JSON array of strings like `["T1110", "T1190"]`. Each ID is a 4-digit MITRE ATT&CK technique code.

The stub provider covers the most common ones:

| ID | Name | When the stub emits it |
|---|---|---|
| T1110 | Brute Force | ssh_brute_force, ssh_failed_login, vpn_brute_force |
| T1190 | Exploit Public-Facing Application | sql_injection_attempt, web exploits |
| T1046 | Network Service Discovery | port_scan |

LLM-backed providers (Ollama, vLLM) can identify a much wider range. The schema allows any string matching `^T\d{4}$` — the regex validates format but the orchestrator does not look up the technique name. (Doing that lookup would require bundling the STIX bundle, which is 50MB+.)

## Verifying the output

The model's self-attribution of techniques can be wrong. Always verify before using it for:

- ATT&CK Navigator exports
- Threat intel reports
- Compliance evidence

The orchestrator records the model's claim in the `mitre_attack` field verbatim. The analyst's job is to confirm.

## Adding technique coverage to the stub

To teach the stub provider a new pattern, edit `src/soc_triage/llm_provider.py`:

```python
def _call_raw(self, prompt: str, system: str) -> str:
    t = prompt.lower()
    if "your_pattern_here" in t:
        return json.dumps({
            "summary": "...",
            "severity": "...",
            "next_steps": [...],
            "confidence": 0.85,
            "mitre_attack": ["Txxxx"],
            "rationale": "...",
        })
    # ... existing patterns
```

Run the test suite to confirm the new pattern still validates against the schema.

## Stretch goal: ATT&CK Navigator export

The brief lists "Add MITRE ATT&CK mapping suggestions and a one-click ATT&CK navigator export" as a stretch goal. The implementation path:

1. Add a `/attack-navigator-layer` endpoint that returns the current triages' MITRE techniques in the [ATT&CK Navigator layer JSON format](https://mitre-attack.github.io/attack-navigator/docs/Usage/Layers/)
2. Add a button to the dashboard that calls the endpoint and downloads the layer as `layer.json`
3. The user opens the file in [attack-navigator.vercel.app](https://attack-navigator.vercel.app) (or their own Navigator deployment)

This is a ~50-line addition to `server.py` and `dashboard.py`. I left it as a stretch because it depends on which techniques are actually being detected — premature to ship the export endpoint before the model is producing useful output.