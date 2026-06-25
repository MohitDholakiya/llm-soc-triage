# Ethics & Responsible Use

This project is a **defensive** tool. It exists to help SOC teams (and learners) understand the read-only pattern for AI-in-the-SOC-loop. It is not, and never has been, intended as an offensive tool.

## What this project does

- Simulates an LLM-powered SOC triage assistant
- **NEVER takes action** against any system — only reads alerts and writes triage notes to its own local store
- Provides a kill switch that drops the AI out of the loop instantly
- Logs every state change with timestamp + source + reason

## What this project does NOT do

- It does not execute any `next_steps` it recommends. The recommendations are text for a human analyst to read and act on (or not).
- It does not acknowledge, dismiss, close, or modify alerts in the source SIEM. Alert sources use only GET endpoints.
- It does not generate attack payloads or exploit code.
- It does not exfiltrate alert data anywhere. All triage records are stored locally.
- It does not call any LLM by default. The stub provider is deterministic and produces plausible-looking output for development.

## Why "read-only" matters

The brief calls out the read-only pattern explicitly: "Wire a local LLM into your SIEM / log pipeline. It summarises alerts, suggests next steps, and writes a draft incident note — but never takes action on its own."

This pattern matters because:

1. **Compliance.** Compliance teams are starting to require AI to be deployed in read-only roles. The pattern here matches that posture.
2. **Reversibility.** If the LLM hallucinates a bad recommendation, the worst case is a misleading note. No system was actually modified. The analyst reads the note, decides it's wrong, and moves on.
3. **Audit.** Every triage is a logged event with the input alert, the LLM output, the schema-validation result, the confidence score, and the kill-switch state at the time. If something goes wrong, you have a full record.

## If you deploy this in a real environment

You accept responsibility for:

- The credentials you put in the configuration (Wazuh API token, Elastic API key, OpenAI API key for hosted endpoints). Use **read-only / sandbox** credentials only. Never production.
- The model's recommendations. The orchestrator never executes them, but a tired analyst at 3am might paste a `next_steps` block into a runbook without reading it. Train your team that **the LLM is a starting point, not an authority**.
- The kill-switch state. Arm it whenever you're not actively monitoring the dashboard.
- The feedback data. The 👍/👎 verdicts are training signal for the prompt bank — if a verdict is wrong, the next triage of that alert type will inherit that wrong signal. Periodically audit the prompt bank.

## Reporting issues

If you find a prompt pattern that bypasses the schema validation or causes the kill switch to behave unexpectedly, open an issue or PR on this repo. The brief explicitly calls out "investigate reward hacking: does the model start gaming the 👍/👎 signal?" — if you observe this in practice, that's exactly the kind of finding worth publishing.

## License

MIT. See `LICENSE`. No warranty. Authors not liable for misuse.

— Mohit Dholakiya, 2026