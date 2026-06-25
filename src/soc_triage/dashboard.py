"""Streamlit dashboard for the SOC triage assistant.

Reads from the same SQLite + JSONL the server writes to. Operator view:
- Live feed of incoming alerts (pulled from the configured alert source)
- Triage results with markdown rendering
- Kill switch button
- Confidence histogram, severity breakdown, MITRE ATT&CK heatmap
- Feedback buttons (thumbs up/down)
- Few-shot prompt bank viewer
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

# Allow `streamlit run src/soc_triage/dashboard.py` to import soc_triage
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent.parent))

from soc_triage.kill_switch import KillSwitch  # noqa: E402
from soc_triage.renderer import render_markdown, render_slack, render_teams  # noqa: E402
from soc_triage.store import TriageStore  # noqa: E402


st.set_page_config(
    page_title="SOC Triage Assistant",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_resource
def get_store() -> TriageStore:
    data_dir = Path(os.environ.get("SOC_TRIAGE_DATA", "./data"))
    return TriageStore(
        db_path=data_dir / "triage.db",
        jsonl_path=data_dir / "triage.jsonl",
    )


@st.cache_resource
def get_kill_switch() -> KillSwitch:
    data_dir = Path(os.environ.get("SOC_TRIAGE_DATA", "./data"))
    return KillSwitch(data_dir=data_dir)


def main() -> None:
    st.title("🛡️ SOC Triage Assistant")
    st.caption("Read-only LLM triage · kill switch armed means no AI runs")

    store = get_store()
    kill_switch = get_kill_switch()

    # ---- sidebar -----------------------------------------------------
    st.sidebar.header("Controls")
    if kill_switch.is_armed():
        st.sidebar.error("🛑 KILL SWITCH ARMED — triage is passthrough")
        if st.sidebar.button("Disarm kill switch"):
            kill_switch.disarm(source="dashboard", operator="operator")
            st.cache_resource.clear()
            st.rerun()
    else:
        if st.sidebar.button("Arm kill switch"):
            kill_switch.arm(source="dashboard", operator="operator", reason="manual arm from dashboard")
            st.cache_resource.clear()
            st.rerun()

    if st.sidebar.button("Refresh"):
        st.cache_resource.clear()
        st.rerun()

    limit = st.sidebar.slider("Recent rows to show", min_value=10, max_value=500, value=50)

    # ---- top stats ---------------------------------------------------
    total = store.count_triage()
    triaged = store.count_triage(status="triaged")
    errors = store.count_triage(status="error")
    skipped = store.count_triage(status="skipped_kill_switch")
    feedback_stats = store.feedback_stats()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total triages", total)
    col2.metric("Triaged", triaged)
    col3.metric("Errors", errors)
    col4.metric("Skipped (kill switch)", skipped)

    if total:
        col1, col2, col3 = st.columns(3)
        col1.metric("Error rate", f"{(errors/total)*100:.1f}%")
        if feedback_stats:
            up = feedback_stats.get("up", 0)
            down = feedback_stats.get("down", 0)
            if up + down:
                col2.metric("Analyst 👍", up)
                col3.metric("Analyst 👎", down)

    if total == 0:
        st.info("No triages yet. Start the API server and POST some alerts to /triage.")
        st.stop()

    # ---- charts ------------------------------------------------------
    st.subheader("Severity distribution")
    sev = store.severity_counts()
    if sev:
        df = pd.DataFrame([{"severity": k, "count": v} for k, v in sev.items()])
        # Order severities correctly
        order = ["low", "medium", "high", "critical", "unknown"]
        df["severity"] = pd.Categorical(df["severity"], categories=order, ordered=True)
        df = df.sort_values("severity")
        fig = px.bar(df, x="severity", y="count", color="severity", title="Triages by severity")
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Confidence histogram")
    hist = store.confidence_histogram(buckets=10)
    if hist:
        df = pd.DataFrame(hist)
        df["confidence_pct"] = (df["bucket"] / 10 * 100).round().astype(int)
        fig = px.bar(df, x="confidence_pct", y="n", title="LLM confidence distribution (each bucket = 10%)")
        st.plotly_chart(fig, use_container_width=True)
        # Mark the 60% threshold (bucket 6)
        st.caption("Alert: bucket 6 = 60% threshold — anything below is flagged for human review.")

    st.subheader("MITRE ATT&CK technique frequency")
    mitre = store.mitre_counts()
    if mitre:
        df = pd.DataFrame([{"technique": k, "count": v} for k, v in sorted(mitre.items(), key=lambda x: -x[1])])
        fig = px.bar(df, x="technique", y="count", title="Top MITRE techniques in triaged alerts")
        st.plotly_chart(fig, use_container_width=True)

    # ---- recent events ----------------------------------------------
    st.subheader(f"Recent triage records (last {limit})")
    rows = store.fetch_all(limit=limit)
    if not rows:
        st.info("No matching events.")
    else:
        df = pd.DataFrame([
            {
                "ID": r["id"],
                "Time": r["ts"],
                "Host": r["host"],
                "Source IP": r["src_ip"],
                "Event Type": r["event_type"],
                "Severity": r["severity"],
                "Confidence": f"{(r.get('confidence') or 0)*100:.0f}%",
                "Status": r["triage_status"],
                "Needs review": "✓" if r.get("needs_human_review") else "",
            }
            for r in rows
        ])
        st.dataframe(df, use_container_width=True, hide_index=True)

        # ---- detail view ------------------------------------------------
        st.subheader("Detail view")
        ids = [r["id"] for r in rows]
        chosen = st.selectbox("Pick a triage record to inspect", ids, index=0)
        if chosen is not None:
            rec = next((r for r in rows if r["id"] == chosen), None)
            if rec:
                col_md, col_slack = st.columns(2)
                with col_md:
                    st.markdown("**Markdown (for dashboard / GitHub):**")
                    st.markdown(render_markdown(rec))
                with col_slack:
                    st.markdown("**Slack mrkdwn:**")
                    st.code(render_slack(rec), language="markdown")

                # Feedback buttons
                st.markdown("**Analyst feedback:**")
                fbc1, fbc2, fbc3 = st.columns(3)
                with fbc1:
                    if st.button("👍 Helpful triage"):
                        store.insert_feedback(chosen, "up", operator="dashboard")
                        store.add_to_prompt_bank(
                            alert_type=rec.get("event_type", ""),
                            prompt_text=str({"summary": rec.get("summary", ""),
                                            "severity": rec.get("severity", ""),
                                            "next_steps": rec.get("next_steps", []),
                                            "confidence": rec.get("confidence", 0.5),
                                            "mitre_attack": rec.get("mitre_attack", []),
                                            "rationale": rec.get("rationale", "")}),
                            source_triage_id=chosen,
                        )
                        st.success("Recorded 👍 and added to prompt bank.")
                with fbc2:
                    if st.button("👎 Wrong / not helpful"):
                        store.insert_feedback(chosen, "down", operator="dashboard")
                        st.warning("Recorded 👎. The triage was not added to the prompt bank.")
                with fbc3:
                    existing_fb = store.feedback_for(chosen)
                    if existing_fb:
                        st.markdown("**Existing feedback:**")
                        for f in existing_fb:
                            verdict = f["verdict"]
                            emoji = "👍" if verdict == "up" else "👎"
                            st.write(f"{emoji} {verdict} — {f.get('comment', '')} ({f.get('operator', '')})")

    # ---- kill switch audit ------------------------------------------
    st.subheader("Kill-switch audit log")
    history = kill_switch.history()
    if history:
        df = pd.DataFrame(history)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.caption("No kill-switch events yet.")


if __name__ == "__main__":
    main()