"""
web_ui/dashboard.py
────────────────────
LIFA-Fuzz Real-Time Web Dashboard — Streamlit-based UI.

Reads live data from the shared filesystem (no API calls to the Fast Loop):
    - shared/raw_traffic.jsonl    → packet/mutation counts
    - shared/active_rules.json    → active SemanticRules
    - crashes/                    → crash PoC artifacts
    - shared/llm_last_inference.json → latest LLM prompt/response

Run:
    streamlit run dashboard.py

Or via Docker:
    docker compose -f sandbox/docker-compose.yml up web_dashboard
    → http://localhost:8501
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATA_DIR = Path(os.environ.get("LIFA_DATA_DIR", "."))
TRAFFIC_LOG = DATA_DIR / "shared" / "raw_traffic.jsonl"
RULES_FILE = DATA_DIR / "shared" / "active_rules.json"
CRASHES_DIR = DATA_DIR / "crashes"
LLM_LOG = DATA_DIR / "shared" / "llm_last_inference.json"

# EPS history buffer (stored in session_state)
EPS_HISTORY_LEN = 120  # ~10 min at 5s refresh

# ---------------------------------------------------------------------------
# Page Config — must be the FIRST Streamlit call
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="LIFA-Fuzz Dashboard",
    page_icon="🔬",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Custom CSS — dark theme polish
# ---------------------------------------------------------------------------

st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #1e1e2e 0%, #2a2a3e 100%);
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        border: 1px solid #3a3a4e;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    .metric-card h2 {
        margin: 0;
        font-size: 2.2rem;
        font-weight: 700;
    }
    .metric-card p {
        margin: 4px 0 0;
        font-size: 0.9rem;
        opacity: 0.7;
    }
    .crash-alert {
        background: linear-gradient(135deg, #4a0000 0%, #6a0000 100%);
        border: 2px solid #ff4444;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        animation: pulse 2s infinite;
    }
    @keyframes pulse {
        0%, 100% { box-shadow: 0 0 8px rgba(255,68,68,0.4); }
        50% { box-shadow: 0 0 20px rgba(255,68,68,0.8); }
    }
    .crash-alert h2 {
        color: #ff6666;
        margin: 0;
        font-size: 2.2rem;
    }
    .crash-alert p {
        color: #ff9999;
        margin: 4px 0 0;
    }
    .status-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .status-running {
        background: #1b5e20;
        color: #69f0ae;
    }
    .status-idle {
        background: #4a4a00;
        color: #ffff00;
    }
    .status-stopped {
        background: #4a0000;
        color: #ff4444;
    }
    div[data-testid="stSidebar"] { display: none; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Data Readers
# ---------------------------------------------------------------------------


def read_traffic_stats() -> dict[str, Any]:
    """Scan the JSONL traffic log and return packet counts."""
    if not TRAFFIC_LOG.exists():
        return {
            "total_packets": 0,
            "total_captured": 0,
            "total_injected": 0,
            "client_packets": 0,
            "server_packets": 0,
            "mutated_packets": 0,
            "latest_timestamp": None,
        }

    total = 0
    captured = 0
    injected = 0
    client_pkts = 0
    server_pkts = 0
    mutated_pkts = 0
    latest_ts: float | None = None

    try:
        with open(TRAFFIC_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    total += 1
                    ts = rec.get("timestamp", 0)
                    if ts and (latest_ts is None or ts > latest_ts):
                        latest_ts = ts

                    if rec.get("is_mutated"):
                        injected += 1
                        mutated_pkts += 1
                    else:
                        captured += 1

                    d = rec.get("direction", "")
                    if "client" in d:
                        client_pkts += 1
                    elif "server" in d:
                        server_pkts += 1

                except json.JSONDecodeError:
                    continue
    except OSError:
        pass

    return {
        "total_packets": total,
        "total_captured": captured,
        "total_injected": injected,
        "client_packets": client_pkts,
        "server_packets": server_pkts,
        "mutated_packets": mutated_pkts,
        "latest_timestamp": latest_ts,
    }


def read_active_rules() -> list[dict]:
    """Load active rules from the shared JSON file."""
    if not RULES_FILE.exists():
        return []
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def read_crash_records() -> list[dict]:
    """Load all crash records from the crashes directory."""
    if not CRASHES_DIR.exists():
        return []
    records = []
    for json_file in sorted(CRASHES_DIR.glob("crash_*.json"), reverse=True):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            data["_source_file"] = json_file.name
            records.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return records


def read_llm_insights() -> dict[str, str]:
    """Read the latest LLM inference log (if available)."""
    if not LLM_LOG.exists():
        return {"prompt": "Waiting for first inference...", "response": ""}
    try:
        return json.loads(LLM_LOG.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"prompt": "Error reading LLM log", "response": ""}


def infer_pipeline_status(stats: dict) -> str:
    """Infer whether the fuzzing pipeline is running based on traffic data."""
    ts = stats.get("latest_timestamp")
    if ts is None:
        return "stopped"
    age = time.time() - ts
    if age < 30:
        return "running"
    elif age < 120:
        return "idle"
    return "stopped"


# ---------------------------------------------------------------------------
# EPS Calculation
# ---------------------------------------------------------------------------


def compute_eps(stats: dict, prev_stats: dict, elapsed_s: float) -> float:
    """Compute current EPS (injections per second)."""
    if elapsed_s <= 0:
        return 0.0
    new_injected = stats["total_injected"] - prev_stats.get("total_injected", 0)
    return new_injected / elapsed_s


# ---------------------------------------------------------------------------
# Dashboard Layout
# ---------------------------------------------------------------------------


def render_header(status: str):
    """Render the dashboard title bar with pipeline status indicator."""
    col1, col2, col3 = st.columns([1, 3, 1])
    with col2:
        st.markdown(
            "<h1 style='text-align: center; color: #00d4ff;'>"
            "🔬 LIFA-Fuzz Dashboard"
            "</h1>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<p style='text-align: center; opacity: 0.5;'>"
            "Live-traffic Inference & Asynchronous Fuzzing Framework"
            "</p>",
            unsafe_allow_html=True,
        )

    status_labels = {
        "running": ("● RUNNING", "status-running"),
        "idle": ("● IDLE", "status-idle"),
        "stopped": ("● STOPPED", "status-stopped"),
    }
    label, css_class = status_labels.get(status, ("● UNKNOWN", "status-idle"))
    st.markdown(
        f"<div style='text-align: center; margin-bottom: 10px;'>"
        f"<span class='status-badge {css_class}'>{label}</span>"
        f"</div>",
        unsafe_allow_html=True,
    )


def render_metrics(stats: dict, rules: list, crashes: list, eps: float):
    """Render the top-level metric cards."""
    crash_count = len(crashes)

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(
            f"<div class='metric-card'>"
            f"<h2 style='color: #00d4ff;'>{eps:.1f}</h2>"
            f"<p>Executions / sec</p>"
            f"</div>",
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"<div class='metric-card'>"
            f"<h2 style='color: #66bb6a;'>{stats['total_packets']:,}</h2>"
            f"<p>Packets Captured</p>"
            f"</div>",
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"<div class='metric-card'>"
            f"<h2 style='color: #ffa726;'>{stats['total_injected']:,}</h2>"
            f"<p>Mutations Injected</p>"
            f"</div>",
            unsafe_allow_html=True,
        )

    with col4:
        st.markdown(
            f"<div class='metric-card'>"
            f"<h2 style='color: #ab47bc;'>{len(rules)}</h2>"
            f"<p>Active Rules</p>"
            f"</div>",
            unsafe_allow_html=True,
        )

    with col5:
        if crash_count > 0:
            st.markdown(
                f"<div class='crash-alert'>"
                f"<h2>💥 {crash_count}</h2>"
                f"<p>Crashes Detected</p>"
                f"</div>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"<div class='metric-card'>"
                f"<h2 style='color: #66bb6a;'>0</h2>"
                f"<p>Crashes Detected</p>"
                f"</div>",
                unsafe_allow_html=True,
            )


def render_eps_chart():
    """Render the real-time EPS line chart."""
    st.subheader("📈 EPS Over Time")

    eps_history = st.session_state.get("eps_history", [])

    if len(eps_history) < 2:
        st.info(
            "Collecting data... EPS chart will appear after a few refresh cycles."
        )
        return

    df = pd.DataFrame(eps_history, columns=["time", "eps"])

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df["time"],
        y=df["eps"],
        mode="lines+markers",
        name="EPS",
        line=dict(color="#00d4ff", width=2),
        fill="tozeroy",
        fillcolor="rgba(0,212,255,0.1)",
    ))

    fig.update_layout(
        height=300,
        margin=dict(l=40, r=20, t=20, b=40),
        xaxis_title="Time",
        yaxis_title="Executions/sec",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#aaa"),
        xaxis=dict(gridcolor="#333"),
        yaxis=dict(gridcolor="#333"),
    )

    st.plotly_chart(fig, use_container_width=True)


def render_crash_table(crashes: list):
    """Render the crash triage table with expandable hex payloads."""
    st.subheader("💥 Crash Triage")

    if not crashes:
        st.info("No crashes detected yet. Fuzzing is running clean! ✅")
        return

    for i, crash in enumerate(crashes):
        ts = crash.get("timestamp", 0)
        try:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
        except (TypeError, ValueError, OSError):
            dt = "unknown"

        exit_code = crash.get("exit_code", "?")
        signal = crash.get("signal", "?")
        rule_id = crash.get("mutation_rule_id", "unknown")
        hex_payload = crash.get("offending_packet_hex", "")

        with st.expander(
            f"🔴 Crash #{len(crashes) - i} — {signal} "
            f"(exit={exit_code}) @ {dt}",
            expanded=(i == 0),  # Expand only the latest crash
        ):
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown(f"**Signal:** `{signal}`")
                st.markdown(f"**Exit Code:** `{exit_code}`")
                st.markdown(f"**Rule ID:** `{rule_id}`")
                st.markdown(f"**Source:** `{crash.get('_source_file', '')}`")
            with col_b:
                st.markdown("**Offending Payload (hex):**")
                st.code(hex_payload, language="hex")

                # Decode ASCII representation for quick visual inspection
                ascii_repr = ""
                for j in range(0, len(hex_payload), 2):
                    if j + 2 > len(hex_payload):
                        break
                    byte_val = int(hex_payload[j:j+2], 16)
                    ascii_repr += chr(byte_val) if 0x20 <= byte_val <= 0x7E else "."
                if ascii_repr:
                    st.markdown("**ASCII:**")
                    st.code(ascii_repr, language="plaintext")


def render_rules_table(rules: list):
    """Render the active SemanticRules table."""
    st.subheader("🧬 Active Semantic Rules")

    if not rules:
        st.info(
            "No active rules. Slow Loop will generate them from traffic analysis."
        )
        return

    # Build a clean table
    rows = []
    for r in rules:
        rows.append({
            "Field": r.get("target_field_name", "?"),
            "Type": r.get("rule_type", "?"),
            "Offset": f"{r.get('offset_start', '?')}-{r.get('offset_end', '?')}",
            "FieldType": r.get("field_type", "?"),
            "Priority": f"{r.get('priority', 0):.2f}",
            "Hits": r.get("hit_count", 0),
            "Crashes": r.get("crash_count", 0),
        })

    df = pd.DataFrame(rows)
    st.dataframe(
        df,
        use_container_width=True,
        height=min(400, 35 * len(rows) + 40),
        column_config={
            "Priority": st.column_config.ProgressColumn(
                min_value=0, max_value=1, format="%.2f"
            ),
        },
    )


def render_llm_insights():
    """Render the latest LLM inference panel."""
    st.subheader("🧠 LLM Insights")

    insights = read_llm_insights()

    col_prompt, col_response = st.columns(2)

    with col_prompt:
        st.markdown("**Latest Prompt (Traffic Sent to LLM):**")
        prompt = insights.get("prompt", "No data yet")
        st.text_area(
            "Prompt",
            value=prompt[:3000],
            height=250,
            disabled=True,
            label_visibility="collapsed",
        )

    with col_response:
        st.markdown("**Latest Response (Inferred Grammar):**")
        response = insights.get("response", "No data yet")
        try:
            # Pretty-print JSON if possible
            parsed = json.loads(response)
            display = json.dumps(parsed, indent=2)
        except (json.JSONDecodeError, TypeError):
            display = response[:3000]

        st.text_area(
            "Response",
            value=display[:3000],
            height=250,
            disabled=True,
            label_visibility="collapsed",
        )


def render_traffic_breakdown(stats: dict):
    """Render a small traffic direction breakdown."""
    st.subheader("📊 Traffic Breakdown")

    labels = ["Client → Server", "Server → Client", "Mutated"]
    values = [
        stats.get("client_packets", 0),
        stats.get("server_packets", 0),
        stats.get("mutated_packets", 0),
    ]
    colors = ["#00d4ff", "#66bb6a", "#ffa726"]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        marker=dict(colors=colors),
        textinfo="label+percent",
        hole=0.4,
    )])
    fig.update_layout(
        height=250,
        margin=dict(l=20, r=20, t=20, b=20),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#aaa"),
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)


def render_footer(stats: dict):
    """Render status footer."""
    latest_ts = stats.get("latest_timestamp")
    if latest_ts:
        try:
            dt = datetime.fromtimestamp(
                latest_ts, tz=timezone.utc
            ).strftime("%H:%M:%S UTC")
            last_seen = f"Last packet: {dt}"
        except (TypeError, ValueError):
            last_seen = "Last packet: unknown"
    else:
        last_seen = "No traffic data yet"

    st.markdown(
        f"<div style='text-align: center; opacity: 0.4; padding-top: 20px;'>"
        f"LIFA-Fuzz Dashboard • {last_seen} • "
        f"Auto-refresh every 5s"
        f"</div>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Main Dashboard Loop
# ---------------------------------------------------------------------------


def main():
    """Streamlit dashboard entry point."""

    # Initialize session state for EPS history
    if "eps_history" not in st.session_state:
        st.session_state.eps_history = []
    if "prev_stats" not in st.session_state:
        st.session_state.prev_stats = {}
    if "last_refresh" not in st.session_state:
        st.session_state.last_refresh = time.monotonic()

    # Read all data sources
    stats = read_traffic_stats()
    rules = read_active_rules()
    crashes = read_crash_records()

    # Compute EPS
    now = time.monotonic()
    elapsed = now - st.session_state.last_refresh
    eps = compute_eps(stats, st.session_state.prev_stats, elapsed)

    # Update EPS history
    ts_label = datetime.now().strftime("%H:%M:%S")
    st.session_state.eps_history.append((ts_label, eps))
    if len(st.session_state.eps_history) > EPS_HISTORY_LEN:
        st.session_state.eps_history = \
            st.session_state.eps_history[-EPS_HISTORY_LEN:]

    # Save state for next cycle
    st.session_state.prev_stats = stats
    st.session_state.last_refresh = now

    # Infer pipeline status
    status = infer_pipeline_status(stats)

    # ── Render ────────────────────────────────────────────────
    render_header(status)
    st.divider()
    render_metrics(stats, rules, crashes, eps)

    st.divider()
    col_chart, col_rules = st.columns([3, 2])

    with col_chart:
        render_eps_chart()

    with col_rules:
        render_rules_table(rules)

    st.divider()

    # Traffic breakdown + LLM side by side
    col_breakdown, col_llm = st.columns([1, 2])

    with col_breakdown:
        render_traffic_breakdown(stats)

    with col_llm:
        render_llm_insights()

    st.divider()
    render_crash_table(crashes)

    render_footer(stats)

    # Auto-refresh every 5 seconds — use st.rerun() scheduled via
    # a Streamlit fragment or the meta-refresh approach.
    # The simplest zero-dependency method is time.sleep + st.rerun(),
    # but we avoid blocking by using st.fragment (Streamlit 1.37+)
    # or fall back to the classic approach.
    time.sleep(5)
    st.rerun()


if __name__ == "__main__":
    main()
