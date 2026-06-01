"""
web_ui/app.py
─────────────
LIFA-Fuzz Dashboard — entry point and layout orchestration.

This is the main file to run:
    streamlit run web_ui/app.py

Or via Docker:
    docker compose -f sandbox/docker-compose.yml up web_dashboard
    → http://localhost:8501
"""

from __future__ import annotations

import time
from datetime import datetime

import streamlit as st

from web_ui.logic.readers import (
    EPS_HISTORY_LEN,
    compute_eps,
    infer_pipeline_status,
    read_active_rules,
    read_crash_records,
    read_evaluation_state,
    read_pipeline_status,
    read_traffic_stats,
)
from web_ui.presentation.components import (
    render_crash_table,
    render_eps_chart,
    render_evaluation_progress,
    render_footer,
    render_header,
    render_llm_insights,
    render_metrics,
    render_pipeline_status,
    render_rules_table,
    render_traffic_breakdown,
)
from web_ui.presentation.styles import load_css


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
# Load CSS
# ---------------------------------------------------------------------------

st.markdown(load_css(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Main Dashboard Loop
# ---------------------------------------------------------------------------


def main() -> None:
    """Streamlit dashboard entry point."""

    # Initialize session state for EPS history
    if "eps_history" not in st.session_state:
        st.session_state.eps_history = []
    if "prev_stats" not in st.session_state:
        st.session_state.prev_stats = {}
    if "last_refresh" not in st.session_state:
        st.session_state.last_refresh = time.monotonic()

    # Initialize session state for crash pagination
    if "crash_page" not in st.session_state:
        st.session_state.crash_page = 0
    if "selected_crash_idx" not in st.session_state:
        st.session_state.selected_crash_idx = None

    # Read all data sources
    stats = read_traffic_stats()
    rules = read_active_rules()
    crashes = read_crash_records()
    pipeline_state = read_pipeline_status()
    eval_state = read_evaluation_state()

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
    render_evaluation_progress(eval_state, stats)
    render_pipeline_status(pipeline_state)
    st.divider()
    render_metrics(stats, rules, crashes, eps)

    st.divider()
    col_chart, col_rules = st.columns([3, 2])

    with col_chart:
        render_eps_chart(st.session_state.eps_history)

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

    # Auto-refresh every 5 seconds
    time.sleep(5)
    st.rerun()


if __name__ == "__main__":
    main()
