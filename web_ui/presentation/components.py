"""
web_ui/presentation/components.py
───────────────────────────────────
Streamlit render functions for the LIFA-Fuzz Dashboard.

Each function renders a self-contained section of the dashboard.
HTML templates are loaded from ``templates/`` — edit those .html files
directly to change the layout. No Python changes needed.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from typing import Optional

import pandas as pd
import streamlit as st

from web_ui.logic.readers import (
    BASELINE_ORDER,
    delete_crash_artifacts,
    delete_all_crashes,
    read_llm_insights,
)
from web_ui.presentation.charts import build_eps_chart, build_traffic_breakdown
from web_ui.presentation.templates import load_section, load_template


# ── Helpers ─────────────────────────────────────────────────────────────────

def _section_label(text: str) -> None:
    """Render a section divider label."""
    st.markdown(
        f"<div class='section-label'>{text}</div>",
        unsafe_allow_html=True,
    )


# ── Evaluation Progress ─────────────────────────────────────────────────────

def _format_duration(seconds: float) -> str:
    """Format seconds to compact human-readable duration."""
    if seconds <= 0:
        return "0s"
    s = int(seconds)
    h, remainder = divmod(s, 3600)
    m, sec = divmod(remainder, 60)
    if h > 0:
        return f"{h}h {m}m"
    if m > 0:
        return f"{m}m {sec}s"
    return f"{sec}s"


_GMT7 = timezone(timedelta(hours=7))


def _format_eta(unix_ts: float) -> str:
    """Format a unix timestamp as a local time string for ETA display."""
    try:
        return datetime.fromtimestamp(unix_ts, tz=_GMT7).strftime("%H:%M")
    except (TypeError, ValueError, OSError):
        return "—"


def render_evaluation_progress(eval_state: dict, stats: dict) -> None:
    """Render the Evaluation Campaign progress panel.

    Compact panel showing:
    - Baseline timeline chips (A ✓ / B ▶ / C ⏳)
    - Progress bar for current baseline
    - Elapsed / Remaining / ETA
    - Overall campaign progress

    Auto-hides when no evaluation is running.
    """
    if not eval_state.get("campaign_active"):
        return

    _section_label("📊 Evaluation Campaign")

    baseline_id = eval_state.get("baseline_id", "?")
    baseline_desc = eval_state.get("baseline_description", "")
    total_baselines = eval_state.get("total_baselines", 3)
    baseline_index = eval_state.get("baseline_index", 0)
    progress_pct = eval_state.get("progress_pct", 0)
    remaining_s = eval_state.get("remaining_s", 0)
    elapsed_s = eval_state.get("baseline_elapsed_s", 0)
    eta_current = eval_state.get("eta_current", 0)
    eta_campaign = eval_state.get("eta_campaign", 0)
    overall_pct = eval_state.get("overall_pct", 0)
    total_elapsed_s = eval_state.get("total_elapsed_s", 0)
    target_name = eval_state.get("target", "")
    driver_name = eval_state.get("sandbox_driver", "")

    # ── Header line ───────────────────────────────────────────
    env_parts = []
    if target_name:
        env_parts.append(target_name)
    if driver_name:
        env_parts.append(driver_name)
    env_str = " / ".join(env_parts) if env_parts else ""

    header = f"**Baseline {baseline_id}**: {baseline_desc}"
    if env_str:
        header += f"  —  {env_str}"
    st.markdown(header)

    # ── Baseline timeline chips ───────────────────────────────
    chip_html_parts = []
    baseline_labels = {
        "A": ("A: Random", "#e74c3c"),
        "B": ("B: Math", "#3498db"),
        "C": ("C: Full", "#2ecc71"),
    }

    # FIX: Always show all 3 baseline chips (A, B, C) regardless of
    # total_baselines. Use the actual baseline_id from runtime state
    # to determine which one is currently running.
    for bid in BASELINE_ORDER:
        label, color = baseline_labels.get(bid, (f"Baseline {bid}", "#7a8390"))

        # FIX: Use baseline_id to determine current, not index-based logic
        # which breaks when running baselines one at a time (total_baselines=1)
        bid_order = BASELINE_ORDER.index(bid) if bid in BASELINE_ORDER else 99
        current_order = BASELINE_ORDER.index(baseline_id) if baseline_id in BASELINE_ORDER else 99

        if bid_order < current_order:
            # Completed
            chip_html_parts.append(
                f"<span style='background:{color};color:#fff;padding:3px 10px;"
                f"border-radius:4px;font-size:0.8em;font-weight:600;'>✅ {label}</span>"
            )
        elif bid == baseline_id:
            # Running
            chip_html_parts.append(
                f"<span style='background:{color};color:#fff;padding:3px 10px;"
                f"border-radius:4px;font-size:0.8em;font-weight:600;"
                f"box-shadow:0 0 8px {color}88;'>▶ {label}</span>"
            )
        else:
            # Pending
            chip_html_parts.append(
                f"<span style='background:#272b30;color:#7a8390;padding:3px 10px;"
                f"border-radius:4px;font-size:0.8em;font-weight:600;'>⏳ {label}</span>"
            )

    st.markdown(
        "<div style='display:flex;gap:8px;align-items:center;margin:6px 0;'>"
        + "  ".join(chip_html_parts)
        + "</div>",
        unsafe_allow_html=True,
    )

    # ── Progress bar ──────────────────────────────────────────
    bar_pct = min(100, max(0, progress_pct))
    bar_color = "#4fc3d4" if bar_pct < 50 else ("#5fb86e" if bar_pct < 90 else "#d4963a")

    st.markdown(
        f"""
        <div style='margin:4px 0;'>
            <div style='background:#272b30;border-radius:6px;overflow:hidden;height:20px;'>
                <div style='background:{bar_color};height:100%;width:{bar_pct:.1f}%;
                    transition:width 0.5s;border-radius:6px;'></div>
            </div>
            <div style='display:flex;justify-content:space-between;font-size:0.75em;
                color:#7a8390;margin-top:2px;'>
                <span>{_format_duration(elapsed_s)} elapsed</span>
                <span>{bar_pct:.0f}%</span>
                <span>{_format_duration(remaining_s)} remaining</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Time breakdown row ────────────────────────────────────
    time_parts = [
        f"⏱ ETA: **{_format_eta(eta_current)}**",
        f"Mutations: **{stats.get('total_injected', 0):,}**",
    ]

    # Overall campaign progress
    if total_baselines > 1:
        time_parts.append(
            f"Overall: **{baseline_index + 1}/{total_baselines}** ({overall_pct:.0f}%)"
        )
        time_parts.append(f"Campaign ETA: **{_format_eta(eta_campaign)}**")

    st.markdown("  │  ".join(time_parts))


# ── Header ───────────────────────────────────────────────────────────────────

def render_header(status: str) -> None:
    """Render the dashboard title bar with pipeline status indicator."""
    status_labels = {
        "running": ("● RUNNING", "status-running"),
        "idle":    ("● IDLE",    "status-idle"),
        "stopped": ("● STOPPED", "status-stopped"),
        "error":   ("● ERROR",   "status-stopped"),
    }
    label, css_class = status_labels.get(status, ("● UNKNOWN", "status-idle"))

    # FIX: render header + status badge in ONE st.markdown call so the badge
    # sits inside the header's flex layout instead of floating below it.
    st.markdown(
        load_section(
            "header.html", "complete",
            label=label, css_class=css_class,
        ),
        unsafe_allow_html=True,
    )


# ── Pipeline Status ──────────────────────────────────────────────────────────


def _health_class(alive: Optional[bool]) -> tuple[str, str]:
    """Map a boolean alive status to (card_css_class, dot_css_class)."""
    if alive is None:
        return ("status-unknown", "dot-unknown")
    if alive:
        return ("status-healthy", "dot-healthy")
    return ("status-down", "dot-down")


def _format_uptime(seconds: float) -> str:
    """Format uptime seconds to human-readable string."""
    if seconds <= 0:
        return "0s"
    hours = int(seconds) // 3600
    minutes = (int(seconds) % 3600) // 60
    secs = int(seconds) % 60
    if hours > 0:
        return f"{hours}h {minutes}m"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def render_pipeline_status(pipeline_state: dict) -> None:
    """Render the Pipeline Status panel with 4 component cards.

    Shows Target Server, Client Process, Slow Loop, and Engine Mode
    cards with live health indicators read from runtime_state.json.
    """
    _section_label("Pipeline Status")

    status = pipeline_state.get("pipeline_status", "not_running")

    # ── Pipeline not running ─────────────────────────────────────
    if status in ("not_running", "error"):
        st.markdown(
            load_section("pipeline.html", "not_running"),
            unsafe_allow_html=True,
        )
        return

    # ── Extract component states ─────────────────────────────────
    target = pipeline_state.get("target", {})
    client = pipeline_state.get("client", {})
    slow_loop = pipeline_state.get("slow_loop", {})
    mutator = pipeline_state.get("mutator", {})
    rule_set = pipeline_state.get("rule_set", {})

    # Determine health for each card
    target_cls, target_dot = _health_class(target.get("alive"))
    client_cls, client_dot = _health_class(client.get("alive"))
    sl_cls, sl_dot = _health_class(slow_loop.get("alive"))

    # Engine health: "healthy" when running in any mode (including dumb),
    # "degraded" when running but in a transitional state, "down" when stopped.
    # FIX: dumb mode is a valid normal state, not degraded. Also fix the
    # logic so the engine can show "down" (red) when actually stopped.
    if status == "stopped":
        engine_alive = False
    elif status == "degraded":
        engine_alive = None  # unknown/warning state
    else:
        engine_alive = True  # Any running mode (dumb, random_subset, one_at_a_time, etc.)
    engine_cls, engine_dot = _health_class(engine_alive)

    # ── Card details ─────────────────────────────────────────────
    driver = target.get("sandbox_driver", "?")
    port = target.get("port", "?")
    target_detail = f"{driver} :{port}"
    target_secondary = "alive" if target.get("alive") else "DOWN"

    client_pid = client.get("pid")
    client_detail = f"PID {client_pid}" if client_pid else "N/A"
    client_secondary = "alive" if client.get("alive") else "stopped"

    sl_cycles = slow_loop.get("total_inferences", 0)
    sl_last = slow_loop.get("last_cycle_time", "")
    sl_alive_val = slow_loop.get("alive")
    sl_total_rules = slow_loop.get("total_rules_pushed", 0)

    # Determine display based on actual state:
    # - alive=True + cycles > 0 → "N inferences" + time
    # - alive=True + 0 cycles   → "running" + "active" (in-process, hasn't completed a cycle yet)
    # - alive=None + running pipeline → "in-process" + "active"
    # - alive=False/None + stopped → "idle" + "waiting"
    if sl_cycles > 0:
        sl_detail = f"{sl_cycles} inference{'s' if sl_cycles != 1 else ''}"
        sl_secondary = f"{sl_last[-8:]}" if sl_last and len(sl_last) >= 8 else "active"
    elif sl_alive_val is True or (sl_alive_val is None and status == "running"):
        # Slow Loop is alive but no inference cycle completed yet — show "running"
        sl_detail = f"{sl_total_rules} rules" if sl_total_rules else "running"
        sl_secondary = "active"
    else:
        sl_detail = "idle"
        sl_secondary = "waiting"

    mode = mutator.get("mode", "dumb").upper().replace("_", " ")
    k = mutator.get("k", "?")
    eps = mutator.get("current_eps", 0)
    engine_detail = f"k={k} {mode}"
    engine_secondary = f"{eps:.0f} EPS"
    if mutator.get("investigation_mode"):
        engine_secondary = "🔍 INVESTIGATING"

    # ── Render panel ─────────────────────────────────────────────
    cards = [
        (target_cls, target_dot, "Target Server", target_detail, target_secondary),
        (client_cls, client_dot, "Client Process", client_detail, client_secondary),
        (sl_cls, sl_dot, "Slow Loop", sl_detail, sl_secondary),
        (engine_cls, engine_dot, "Mutation Engine", engine_detail, engine_secondary),
    ]

    # FIX: build the complete panel HTML in one string and render with a
    # single st.markdown() call. The old split pattern (panel_open →
    # st.columns → panel_close) broke because Streamlit injects wrapper
    # divs between the opening and closing tags, leaving the panel empty
    # and the cards floating outside it.

    cards_html = ""
    for s_cls, d_cls, title, detail, secondary in cards:
        cards_html += load_section(
            "pipeline.html", "card",
            status_class=s_cls,
            dot_class=d_cls,
            title=title,
            detail=detail,
            secondary=secondary,
        )

    # ── Summary line ─────────────────────────────────────────────
    uptime = _format_uptime(pipeline_state.get("uptime_seconds", 0))
    unique = pipeline_state.get("unique_crashes", 0)
    total_hits = pipeline_state.get("total_crash_hits", 0)
    rs_version = rule_set.get("version", 0)
    rs_protocol = rule_set.get("protocol_name", "unknown")
    rs_conf = rule_set.get("confidence") or 0  # FIX: handle null → 0
    rs_rules = rule_set.get("total_rules", 0)

    summary_parts = [
        f"{driver}",
        f"Rules v{rs_version} ({rs_protocol}, {rs_conf:.0%})" if rs_version else "No rules yet",
        f"Crashes: {total_hits} ({unique} unique)" if total_hits else "No crashes",
        f"Uptime: {uptime}",
    ]
    summary_line = "  │  ".join(summary_parts)

    st.markdown(
        f"""<div class="pipeline-panel">
  <div class="pipeline-cards">
    {cards_html}
  </div>
  <div class="pipeline-summary">{summary_line}</div>
</div>""",
        unsafe_allow_html=True,
    )


# ── Metric Cards ─────────────────────────────────────────────────────────────

def render_metrics(
    stats: dict,
    rules: list,
    crashes: list,
    eps: float,
    rule_count: int | None = None,
) -> None:
    """Render the top-level metric cards.

    ``rule_count`` is the authoritative active-rule count (see
    ``readers.read_active_rule_count``): when provided it overrides
    ``len(rules)``, so the card reflects the engine's live rule count even
    if the rule file is temporarily unavailable.
    """
    crash_count = len(crashes)
    active_rules = rule_count if rule_count is not None else len(rules)

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(
            load_section("metrics.html", "eps", eps=eps),
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            load_section("metrics.html", "packets", total_packets=stats["total_packets"]),
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            load_section("metrics.html", "mutations", total_injected=stats["total_injected"]),
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            load_section("metrics.html", "rules", rules_count=active_rules),
            unsafe_allow_html=True,
        )
    with col5:
        if crash_count > 0:
            st.markdown(
                load_section("metrics.html", "crashes_alert", crash_count=crash_count),
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                load_section("metrics.html", "crashes_zero"),
                unsafe_allow_html=True,
            )


# ── Charts ────────────────────────────────────────────────────────────────────

def render_eps_chart(eps_history: list) -> None:
    """Render the real-time EPS line chart."""
    _section_label("EPS Over Time")

    # Filter out NaN/inf values
    eps_history = [
        (t, e) for t, e in eps_history
        if isinstance(e, (int, float)) and e == e  # NaN check
    ]

    if len(eps_history) < 2:
        st.info("Collecting data — EPS chart will appear after a few refresh cycles.")
        return

    fig = build_eps_chart(eps_history)
    st.plotly_chart(fig, use_container_width=True)


def render_traffic_breakdown(stats: dict) -> None:
    """Render the traffic direction donut chart."""
    _section_label("Traffic Breakdown")
    fig = build_traffic_breakdown(stats)
    st.plotly_chart(fig, use_container_width=True)


# ── Crash Triage ─────────────────────────────────────────────────────────────

PAGE_SIZE = 20


def _format_timestamp(ts: float) -> str:
    """Safely format a unix timestamp to a human-readable string (GMT+7)."""
    try:
        return datetime.fromtimestamp(ts, tz=_GMT7).strftime(
            "%Y-%m-%d %H:%M:%S GMT+7"
        )
    except (TypeError, ValueError, OSError):
        return "unknown"


def _hex_to_ascii(hex_str: str) -> str:
    """Convert hex string to printable ASCII (non-printable → '.')."""
    result = []
    for i in range(0, len(hex_str), 2):
        if i + 2 > len(hex_str):
            break
        byte_val = int(hex_str[i : i + 2], 16)
        result.append(chr(byte_val) if 0x20 <= byte_val <= 0x7E else ".")
    return "".join(result)


def render_crash_table(crashes: list) -> None:
    """Render compact crash triage table with pagination and delete controls.

    Layout:
        [Crash Triage]               [🗑 Clear All]
        ┌───────────────────────────────────────────┐
        │  # │ Signal  │ Exit │ Time         │ Rule │  ← DataFrame (20 rows)
        └───────────────────────────────────────────┘
        [< Prev]      Page X of Y      [Next >]

        [Select crash to inspect ▼]    [Delete This Crash]
        ┌─ Crash Detail ──────────────────────────────┐
        │  Signal / Exit Code / Rule / Hex / ASCII    │
        └──────────────────────────────────────────────┘
    """
    # ── Header + Clear All button ──────────────────────────────────
    col_title, col_clear = st.columns([5, 1])
    with col_title:
        _section_label(f"Crash Triage  ({len(crashes)} crashes)")
    with col_clear:
        if crashes:
            st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
            if st.button("🗑 Clear All", key="clear_all_crashes"):
                count = delete_all_crashes()
                st.toast(f"Deleted {count} crash artifacts", icon="🗑")

    if not crashes:
        st.info("No crashes detected. Fuzzing is running clean.")
        return

    # ── Pagination state ───────────────────────────────────────────
    total_pages = max(1, (len(crashes) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = st.session_state.get("crash_page", 0)
    if page >= total_pages:
        page = max(0, total_pages - 1)
        st.session_state.crash_page = page

    start = page * PAGE_SIZE
    end = min(start + PAGE_SIZE, len(crashes))
    page_crashes = crashes[start:end]

    # ── Compact DataFrame ──────────────────────────────────────────
    rows = []
    for i, crash in enumerate(page_crashes):
        global_idx = len(crashes) - (start + i)
        ts = crash.get("timestamp", 0)
        rows.append({
            "#": global_idx,
            "Signal": crash.get("signal", "?") or "?",
            "Exit": crash.get("exit_code", "?"),
            "Time": _format_timestamp(ts),
            "Rule ID": crash.get("mutation_rule_id") or "—",
        })

    df = pd.DataFrame(rows)
    st.dataframe(
        df,
        use_container_width=True,
        height=min(400, 35 * len(rows) + 40),
        hide_index=True,
    )

    # ── Pagination controls ────────────────────────────────────────
    col_prev, col_info, col_next = st.columns([1, 2, 1])
    with col_prev:
        if st.button("◀ Previous", disabled=(page == 0), key="crash_prev"):
            st.session_state.crash_page = max(0, page - 1)
            st.session_state.selected_crash_idx = None
            st.rerun()
    with col_info:
        st.markdown(
            f"<div style='text-align:center;padding-top:4px;opacity:0.7'>"
            f"Page {page + 1} of {total_pages}  ·  Showing #{len(crashes) - start}"
            f"–#{len(crashes) - end + 1}</div>",
            unsafe_allow_html=True,
        )
    with col_next:
        if st.button("Next ▶", disabled=(page >= total_pages - 1), key="crash_next"):
            st.session_state.crash_page = page + 1
            st.session_state.selected_crash_idx = None
            st.rerun()

    # ── Detail-on-demand selector ──────────────────────────────────
    crash_labels = [
        f"#{len(crashes) - (start + i)}  ·  {c.get('signal', '?')}  ·  "
        f"exit={c.get('exit_code', '?')}  ·  {_format_timestamp(c.get('timestamp', 0))}"
        for i, c in enumerate(page_crashes)
    ]

    selected = st.selectbox(
        "Select crash to inspect",
        options=range(len(crash_labels)),
        format_func=lambda idx: crash_labels[idx],
        key="crash_detail_selector",
    )

    if selected is not None:
        crash = page_crashes[selected]
        signal = crash.get("signal", "?") or "?"
        exit_code = crash.get("exit_code", "?")
        rule_id = crash.get("mutation_rule_id") or "unknown"
        hex_payload = crash.get("offending_packet_hex", "")

        with st.expander(
            f"Crash Detail — {signal} (exit={exit_code})", expanded=True
        ):
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown(f"**Signal:** `{signal}`")
                st.markdown(f"**Exit Code:** `{exit_code}`")
                st.markdown(f"**Rule ID:** `{rule_id}`")
                st.markdown(f"**Source:** `{crash.get('_source_file', '')}`")
            with col_b:
                if hex_payload:
                    st.markdown("**Offending Payload (hex)**")
                    st.code(hex_payload, language="hex")
                    ascii_repr = _hex_to_ascii(hex_payload)
                    if ascii_repr:
                        st.markdown("**ASCII**")
                        st.code(ascii_repr, language="plaintext")
                else:
                    st.markdown("**Offending Payload:** _(no payload captured)_")

            # Per-crash delete
            if st.button("🗑 Delete This Crash", key="delete_single_crash"):
                source = crash.get("_source_file", "")
                if source and delete_crash_artifacts(source):
                    st.toast("Crash deleted", icon="🗑")
                    st.session_state.selected_crash_idx = None
                    st.rerun()


# ── Rules Table ───────────────────────────────────────────────────────────────

def render_rules_table(rules: list) -> None:
    """Render the active SemanticRules table."""
    _section_label("Active Semantic Rules")

    if not rules:
        st.info("No active rules. Slow Loop will generate them from traffic analysis.")
        return

    rows = []
    for r in rules:
        rows.append({
            "Field":     r.get("target_field_name", "?"),
            "Type":      r.get("rule_type", "?"),
            "Offset":    f"{r.get('offset_start', '?')}-{r.get('offset_end', '?')}",
            "FieldType": r.get("field_type", "?"),
            "Priority":  f"{max(0, min(1, float(r.get('priority', 0)))):.2f}",
            "Hits":      r.get("hit_count", 0),
            "Crashes":   r.get("crash_count", 0),
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


# ── LLM Insights ─────────────────────────────────────────────────────────────

def render_llm_insights() -> None:
    """Render the latest LLM inference panel."""
    _section_label("LLM Insights")

    insights = read_llm_insights()

    col_prompt, col_response = st.columns(2)

    with col_prompt:
        st.markdown("**Prompt sent to LLM**")
        prompt = insights.get("prompt", "No data yet")
        st.text_area(
            "Prompt",
            value=prompt[:3000],
            height=250,
            disabled=True,
            label_visibility="collapsed",
        )

    with col_response:
        st.markdown("**Inferred Grammar Response**")
        response = insights.get("response", "No data yet")
        try:
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


# ── Footer ────────────────────────────────────────────────────────────────────

def render_footer(stats: dict) -> None:
    """Render status footer."""
    latest_ts = stats.get("latest_timestamp")
    if latest_ts:
        try:
            dt = datetime.fromtimestamp(
                latest_ts, tz=_GMT7
            ).strftime("%H:%M:%S GMT+7")
            last_seen = f"Last packet: {dt}"
        except (TypeError, ValueError):
            last_seen = "Last packet: unknown"
    else:
        last_seen = "No traffic data yet"

    st.markdown(
        load_template("footer.html", last_seen=last_seen),
        unsafe_allow_html=True,
    )