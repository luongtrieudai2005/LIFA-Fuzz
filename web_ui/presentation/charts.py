"""
web_ui/presentation/charts.py
──────────────────────────────
Plotly figure builders for the LIFA-Fuzz Dashboard.

NO Streamlit dependency — these functions return ``go.Figure`` objects
rendered by ``components.py`` via ``st.plotly_chart()``.
"""

from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.graph_objects as go

# Design system colors (mirrors CSS variables)
_BG_BASE      = "rgba(0,0,0,0)"
_BG_SURFACE   = "#141618"
_GRID         = "#272b30"
_TEXT_DIM     = "#7a8390"
_CYAN         = "#4fc3d4"
_GREEN        = "#5fb86e"
_AMBER        = "#d4963a"

_FONT = dict(family="IBM Plex Mono, monospace", color=_TEXT_DIM, size=11)

_AXIS_COMMON = dict(
    gridcolor=_GRID,
    linecolor=_GRID,
    tickfont=_FONT,
    title_font=_FONT,
    zeroline=False,
)

_LAYOUT_BASE = dict(
    paper_bgcolor=_BG_BASE,
    plot_bgcolor=_BG_BASE,
    font=_FONT,
    margin=dict(l=44, r=16, t=16, b=40),
    legend=dict(
        bgcolor="rgba(0,0,0,0)",
        bordercolor=_GRID,
        borderwidth=1,
        font=_FONT,
    ),
)


def build_eps_chart(eps_history: list[tuple[str, float]]) -> go.Figure:
    """Build the real-time EPS line chart.

    Args:
        eps_history: List of (time_label, eps_value) tuples.

    Returns:
        Plotly Figure ready for ``st.plotly_chart()``.
    """
    df = pd.DataFrame(eps_history, columns=["time", "eps"])

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df["time"],
        y=df["eps"],
        mode="lines+markers",
        name="EPS",
        line=dict(color=_CYAN, width=1.5),
        marker=dict(color=_CYAN, size=3),
        fill="tozeroy",
        fillcolor="rgba(79,195,212,0.07)",
    ))

    fig.update_layout(
        height=240,
        xaxis=dict(title="Time", **_AXIS_COMMON),
        yaxis=dict(title="Exec/sec", **_AXIS_COMMON),
        showlegend=False,
        **_LAYOUT_BASE,
    )

    return fig


def build_traffic_breakdown(stats: dict[str, Any]) -> go.Figure:
    """Build the traffic direction donut chart with response breakdown.

    Shows accepted/rejected/timeout/crash response categories from the
    mutator's response-aware sending, plus normal traffic categories.

    Args:
        stats: Traffic stats dict from ``readers.read_traffic_stats()``.

    Returns:
        Plotly Figure ready for ``st.plotly_chart()``.
    """
    # Response breakdown from mutator (via runtime_state.json)
    accepted = stats.get("total_accepted", 0)
    rejected = stats.get("total_rejected", 0)
    timeout = stats.get("total_timeout", 0)
    crash = stats.get("total_crashes", 0)
    total_c2s = stats.get("client_packets", 0)
    total_s2c = stats.get("server_packets", 0)

    # FIX: the response outcomes (Accepted/Rejected/Timeout/Crash) and the
    # traffic-direction counts (C2S/S2C) are TWO DIFFERENT populations — the
    # former are outcomes of injected mutations, the latter are raw captured
    # packets from the log. Mixing them in one pie made every percent
    # meaningless (e.g. a 90% acceptance rate showed as ~53% because 1000
    # outcomes were diluted with 700 direction packets). When we have response
    # data, show ONLY the mutation-outcome distribution so each percent is a
    # real acceptance/rejection rate.
    has_response_data = accepted + rejected + timeout + crash > 0

    if has_response_data:
        labels = ["✓ Accepted", "✗ Rejected", "⏱ Timeout", "💥 Crash"]
        values = [accepted, rejected, timeout, crash]
        colors = ["#5fb86e", "#e74c3c", "#d4963a", "#9b59b6"]
    else:
        # Fallback: no response data yet — direction breakdown is coherent
        # here because all three slices are traffic-log populations.
        mutated = max(
            stats.get("mutated_packets", 0),
            stats.get("total_injected", 0),
        )
        legitimate_c2s = max(0, total_c2s - stats.get("mutated_packets", 0))
        labels = ["Client → Server", "Server → Client", "Mutated"]
        values = [legitimate_c2s, total_s2c, mutated]
        colors = [_CYAN, _GREEN, _AMBER]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        marker=dict(
            colors=colors,
            line=dict(color=_GRID, width=2),
        ),
        textinfo="label+percent",
        textfont=dict(family="IBM Plex Mono, monospace", size=10, color="#d4d8dc"),
        hole=0.45,
        hovertemplate="%{label}: %{value:,} (%{percent})<extra></extra>",
    )])

    fig.update_layout(
        height=220,
        margin=dict(l=16, r=16, t=16, b=16),
        paper_bgcolor=_BG_BASE,
        font=_FONT,
        showlegend=True,
        legend=dict(
            orientation="v",
            x=1.02, y=0.5,
            bgcolor="rgba(0,0,0,0)",
            font=dict(family="IBM Plex Mono, monospace", size=10, color=_TEXT_DIM),
        ),
    )

    return fig