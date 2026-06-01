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
    """Build the traffic direction donut chart.

    Uses ``total_injected`` (from mutator via runtime_state.json) as the
    mutation count since MutationEngine sends directly to target — the
    traffic log only captures Interceptor-relayed packets.

    Args:
        stats: Traffic stats dict from ``readers.read_traffic_stats()``.

    Returns:
        Plotly Figure ready for ``st.plotly_chart()``.
    """
    # FIX: compute disjoint traffic categories.
    # client_packets = all C2S from traffic log (includes mutated)
    # server_packets = all S2C from traffic log
    # mutated = injected by mutator (bypasses interceptor)
    # For a meaningful donut, show: (C2S legitimate) | (S2C) | (Mutated)
    total_c2s = stats.get("client_packets", 0)
    total_s2c = stats.get("server_packets", 0)
    mutated = max(
        stats.get("mutated_packets", 0),
        stats.get("total_injected", 0),
    )
    # Subtract mutated from C2S to avoid double-counting
    legitimate_c2s = max(0, total_c2s - stats.get("mutated_packets", 0))
    labels = ["Client → Server", "Server → Client", "Mutated"]
    values = [
        legitimate_c2s,
        total_s2c,
        mutated,
    ]
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