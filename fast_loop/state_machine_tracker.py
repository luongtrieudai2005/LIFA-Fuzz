"""
fast_loop/state_machine_tracker.py
──────────────────────────────────
InferredStateTracker — generic Fast Loop state tracker from a P-PSM (Tầng 3).

Reads shared/state_machine.json (written by Slow Loop's StateMachineInferer)
and labels each response packet with the P-PSM's nearest medoid state type.
Tracks unique (prev_state, label, new_state) edges — analogous to the FTP STG
but PROTOCOL-AGNOSTIC (no hardcoded status codes or command keywords).

This is the generic replacement for FTPStateTracker: with NullModule, the
fuzzer still tracks state transitions for ANY protocol whose traffic was
captured → StateMachineInferer inferred a P-PSM → InferredStateTracker reads it.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

from shared.logger import get_logger

log = get_logger("fast_loop.state_machine_tracker")

_SM_PATH = Path("shared/state_machine.json")
_READ_INTERVAL = 100  # re-read file every N labels (cheap hot-loop check)


class InferredStateTracker:
    """Generic state tracker backed by an inferred P-PSM.

    Reads shared/state_machine.json periodically. For each response packet,
    labels it with the P-PSM's nearest medoid → state index. Records unique
    (prev_state, packet_label, new_state) edges — analogous to FTP STG edges
    but protocol-agnostic.

    Attributes:
        _psm: the loaded ProbabilisticStateMachine (or None if no file yet).
        _states: set of state indices seen.
        _edges: dict[edge_key → True] for unique edges.
        _total_edges: total record_edge calls (including duplicates).
        _novel_seeds: dict[seq_id → first edge key].
        _label_counter: for periodic file re-read.
        _last_file_mtime: to avoid re-reading unchanged file.
    """

    def __init__(self) -> None:
        self._psm: Any = None  # ProbabilisticStateMachine
        self._states: set[int] = set()
        self._edges: dict[str, bool] = {}
        self._total_edges: int = 0
        self._novel_seeds: dict[str, str] = {}
        self._label_counter: int = 0
        self._last_mtime: float = 0.0
        self._maybe_reload()

    def _maybe_reload(self) -> None:
        """Re-read shared/state_machine.json if it changed."""
        try:
            if not _SM_PATH.exists():
                return
            mtime = _SM_PATH.stat().st_mtime
            if mtime <= self._last_mtime:
                return  # unchanged
            self._last_mtime = mtime
            from slow_loop.state_machine_inferer import ProbabilisticStateMachine

            data = json.loads(_SM_PATH.read_text())
            self._psm = ProbabilisticStateMachine.from_dict(data)
            log.info(
                f"InferredStateTracker: loaded P-PSM "
                f"({self._psm.n_states} states, "
                f"{len(self._psm.transitions)} transitions)"
            )
        except Exception as e:
            log.debug(f"InferredStateTracker: reload failed: {e}")

    def record_edge(
        self,
        prev_state: Any,
        label: str,
        new_state_raw: bytes,
        sequence_id: str = "",
    ) -> bool:
        """Record a state transition edge.

        Args:
            prev_state:   previous state index (int) or "init" string.
            label:        packet label (command/payload identifier — generic).
            new_state_raw: the raw response bytes to label.
            sequence_id:  session ID for novelty tracking.

        Returns:
            True if this edge is novel (never seen before).
        """
        if self._label_counter % _READ_INTERVAL == 0:
            self._maybe_reload()
        self._label_counter += 1

        if self._psm is None or self._psm.n_states == 0:
            return False  # no P-PSM loaded — can't track

        new_state = self._psm.label_packet(new_state_raw)
        if new_state is None:
            return False  # "unknown" state (data packet, too far from medoids)

        # Normalize prev_state to int (or -1 for init)
        prev_idx = prev_state if isinstance(prev_state, int) else -1
        self._states.add(new_state)

        edge_key = f"{prev_idx}|{label[:8]}|{new_state}"
        self._total_edges += 1
        is_new = edge_key not in self._edges
        if is_new:
            self._edges[edge_key] = True
            if sequence_id and sequence_id not in self._novel_seeds:
                self._novel_seeds[sequence_id] = edge_key

        return is_new

    @property
    def stats(self) -> dict[str, int]:
        return {
            "unique_states": len(self._states),
            "unique_edges": len(self._edges),
            "unique_paths": 0,  # not tracked in Phase 1
            "total_edge_records": self._total_edges,
            "novel_seed_count": len(self._novel_seeds),
        }

    def is_novel_seed(self, sequence_id: str) -> bool:
        return sequence_id in self._novel_seeds
