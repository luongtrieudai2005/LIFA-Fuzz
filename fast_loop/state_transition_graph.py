"""
fast_loop/state_transition_graph.py
────────────────────────────────────
Protocol State Transition Graph (STG) Tracker.

Tracks unique protocol state transitions at runtime, treating each
(prev_code, command, new_code) tuple as a "state edge" analogous to
AFL's code-branch edges. When the fuzzer discovers a new edge, the
seed that triggered it is marked as STATE_NOVELTY and receives a
priority boost in the IFPS seed selector.

Design:
    - Lock-free: owned by MutationEngine, accessed only from the
      single asyncio hot loop — no cross-thread contention.
    - O(1) operations: dict/set lookups for edge dedup and seed
      novelty checks.
    - Piggyback EWMA: edges are recorded only when recv() already
      fires (no extra network I/O).
    - FTP-specific: extracts 3-digit status codes and command tokens
      from FTP wire format (RFC 959).

State Edge Definition:
    A state edge is a 3-tuple: (Previous_FTP_Code, Command, New_FTP_Code)
    Example: ("220", "USER", "331"), ("331", "PASS", "230")

Integration Points:
    - MutationEngine._execute_sequence(): prefix responses are already
      read but discarded — captured for STG at zero cost.
    - MutationEngine._send(): piggybacks on _should_recv() gate.
    - MutationEngine._pick_seed(): STATE_NOVELTY seeds get 5x energy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from shared.logger import get_logger

log = get_logger("fast_loop.state_transition_graph")


# =============================================================================
# State Edge — a single protocol state transition
# =============================================================================


@dataclass(frozen=True, slots=True)
class StateEdge:
    """A single protocol state transition.

    Attributes:
        prev_code:  FTP status code BEFORE this command (e.g. "220").
        command:    FTP command keyword sent by client (e.g. "USER").
        new_code:   FTP status code AFTER this command (e.g. "331").
    """

    prev_code: str
    command: str
    new_code: str


# =============================================================================
# State Transition Graph
# =============================================================================


class StateTransitionGraph:
    """Runtime tracker for unique protocol state transitions.

    Maintains:
        - _edges:      dict[edge_key → StateEdge] — all unique edges seen.
        - _paths:      set[path_hash] — unique full-session paths.
        - _states:     set[code] — unique FTP status codes observed.
        - _novel_seeds: set[sequence_id] — seeds that discovered new edges.

    All operations are O(1) amortised (dict/set lookups and insertions).
    No locks needed — single-writer from the asyncio hot loop.
    """

    # Multiplier applied to IFPS energy for STATE_NOVELTY seeds.
    NOVELTY_ENERGY_MULTIPLIER: float = 5.0

    def __init__(self) -> None:
        self._edges: dict[str, StateEdge] = {}
        self._paths: set[str] = set()
        self._states: set[str] = set()
        self._total_edge_records: int = 0
        self._novel_seeds: set[str] = set()
        self._novel_seed_edges: dict[str, str] = {}  # seq_id → first edge key

    # -----------------------------------------------------------------
    # Edge Key — canonical string key for dedup
    # -----------------------------------------------------------------

    @staticmethod
    def make_edge_key(prev_code: str, command: str, new_code: str) -> str:
        """Create a canonical string key for a state edge.

        Format: ``"prev_code|command|new_code"``
        Example: ``"220|USER|331"``
        """
        return f"{prev_code}|{command}|{new_code}"

    # -----------------------------------------------------------------
    # FTP Command Extraction
    # -----------------------------------------------------------------

    @staticmethod
    def extract_ftp_command(payload: bytes) -> str:
        """Extract the FTP command keyword from a client-to-server payload.

        FTP commands are the first whitespace-delimited token on each line:
            ``USER admin\\r\\n`` → ``"USER"``
            ``SYST\\r\\n`` → ``"SYST"``
            ``PORT 127,0,0,1,4,1\\r\\n`` → ``"PORT"``

        For non-FTP or malformed payloads, returns ``"UNKNOWN"``.

        Args:
            payload: Raw bytes sent from client to server.

        Returns:
            Uppercase command keyword string (max 6 chars per RFC 959).
        """
        try:
            text = payload.decode("ascii", errors="replace").split("\r\n")[0]
            cmd = text.split(" ")[0].strip().upper()
            # RFC 959: FTP commands are alphabetic, 3-4 chars (max 6 for
            # extensions like "EPRT", "EPSV").  Reject garbage.
            if cmd.isalpha() and 2 <= len(cmd) <= 6:
                return cmd
        except Exception:
            pass
        return "UNKNOWN"

    # -----------------------------------------------------------------
    # Edge Recording
    # -----------------------------------------------------------------

    def record_edge(
        self,
        prev_code: str,
        command: str,
        new_state_raw,
        sequence_id: str = "",
    ) -> bool:
        """Record a state transition edge.

        Returns ``True`` if this edge has **never been seen before**
        (STATE_NOVELTY), ``False`` if it is a duplicate.

        Side effects:
            - Adds prev_code and new_code to the unique states set.
            - If the edge is novel and sequence_id is non-empty, marks
              that sequence_id as a novel seed for IFPS priority boost.

        Args:
            prev_code:      FTP status code before this command.
            command:        FTP command keyword (from extract_ftp_command).
            new_state_raw:  Raw response bytes (or str code). FTP code is
                            extracted from bytes[:3] for backward compat.
            sequence_id:    SeedSequence ID (for novelty tracking).

        Returns:
            True if this is a new edge, False if already known.
        """
        # Extract FTP status code from raw response bytes (or accept str).
        if isinstance(new_state_raw, bytes):
            new_code = new_state_raw[:3].decode("ascii", errors="replace") if len(new_state_raw) >= 3 else "000"
        else:
            new_code = str(new_state_raw)

        self._total_edge_records += 1
        self._states.add(prev_code)
        self._states.add(new_code)

        key = self.make_edge_key(prev_code, command, new_code)
        is_new = key not in self._edges

        if is_new:
            self._edges[key] = StateEdge(prev_code, command, new_code)
            if sequence_id:
                self._novel_seeds.add(sequence_id)
                if sequence_id not in self._novel_seed_edges:
                    self._novel_seed_edges[sequence_id] = key

        return is_new

    # -----------------------------------------------------------------
    # Path Recording (full session sequences)
    # -----------------------------------------------------------------

    def record_path(
        self,
        edges: list[StateEdge],
        sequence_id: str = "",
    ) -> bool:
        """Record a full protocol session path (ordered sequence of edges).

        A "path" is the concatenation of all edge keys in order.
        Returns ``True`` if this path has never been seen before.

        Args:
            edges:        Ordered list of StateEdge objects forming one session.
            sequence_id:  Optional session identifier for logging.

        Returns:
            True if this is a new path, False if already known.
        """
        if not edges:
            return False

        path_hash = "|".join(
            self.make_edge_key(e.prev_code, e.command, e.new_code)
            for e in edges
        )
        is_new = path_hash not in self._paths
        if is_new:
            self._paths.add(path_hash)
        return is_new

    # -----------------------------------------------------------------
    # Novelty Query (used by _pick_seed)
    # -----------------------------------------------------------------

    def is_novel_seed(self, sequence_id: str) -> bool:
        """Check if a seed discovered a previously-unseen state edge.

        O(1) set membership check — safe to call from the hot loop.

        Args:
            sequence_id: The SeedSequence.sequence_id to check.

        Returns:
            True if this seed found at least one novel edge.
        """
        return sequence_id in self._novel_seeds

    # -----------------------------------------------------------------
    # Stats (for CSV telemetry and coverage_summary)
    # -----------------------------------------------------------------

    @property
    def stats(self) -> dict[str, int]:
        """Return a telemetry-friendly stats dict.

        Keys:
            unique_states:      Number of distinct FTP status codes seen.
            unique_edges:       Number of distinct (code, cmd, code) edges.
            unique_paths:       Number of distinct full-session paths.
            total_edge_records: Total record_edge() calls (including duplicates).
            novel_seed_count:   Number of seeds that found new edges.
        """
        return {
            "unique_states": len(self._states),
            "unique_edges": len(self._edges),
            "unique_paths": len(self._paths),
            "total_edge_records": self._total_edge_records,
            "novel_seed_count": len(self._novel_seeds),
        }

    # -----------------------------------------------------------------
    # Debug / Export
    # -----------------------------------------------------------------

    def get_edges(self) -> list[StateEdge]:
        """Return all recorded edges (for testing and debugging)."""
        return list(self._edges.values())

    def clear_novel_seeds(self) -> None:
        """Clear the novel seed set (for periodic reset if needed)."""
        self._novel_seeds.clear()
        self._novel_seed_edges.clear()
