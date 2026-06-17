"""
fast_loop/baseline_tracker.py
─────────────────────────────
ResponseBaselineTracker — the differential-baseline oracle's memory (Phase 3).

A structural violation SHOULD change the server's response. This tracker
records the response signatures a command NORMALLY gets (from accepted,
non-violation sends) and lets the oracle ask: "did the violation's response
look indistinguishable from a normal one for this command/state?" If yes,
the server failed to validate the violation ⇒ a potential semantic bug.

NO RFC is used. The baseline is purely behavioural (observed replies). The
key is ``(command, prev_state)`` — the same dimensions the
StateTransitionGraph already keys on — and the signature comes from
``ProtocolModule.response_signature``. This is what makes the oracle
protocol-agnostic and ground-truth-free.

Thread-safety: appended to from the hot loop (single asyncio task), read by
the same task — no lock needed.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Optional


class ResponseBaselineTracker:
    """Records normal response signatures per (command, state) and answers
    whether a given signature is "baseline" (normal-looking) for that key."""

    def __init__(self, max_per_key: int = 32) -> None:
        # key (tuple) -> set of normal response signatures seen.
        self._baselines: dict[tuple, set[str]] = defaultdict(set)
        self._max_per_key = max_per_key  # cap to bound memory per command

    def make_key(
        self,
        module: Any,
        payload: bytes,
        prev_state_code: Optional[str],
    ) -> Optional[tuple]:
        """Build the (command, prev_state) key from a payload.

        Returns None if the module exposes no command/state (then the
        tracker can't bucket — caller skips the oracle for this send).
        """
        try:
            cmd = module.extract_command(payload) if module else ""
        except Exception:
            cmd = ""
        state = prev_state_code or ""
        if not cmd and not state:
            return None
        return (cmd, state)

    def signature(self, module: Any, response: bytes, payload: bytes) -> str:
        try:
            return module.response_signature(response, payload)
        except Exception:
            # Fall back to a coarse identity if the module fails.
            return response[:8].hex() if response else "empty"

    def record(self, key: Optional[tuple], signature: str) -> None:
        """Record a NORMAL (non-violation) response signature under key."""
        if key is None or not signature:
            return
        bucket = self._baselines[key]
        if len(bucket) < self._max_per_key:
            bucket.add(signature)

    def is_baseline(self, key: Optional[tuple], signature: str) -> bool:
        """True if `signature` was seen as a normal response for `key`.

        Returns False when the key has no baseline yet (the oracle then
        skips — cannot judge without a baseline).
        """
        if key is None or not signature:
            return False
        bucket = self._baselines.get(key)
        if not bucket:
            return False  # no baseline recorded yet — can't judge
        return signature in bucket

    def has_baseline(self, key: Optional[tuple]) -> bool:
        """True if at least one normal response was recorded for key."""
        if key is None:
            return False
        return bool(self._baselines.get(key))

    def stats(self) -> dict[str, int]:
        """Telemetry: how many keys tracked, total signatures."""
        return {
            "baseline_keys": len(self._baselines),
            "baseline_signatures": sum(len(v) for v in self._baselines.values()),
        }
