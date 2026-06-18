"""tests/test_ppsm_fallback.py
──────────────────────────────
Tests for the P-PSM frequency-fallback (recover when the KS filter over-prunes
on a small / unbalanced sample and drops the offset-0 protocol units).

The fallback is protocol-agnostic (frequency + offset-0 prior), so tests use
synthetic responses that are NOT tied to any real target.
"""
from __future__ import annotations

import pytest

from slow_loop.state_machine_inferer import (
    StateMachineInferer,
    _frequency_candidate_units,
    _ks_test_filter,
    _extract_message_units,
    _reconstruct_format_messages,
)


def _u(code: bytes) -> bytes:
    """3-byte offset-0 unit of a status response like b'220 ...'."""
    return code[:3]


class TestKsOverPruneRecovery:
    def test_ks_drops_offset0_units_on_unbalanced_halves(self):
        # Half A all '220', half B all '331' → offset-0 units are not shared
        # across halves → the KS progressive-λ filter drops both.
        pkts = [b"220 ready\r\n"] * 10 + [b"331 need pass\r\n"] * 10
        ks = _ks_test_filter(_extract_message_units(pkts), pkts)
        assert _u(b"220") not in ks
        assert len(_reconstruct_format_messages(pkts, ks)) == 0

    def test_frequency_fallback_keeps_offset0_units(self):
        pkts = [b"220 ready\r\n"] * 10 + [b"331 need pass\r\n"] * 10
        freq = _frequency_candidate_units(pkts, min_packets=2)
        assert _u(b"220") in freq and _u(b"331") in freq
        assert len(_reconstruct_format_messages(pkts, freq)) >= 3

    def test_infer_recovers_non_degenerate_model_via_fallback(self):
        # Unbalanced halves force KS to under-produce; with sessions the
        # fallback must still yield a real P-PSM (>=2 states, >0 transitions).
        a = [b"220 ready\r\n"] * 6 + [b"331 need pass\r\n"] * 4
        b = [b"230 logged in\r\n"] * 5 + [b"221 goodbye\r\n"] * 5
        pkts = a + b
        psm = StateMachineInferer(min_packets=10).infer(pkts, [a, b])
        assert psm.n_states >= 2
        assert len(psm.transitions) > 0

    def test_healthy_sample_still_uses_ks_path(self):
        # A balanced, varied sample should produce format messages via KS
        # (the fallback must not replace KS when KS is healthy).
        pkts = []
        for code in (b"220", b"331", b"230", b"215", b"257", b"200", b"221"):
            pkts += [code + b" payload data here\r\n"] * 4
        ks = _ks_test_filter(_extract_message_units(pkts), pkts)
        assert len(_reconstruct_format_messages(pkts, ks)) >= 3
