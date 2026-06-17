"""tests/test_baseline_oracle.py
────────────────────────────────
Unit tests for the Phase-3 differential-baseline oracle.

The oracle is RFC-free and behavioural: it records the response signatures a
command normally gets, then flags a structural violation whose response
signature MATCHES that baseline (server did not react).

Tests:
- ResponseBaselineTracker record / is_baseline / has_baseline.
- response_signature stability (FTP status code; NullModule prefix+bucket).
- The oracle's CORE property on a synthetic STRICT target: a violation that
  yields a DIFFERENT signature is NOT flagged (no false positive), while one
  that yields the SAME signature IS flagged.
"""
from __future__ import annotations

from shared.protocol_module import NullModule
from fast_loop.baseline_tracker import ResponseBaselineTracker


class _FakeModule:
    """Minimal module: command/state/signature stubs for oracle tests."""
    def __init__(self, sig_of):
        self._sig_of = sig_of  # callable(response)->signature

    def extract_command(self, payload: bytes) -> str:
        return payload.split(b" ", 1)[0].decode("ascii", "replace") if payload else ""

    def extract_state_code(self, response: bytes) -> str:
        return self._sig_of(response)  # reuse signature as a state label

    def response_signature(self, response: bytes, payload: bytes) -> str:
        return self._sig_of(response)


class TestBaselineTracker:
    def test_record_and_match(self):
        t = ResponseBaselineTracker()
        m = _FakeModule(lambda r: r.decode())
        key = t.make_key(m, b"USER admin", "220")
        t.record(key, "331")
        assert t.has_baseline(key)
        assert t.is_baseline(key, "331")
        assert not t.is_baseline(key, "530")  # different signature

    def test_no_baseline_no_flag(self):
        t = ResponseBaselineTracker()
        m = _FakeModule(lambda r: r.decode())
        key = t.make_key(m, b"USER admin", "220")
        # Nothing recorded → cannot judge → not flagged.
        assert not t.has_baseline(key)
        assert not t.is_baseline(key, "331")

    def test_none_key_skipped(self):
        t = ResponseBaselineTracker()
        t.record(None, "x")  # no-op
        assert not t.has_baseline(None)


class TestResponseSignature:
    def test_null_module_prefix_bucket(self):
        nm = NullModule()
        assert nm.response_signature(b"", b"") == "empty"
        s = nm.response_signature(b"abcdefgh", b"")
        assert s.endswith(":S")  # short → S bucket

    def test_ftp_status_code(self):
        import sys
        sys.path.insert(0, ".")
        import fast_loop.ftp_module  # register
        from shared.protocol_module import get_protocol_module
        ftp = get_protocol_module("ftp")
        assert ftp.response_signature(b"220 ready\r\n", b"") == "220"
        assert ftp.response_signature(b"530 fail\r\n", b"") == "530"


class TestDifferentialOracleProperty:
    """The core precision property: a strict server (different signature on
    violation) is NOT flagged; a non-reacting server (same signature) IS."""

    def test_strict_target_not_flagged(self):
        # Baseline: command "X" normally gets "ACK".
        t = ResponseBaselineTracker()
        m = _FakeModule(lambda r: r.decode())
        key = t.make_key(m, b"X data", "INIT")
        t.record(key, "ACK")
        # Violation: strict server answers "ERROR" (≠ baseline) → not flagged.
        assert not t.is_baseline(key, "ERROR")

    def test_non_reacting_target_flagged(self):
        t = ResponseBaselineTracker()
        m = _FakeModule(lambda r: r.decode())
        key = t.make_key(m, b"X data", "INIT")
        t.record(key, "ACK")
        # Violation: server still answers "ACK" (== baseline) → flagged.
        assert t.is_baseline(key, "ACK")
