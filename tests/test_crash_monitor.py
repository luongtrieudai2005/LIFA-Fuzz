"""Unit tests for CrashMonitor — focuses on the on_crash() actionability bug.

Regression coverage for the fix where a NORMAL exit (exit 0) must NOT:
  - increment the crash counter,
  - log at ERROR level ("Crash #N" / "Crash artifact"),
  - save a crash artifact to disk,
  - be recorded through CrashManager,
while a real crash (SIGSEGV/SIGABRT) still does all of the above.

The e2e test (test_e2e_crash_detection.py) only exercises the actionable
path with a live vulnerable binary; these tests cover both branches and
the classification→is_actionable contract directly, with a fake sandbox.
"""
import asyncio
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import pytest

from fast_loop.crash_monitor import CrashMonitor
from shared.schemas import Signal


class _FakeSandbox:
    """Minimal BaseSandbox stand-in for unit-testing CrashMonitor.

    reset_state() flips back to alive so restart_target() can verify recovery.
    """

    def __init__(self, *, alive: bool = True) -> None:
        self._alive = alive
        self.reset_calls = 0

    async def is_target_alive(self) -> bool:
        return self._alive

    async def reset_state(self) -> None:
        self.reset_calls += 1
        self._alive = True  # recover on reset

    async def get_last_crash_info(self):
        return None


class _RecordingCrashManager:
    """Captures record() calls so tests can assert non-recording of normal exits."""

    def __init__(self) -> None:
        self.recorded: list = []

    async def record(self, **kwargs):
        self.recorded.append(kwargs)

        class _R:
            is_new = True
            signature = "sig"
            duplicate_count = 0

        return _R()


def _make_monitor(tmp_path, *, auto_reset=True) -> tuple[CrashMonitor, _FakeSandbox, _RecordingCrashManager]:
    sandbox = _FakeSandbox()
    cm = _RecordingCrashManager()
    monitor = CrashMonitor(
        sandbox=sandbox,
        crash_corpus_dir=str(tmp_path / "crashes"),
        auto_reset=auto_reset,
        restart_delay_s=0,  # keep tests fast
        crash_manager=cm,
    )
    return monitor, sandbox, cm


# ──────────────────────────────────────────────────────────────────────────
# Classification contract
# ──────────────────────────────────────────────────────────────────────────

def test_classify_normal_exit_is_not_actionable():
    m, _, _ = _make_monitor(pathlib.Path("/tmp"))
    c = m._classify_crash(exit_code=0)
    assert c["is_actionable"] is False
    assert c["type"] == "normal_exit"


def test_classify_sigsegv_is_actionable():
    m, _, _ = _make_monitor(pathlib.Path("/tmp"))
    c = m._classify_crash(exit_code=139)
    assert c["is_actionable"] is True
    assert c["type"] == "signal_crash"


def test_classify_asan_is_actionable():
    m, _, _ = _make_monitor(pathlib.Path("/tmp"))
    c = m._classify_crash(exit_code=1, serial_output="==ERROR: AddressSanitizer: heap-buffer-overflow")
    assert c["is_actionable"] is True
    assert c["type"] == "asan_violation"


# ──────────────────────────────────────────────────────────────────────────
# on_crash: normal exit must NOT be counted / recorded / saved
# ──────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_normal_exit_does_not_increment_crash_count(tmp_path):
    m, sandbox, cm = _make_monitor(tmp_path)
    await m.on_crash(
        exit_code=0,
        classification=m._classify_crash(exit_code=0),
    )
    assert m.total_crashes == 0  # NOT counted
    assert cm.recorded == []      # NOT recorded through CrashManager


@pytest.mark.asyncio
async def test_normal_exit_does_not_save_artifact(tmp_path):
    m, sandbox, cm = _make_monitor(tmp_path)
    await m.on_crash(
        exit_code=0,
        classification=m._classify_crash(exit_code=0),
    )
    crash_dir = tmp_path / "crashes"
    # No crash artifacts on disk for a normal exit.
    assert not crash_dir.exists() or not any(crash_dir.iterdir())


@pytest.mark.asyncio
async def test_normal_exit_still_restarts_target(tmp_path):
    # A normal exit means the server IS down — restart_target must still run.
    m, sandbox, cm = _make_monitor(tmp_path)
    await m.on_crash(
        exit_code=0,
        classification=m._classify_crash(exit_code=0),
    )
    assert sandbox.reset_calls == 1
    assert await sandbox.is_target_alive() is True


@pytest.mark.asyncio
async def test_normal_exit_returns_record_without_recording(tmp_path):
    m, sandbox, cm = _make_monitor(tmp_path)
    rec = await m.on_crash(
        exit_code=0,
        classification=m._classify_crash(exit_code=0),
    )
    assert rec.exit_code == 0
    assert m.total_crashes == 0


# ──────────────────────────────────────────────────────────────────────────
# on_crash: actionable crash IS counted / recorded / saved
# ──────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_real_crash_increments_count_and_records(tmp_path):
    m, sandbox, cm = _make_monitor(tmp_path)
    cls = m._classify_crash(exit_code=139)  # SIGSEGV
    await m.on_crash(exit_code=139, classification=cls)
    assert m.total_crashes == 1
    assert len(cm.recorded) == 1
    assert cm.recorded[0]["crash_type"] == "signal_crash"


@pytest.mark.asyncio
async def test_real_crash_saves_artifact(tmp_path):
    m, sandbox, cm = _make_monitor(tmp_path)
    # Register an offending packet so the artifact has a .bin to save.
    m.register_offending_packet(b"EXPLOIT", mutation_rule_id="boundary_len")
    await m.on_crash(exit_code=139, classification=m._classify_crash(exit_code=139))
    crash_dir = tmp_path / "crashes"
    files = list(crash_dir.iterdir()) if crash_dir.exists() else []
    assert any(f.suffix == ".json" for f in files)
    assert any(f.suffix == ".bin" for f in files)


@pytest.mark.asyncio
async def test_multiple_normal_exits_then_one_crash(tmp_path):
    """Counter must reflect ONLY actionable crashes across mixed events."""
    m, sandbox, cm = _make_monitor(tmp_path)
    normal = m._classify_crash(exit_code=0)
    segv = m._classify_crash(exit_code=139)
    await m.on_crash(exit_code=0, classification=normal)
    await m.on_crash(exit_code=0, classification=normal)
    await m.on_crash(exit_code=0, classification=normal)
    await m.on_crash(exit_code=139, classification=segv)
    # Three normal exits ignored; one real crash counted.
    assert m.total_crashes == 1
    assert len(cm.recorded) == 1
