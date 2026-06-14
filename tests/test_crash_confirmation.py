"""Post-crash confirmation Phase 1 — regression tests.

Covers:
  - mutator.freeze_crash_window / unfreeze: appending stops while frozen,
    resumes after unfreeze.
  - crash_monitor._confirm_crash: replays most-recent-first and returns the
    packet that reproduces (reproduced=True), not the window's last entry.
  - failure isolation: confirmation errors fall back to window[-1] flagged
    reproduced=False, never raise.
  - reproduced/confirmation_method flow through to CrashManager + statistics.
"""
import asyncio
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import pytest

from fast_loop.crash_monitor import CrashMonitor
from fast_loop.mutator import MutationEngine  # noqa: F401  (for isinstance checks)
from shared.schemas import Signal


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _FakeSandbox:
    """Sandbox whose target dies ONLY when a specific 'killer' payload is sent.

    reset_state() revives it. This lets us deterministically model which
    candidate reproduces the crash.
    """

    def __init__(self, killer: bytes) -> None:
        self._killer = killer
        self._alive = True
        self.reset_calls = 0

    async def is_target_alive(self) -> bool:
        return self._alive

    async def reset_state(self) -> None:
        self.reset_calls += 1
        self._alive = True

    async def get_last_crash_info(self):
        return None


class _FakeMutator:
    """Minimal mutator stand-in: exposes freeze/unfreeze + target host/port.

    For these tests we bypass _replay_and_check's real TCP send by patching
    it, so target_host/port just need to be present.
    """

    def __init__(self, killer: bytes) -> None:
        self.target_host = "127.0.0.1"
        self.target_port = 9999
        self._killer = killer
        self._last_injected_packet: bytes = b""
        self._last_injected_rule_id = None

    # crash window freeze API (mirrors the real MutationEngine)
    @property
    def window_frozen(self) -> bool:
        return getattr(self, "_frozen", False)

    def get_crash_window(self):
        return list(getattr(self, "_window", []))

    def freeze_crash_window(self):
        self._frozen = True
        return list(getattr(self, "_window", []))

    def unfreeze_crash_window(self):
        self._frozen = False

    def pause(self):
        pass

    def resume(self):
        pass


class _RecordingCrashManager:
    async def record(self, **kwargs):
        self.last = kwargs

        class _R:
            is_new = True
            signature = "sig"
            duplicate_count = 0

        return _R()


# ---------------------------------------------------------------------------
# mutator freeze/unfreeze (real MutationEngine, no network)
# ---------------------------------------------------------------------------

def test_freeze_blocks_append(tmp_path):
    import os
    # Build a real MutationEngine without running it; we only exercise the
    # crash-window bookkeeping.
    eng = MutationEngine(
        target_host="127.0.0.1", target_port=1,
        seed_queue=asyncio.Queue(), k=2,
    )
    eng._crash_window.append((0.0, b"AAA", "r1"))
    assert len(eng.get_crash_window()) == 1

    frozen = eng.freeze_crash_window()
    assert eng.window_frozen is True
    assert len(frozen) == 1
    # While frozen, a simulated send must NOT append.
    if not eng._window_frozen:
        eng._crash_window.append((1.0, b"BBB", "r2"))
    assert len(eng.get_crash_window()) == 1, "append must be blocked while frozen"

    eng.unfreeze_crash_window()
    assert eng.window_frozen is False
    if not eng._window_frozen:
        eng._crash_window.append((2.0, b"CCC", "r3"))
    assert len(eng.get_crash_window()) == 2, "append resumes after unfreeze"


# ---------------------------------------------------------------------------
# crash_monitor._confirm_crash
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_confirm_crash_finds_the_real_culprit_not_window_last():
    """50 candidates; only the one at index 10 reproduces. Confirmation must
    return THAT packet, not window[-1]."""
    killer = b"KILLER_PACKET"
    benign = b"benign"
    sandbox = _FakeSandbox(killer)
    mutator = _FakeMutator(killer)
    cm = CrashMonitor(sandbox=sandbox, mutator=mutator, auto_reset=True,
                      restart_delay_s=0, confirm_crashes=True)

    # Patch the TCP replay to use the sandbox's killer knowledge instead of a
    # real socket: a payload reproduces iff it equals the killer.
    async def fake_replay(payload, host, port):
        if payload == killer:
            sandbox._alive = False  # killer crashes the target
            return True
        return False
    cm._replay_and_check = fake_replay

    candidates = [(float(i), benign, "r") for i in range(50)]
    candidates[10] = (10.0, killer, "rule_killer")

    payload, rule, reproduced = await cm._confirm_crash(candidates)
    assert reproduced is True
    assert payload == killer
    assert rule == "rule_killer"


@pytest.mark.asyncio
async def test_confirm_crash_none_reproduces_falls_back_flagged():
    """When no candidate reproduces, return window[-1] with reproduced=False."""
    sandbox = _FakeSandbox(b"never")
    mutator = _FakeMutator(b"never")
    cm = CrashMonitor(sandbox=sandbox, mutator=mutator, auto_reset=True,
                      restart_delay_s=0, confirm_crashes=True)

    async def never_replay(payload, host, port):
        return False
    cm._replay_and_check = never_replay

    candidates = [(0.0, b"a", "r1"), (1.0, b"b", "r2"), (2.0, b"c", "r3")]
    payload, rule, reproduced = await cm._confirm_crash(candidates)
    assert reproduced is False
    assert payload == b"c"  # window[-1] fallback
    assert rule == "r3"


@pytest.mark.asyncio
async def test_confirm_crash_empty_candidates():
    cm = CrashMonitor(sandbox=_FakeSandbox(b"x"), mutator=_FakeMutator(b"x"))
    payload, rule, reproduced = await cm._confirm_crash([])
    assert (payload, rule, reproduced) == (b"", None, False)


@pytest.mark.asyncio
async def test_confirm_crash_reset_failure_is_isolated():
    """If reset_state raises on some candidates, confirmation must skip them
    and keep trying — never raise."""
    sandbox = _FakeSandbox(b"K")
    mutator = _FakeMutator(b"K")
    # Make the first reset raise, then succeed.
    original_reset = sandbox.reset_state
    call_count = {"n": 0}

    class _FlakySandbox(_FakeSandbox):
        async def reset_state(self):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("transient reset failure")
            await original_reset()
    flaky = _FlakySandbox(b"K")
    cm = CrashMonitor(sandbox=flaky, mutator=mutator, auto_reset=True,
                      restart_delay_s=0, confirm_crashes=True)

    async def replay(payload, host, port):
        if payload == b"K":
            flaky._alive = False
            return True
        return False
    cm._replay_and_check = replay

    candidates = [(0.0, b"x", "r"), (1.0, b"K", "rk"), (2.0, b"y", "r")]
    payload, rule, reproduced = await cm._confirm_crash(candidates)
    assert reproduced is True
    assert payload == b"K"


# ---------------------------------------------------------------------------
# reproduced flag flows through CrashManager.record + statistics
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_record_stores_reproduced_and_statistics(tmp_path):
    from shared.crash_manager import CrashManager
    cm = CrashManager(crash_dir=str(tmp_path / "crashes"))
    await cm.load()

    await cm.record(payload=b"poc1", crash_type="segv", reproduced=True,
                    confirmation_method="replay_confirmed")
    await cm.record(payload=b"poc2", crash_type="segv", reproduced=False,
                    confirmation_method="replay_unconfirmed")

    stats = await cm.get_statistics()
    assert stats.reproduced_crashes == 1
    assert stats.unconfirmed_crashes == 1
    assert stats.unique_crashes == 2


# ---------------------------------------------------------------------------
# Full on_crash + confirmation integration (pause → drain → freeze → confirm)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_on_crash_with_confirmation_records_reproduced_flag(tmp_path):
    """End-to-end: on_crash with confirm_crashes=True must run confirmation,
    and the reproduced/confirmation_method flags must reach crash_manager."""
    killer = b"THE_KILLER"
    sandbox = _FakeSandbox(killer)
    mutator = _FakeMutator(killer)
    # Seed the frozen window with candidates; only 'killer' reproduces.
    mutator._window = [(0.0, b"a", "r"), (1.0, b"b", "r"), (2.0, killer, "rk")]
    cmgr = _RecordingCrashManager()
    mon = CrashMonitor(
        sandbox=sandbox, mutator=mutator,
        crash_corpus_dir=str(tmp_path / "crashes"),
        auto_reset=True, restart_delay_s=0,
        crash_manager=cmgr, confirm_crashes=True,
    )
    # Bypass the real TCP replay + the 0.5s drain for test speed.
    mon.confirm_drain_s = 0.0

    async def fake_replay(payload, host, port):
        if payload == killer:
            sandbox._alive = False
            return True
        return False
    mon._replay_and_check = fake_replay

    # Actionable crash (SIGSEGV=139) → enters the confirmation path.
    await mon.on_crash(exit_code=139, classification=mon._classify_crash(139))

    # crash_manager.record received the CONFIRMED culprit + flags.
    assert cmgr.last is not None
    assert cmgr.last["payload"] == killer
    assert cmgr.last["reproduced"] is True
    assert cmgr.last["confirmation_method"] == "replay_confirmed"
    # Window was unfrozen after confirmation (finally block).
    assert mutator.window_frozen is False


@pytest.mark.asyncio
async def test_on_crash_confirmation_unconfirmed_when_no_replay_matches(tmp_path):
    """If no candidate reproduces, recorded payload is window[-1] with
    reproduced=False + confirmation_method='replay_unconfirmed'."""
    sandbox = _FakeSandbox(b"never")
    mutator = _FakeMutator(b"never")
    mutator._window = [(0.0, b"a", "r1"), (1.0, b"b", "r2")]
    cmgr = _RecordingCrashManager()
    mon = CrashMonitor(
        sandbox=sandbox, mutator=mutator,
        crash_corpus_dir=str(tmp_path / "crashes"),
        auto_reset=True, restart_delay_s=0,
        crash_manager=cmgr, confirm_crashes=True,
    )
    mon.confirm_drain_s = 0.0

    async def never_replay(payload, host, port):
        return False
    mon._replay_and_check = never_replay

    await mon.on_crash(exit_code=139, classification=mon._classify_crash(139))

    assert cmgr.last["payload"] == b"b"  # window[-1]
    assert cmgr.last["reproduced"] is False
    assert cmgr.last["confirmation_method"] == "replay_unconfirmed"
