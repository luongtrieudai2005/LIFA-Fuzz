"""tests/test_violation_mutator.py
──────────────────────────────────
Unit tests for the SemFuzz-style semantic-violation engine + oracle.

Faithfulness to the paper (Sun et al., 2026):
  - Only add/remove/update actions exist (no reorder).
  - add/remove recompute the length field (§3.5.2).
  - The oracle flags expected≠actual response category as a potential bug.

All tests use a SYNTHETIC "XYZW" protocol (different magic/offsets than LIFA)
to prove the engine is protocol-agnostic — no LIFA-specific hardcoding.
"""
from __future__ import annotations

import struct

import pytest

from shared.schemas import (
    FieldRule,
    FieldType,
    MutationStrategy,
    ResponseCategory,
    ViolationAction,
    ViolationStrategy,
)
from fast_loop.violation_mutator import FlatFieldViolationMutator


# Synthetic protocol "XYZW": magic[0,4) type[4,5) len_le16[5,7) payload[7,-1)
MAGIC = b"XYZW"


def _fields():
    return [
        FieldRule(
            field_name="len", offset=5, length=2,
            mutation_strategy=MutationStrategy.CALCULATED,
            calculation_source="payload", data_type=FieldType.UINT16_LE,
        ),
        FieldRule(
            field_name="payload", offset=7, length=-1,
            mutation_strategy=MutationStrategy.RANDOM_BYTES,
        ),
    ]


def _seed(payload: bytes = b"hello") -> bytearray:
    return bytearray(MAGIC + bytes([0x10]) + struct.pack("<H", len(payload)) + payload)


def _declared(buf: bytearray) -> int:
    return struct.unpack("<H", bytes(buf[5:7]))[0]


class TestViolationActions:
    def test_add_inserts_and_recomputes_length(self):
        eng = FlatFieldViolationMutator(_fields())
        before = _seed(b"hello")           # payload 5B, declared 5
        out = eng.add(bytearray(before), 7, b"\xaa\xbb")  # +2 bytes at payload start
        assert len(out) == len(before) + 2
        assert _declared(out) == 7         # recomputed to new payload size

    def test_add_default_is_one_nul(self):
        eng = FlatFieldViolationMutator(_fields())
        before = _seed(b"hi")
        out = eng.add(bytearray(before), 7, None)
        assert len(out) == len(before) + 1
        assert out[7] == 0x00

    def test_remove_deletes_and_recomputes_length(self):
        eng = FlatFieldViolationMutator(_fields())
        before = _seed(b"hello")           # payload 5B, declared 5
        out = eng.remove(bytearray(before), 7, 3)         # -3 bytes
        assert len(out) == len(before) - 3
        assert _declared(out) == 2         # recomputed

    def test_update_overwrites_in_place_no_size_change(self):
        eng = FlatFieldViolationMutator(_fields())
        before = _seed(b"hello")
        out = eng.update(bytearray(before), 0, b"ABCD")  # overwrite magic
        assert len(out) == len(before)     # no size change
        assert bytes(out[:4]) == b"ABCD"

    def test_negative_offset_targets_tail(self):
        # FTP-style: strip trailing CRLF at offset -2
        eng = FlatFieldViolationMutator(_fields())
        before = bytearray(MAGIC + b"\x10" + struct.pack("<H", 3) + b"ab\r\n")
        out = eng.remove(bytearray(before), -2, 2)
        assert not bytes(out).endswith(b"\r\n")

    def test_execute_dispatches_all_three_actions(self):
        eng = FlatFieldViolationMutator(_fields())
        for action in (ViolationAction.ADD, ViolationAction.REMOVE, ViolationAction.UPDATE):
            s = ViolationStrategy(action=action, target_offset=7,
                                  target_length=1, insert_value="ff")
            out = eng.execute(bytearray(_seed()), s)
            assert isinstance(out, bytearray)


class TestOracleModel:
    def test_violation_strategy_default_expects_error(self):
        s = ViolationStrategy(action=ViolationAction.REMOVE, target_offset=0,
                              target_length=1)
        assert s.expected_category == ResponseCategory.ERROR

    def test_response_categories(self):
        assert ResponseCategory.NORMAL.value == "normal"
        assert ResponseCategory.ERROR.value == "error"


class TestFaithfulness:
    """Guard against drift from the paper — no reorder, 2-category oracle."""

    def test_only_three_actions_defined(self):
        assert {a.value for a in ViolationAction} == {"add", "remove", "update"}

    def test_no_reorder_action_in_engine(self):
        # The engine must not define a reorder method/action (paper has none).
        import inspect
        from fast_loop import violation_mutator as vm
        methods = {
            name for name, _ in inspect.getmembers(
                vm.FlatFieldViolationMutator, predicate=inspect.isfunction
            )
        }
        assert "reorder" not in methods
        # And no REORDER variant in the action enum (covered above too).
        assert not any("reorder" in a.value for a in ViolationAction)
