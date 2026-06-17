"""
fast_loop/lifa_module.py
────────────────────────
LifaModule — an OPT-IN, DISCLOSED ProtocolModule for the LIFA-v2 binary target.

This is NOT part of the black-box core (NullModule is the default). It exists
so the differential-baseline oracle (Phase 3) can run on the v2 target:
NullModule exposes no command/state, so the oracle's baseline key would be
None and no check would run. LifaModule parses the v2 frame's opcode byte as
the "command"/"state" identity, letting the oracle bucket responses.

v2 frame: MAGIC(4) + version(1) + opcode(1) + len_le16(2) + payload.
Response opcodes: PONG=0x81, ACK=0x82, STATUS_RESP=0x83, ERROR=0xFF.

Loaded only when config/env selects ``protocol_module: lifa``. Registered
into the shared registry on import.
"""
from __future__ import annotations

from typing import Any, Optional

from shared.protocol_module import ProtocolModule, register_protocol_module
from shared.schemas import PacketStatus

_LIFA_MAGIC = b"LIFA"
# Request opcodes (payload[5])
_REQ = {0x01: "PING", 0x02: "PROCESS", 0x03: "STATUS", 0x04: "RESET"}
# Response opcodes (response[5])
_RESP = {0x81: "PONG", 0x82: "ACK", 0x83: "STATUS_RESP", 0xFF: "ERROR"}


def _is_lifa(buf: bytes) -> bool:
    return len(buf) >= 6 and buf[:4] == _LIFA_MAGIC


class LifaModule(ProtocolModule):
    """Disclosed case-study module for the LIFA-v2 binary target."""

    name = "lifa"

    def binary_operators(self) -> list[str]:
        return []

    def extract_state_code(self, response: bytes) -> str:
        # Use the response opcode as the state label (PONG/ACK/STATUS_RESP/ERROR).
        if _is_lifa(response):
            return _RESP.get(response[5], f"op{response[5]:02x}")
        return ""

    def extract_command(self, payload: bytes) -> str:
        if _is_lifa(payload):
            return _REQ.get(payload[5], f"op{payload[5]:02x}")
        return ""

    def classify(self, response: bytes, payload: bytes) -> PacketStatus:
        if not response:
            return PacketStatus.REJECTED
        return PacketStatus.ACCEPTED

    def ensure_framing(self, payload: bytes) -> bytes:
        return payload  # binary, no framing

    def state_tracker(self) -> Optional[Any]:
        return None  # state tracking via the generic P-PSM (NullModule path)

    def response_sample_extra(self, response: bytes) -> dict[str, Any]:
        if _is_lifa(response):
            return {"lifa_resp_opcode": f"{response[5]:02x}"}
        return {}

    def response_category(self, response: bytes, payload: bytes) -> str:
        # ERROR opcode (0xFF) or empty ⇒ error; everything else ⇒ normal.
        if not response:
            return "error"
        if _is_lifa(response) and response[5] == 0xFF:
            return "error"
        return "normal"

    def response_signature(self, response: bytes, payload: bytes) -> str:
        # The response opcode byte is the stable identity (PONG/ACK/.../ERROR).
        if _is_lifa(response):
            return _RESP.get(response[5], f"op{response[5]:02x}")
        return "non_lifa" if response else "empty"

    def violation_strategies(self) -> list:
        # No case-study violations; grammar-targeted violations come from the
        # rule generator (Phase 2) and are field-name resolved by the engine.
        return []


register_protocol_module("lifa", LifaModule)
