"""
fast_loop/ftp_module.py
───────────────────────
FTPModule — an OPT-IN, DISCLOSED ProtocolModule for the LightFTP/FTP case study.

This is NOT part of the black-box core. The core (``MutationEngine`` +
``BinaryMutator`` + ``NullModule``) fuzzes any unknown protocol with zero
protocol knowledge. FTPModule adds FTP-specific response parsing, CRLF
framing, an FTP state-transition tracker, and the 4 FTP token-injection
operators — knowledge that is legitimate for an FTP case study but would
contradict the "unknown protocol" thesis if it were in the core.

Wiring: loaded only when config ``protocol_module: ftp`` (default is
``null`` ⇒ NullModule ⇒ pure black-box). Registered into the shared registry
on import so the core resolves the name without a hard dependency.

Ablation (scripts/ablation_generic_vs_module.py) runs LightFTP with NullModule
vs FTPModule to characterize — honestly — what the black-box core alone
achieves vs what the disclosed FTP module adds.
"""
from __future__ import annotations

from typing import Any, Optional

from shared.protocol_module import ProtocolModule, register_protocol_module
from shared.schemas import PacketStatus
from fast_loop.state_transition_graph import StateTransitionGraph

#: The 4 FTP-specific BinaryMutator strategy names (implemented in
#: binary_mutator.py). The core never selects these unless a module offers them.
_FTP_BINARY_OPERATORS = [
    "ftp_token_inject",
    "ftp_token_replace",
    "ftp_arg_fuzz",
    "ftp_crlf_insert",
]


def _extract_ftp_code(response: bytes) -> str:
    """3-digit FTP status code (RFC 959): digits 100-599 + space/hyphen.
    ``"000"`` if not a valid FTP status line."""
    if len(response) >= 4 and response[:3].isdigit():
        try:
            code_val = int(response[:3])
            if 100 <= code_val <= 599 and response[3:4] in (b" ", b"-"):
                return f"{code_val:03d}"
        except ValueError:
            pass
    return "000"


class FTPModule(ProtocolModule):
    """FTP case-study module: FTP status codes, CRLF framing, FTP STG,
    and the FTP token-injection operators."""

    name = "ftp"

    def binary_operators(self) -> list[str]:
        return list(_FTP_BINARY_OPERATORS)

    def extract_state_code(self, response: bytes) -> str:
        return _extract_ftp_code(response)

    def extract_command(self, payload: bytes) -> str:
        return StateTransitionGraph.extract_ftp_command(payload)

    def classify(self, response: bytes, payload: bytes) -> PacketStatus:
        if not response:
            return PacketStatus.REJECTED
        if len(response) >= 3:
            try:
                code = int(response[:3])
                if 200 <= code < 400:
                    return PacketStatus.ACCEPTED
                if 400 <= code < 600:
                    return PacketStatus.REJECTED
            except ValueError:
                pass
        return PacketStatus.ACCEPTED

    def ensure_framing(self, payload: bytes) -> bytes:
        """Enforce CRLF termination per RFC 959 (FTP commands end in \\r\\n)."""
        if not payload:
            return payload
        if payload.endswith(b"\r\n"):
            return payload
        if payload.endswith(b"\n"):
            return payload[:-1] + b"\r\n"
        if payload.endswith(b"\r"):
            return payload + b"\n"
        return payload + b"\r\n"

    def state_tracker(self) -> Optional[Any]:
        # StateTransitionGraph is FTP-coded (status codes + command tokens).
        # Returned only for the FTP case study; NullModule returns None.
        return StateTransitionGraph()

    def response_sample_extra(self, response: bytes) -> dict[str, Any]:
        code = _extract_ftp_code(response)
        return {"ftp_status_code": code} if code != "000" else {}


# Register so config `protocol_module: ftp` resolves to this. The default
# remains "null" (NullModule) — the pure black-box core.
register_protocol_module("ftp", FTPModule)
