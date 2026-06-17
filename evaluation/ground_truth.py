"""
evaluation/ground_truth.py
───────────────────────────
Canonical definition of the LIFA vulnerable server protocol.

This module defines the TRUE protocol structure as implemented in
``sandbox/target/vulnerable_server.c`` (vulnerable_server_v2). It serves as
the ground truth for RQ1 accuracy evaluation — comparing what the
LLM / DifferentialAnalyzer infers against the actual wire format.

Protocol Layout (LIFA Binary Protocol v2 — 8-byte header):
    Bytes 0-3:  Magic Bytes  "LIFA"  (0x4C 0x49 0x46 0x41)  — STATIC
    Byte  4:    Version (0x01)                              — STATIC
    Byte  5:    Opcode                                      — ENUM
                0x01=PING, 0x02=PROCESS_DATA, 0x03=STATUS, 0x04=RESET
    Bytes 6-7:  Payload Length (uint16_le)                  — CALCULATED / LENGTH
    Bytes 8+:   Payload data                                — VARIABLE / HIGH_ENTROPY

State machine (per-connection): INIT ──[PING]──▶ AUTHENTICATED.
    PROCESS_DATA is the VULNERABLE opcode but is only honoured in AUTH state.
    A fresh connection starts in INIT, so a single-packet fuzzer is always
    rejected (ERR_BAD_STATE). The fuzzer MUST execute the sequence
    [new conn] → PING → PROCESS_DATA(overflow) to reach the bug.

Vulnerability:
    Opcode 0x02 (PROCESS_DATA) copies payload into a fixed 64-byte
    stack buffer using memcpy without bounds checking.
    Trigger: opcode=0x02, state=AUTHENTICATED, length > 64
             → stack buffer overflow → SIGSEGV (or ASAN SIGABRT).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# =============================================================================
# Ground Truth Field Definition
# =============================================================================


@dataclass(frozen=True)
class GroundTruthField:
    """A single field in the true protocol structure.

    Attributes:
        name:          Human-readable field name.
        offset_start:  Start byte offset (inclusive, 0-indexed).
        offset_end:    End byte offset (exclusive). ``-1`` = variable length.
        wire_type:     Wire encoding type (e.g. ``"bytes"``, ``"uint8"``).
        semantic_role: Semantic role (``"static"``, ``"enum"``, ``"length"``,
                       ``"variable"``).
        description:   What this field does.
        static_hex:    Hex value if the field is constant across all packets.
        valid_values:  List of valid values for enum fields.
    """

    name: str
    offset_start: int
    offset_end: int  # -1 = variable/remainder
    wire_type: str
    semantic_role: str
    description: str = ""
    static_hex: Optional[str] = None
    valid_values: Optional[list[int]] = None

    @property
    def length(self) -> int:
        """Fixed field length, or -1 for variable."""
        if self.offset_end == -1:
            return -1
        return self.offset_end - self.offset_start


# =============================================================================
# LIFA Protocol Ground Truth
# =============================================================================

LIFA_MAGIC_HEX = "4c494641"  # "LIFA" in hex
LIFA_VERSION = 0x01

LIFA_GROUND_TRUTH: list[GroundTruthField] = [
    GroundTruthField(
        name="magic",
        offset_start=0,
        offset_end=4,
        wire_type="bytes",
        semantic_role="static",
        description="Protocol magic bytes 'LIFA' (0x4C 0x49 0x46 0x41). "
                    "Constant across all valid packets. Server rejects "
                    "packets with incorrect magic.",
        static_hex=LIFA_MAGIC_HEX,
    ),
    GroundTruthField(
        name="version",
        offset_start=4,
        offset_end=5,
        wire_type="uint8",
        semantic_role="static",
        description="Protocol version byte. Must be exactly 0x01. "
                    "Server rejects packets with a different version.",
        static_hex="01",
    ),
    GroundTruthField(
        name="opcode",
        offset_start=5,
        offset_end=6,
        wire_type="uint8",
        semantic_role="enum",
        description="Command opcode. 0x01=PING (auth handshake: INIT → AUTH), "
                    "0x02=PROCESS_DATA (VULNERABLE — only valid in AUTH state, "
                    "stack buffer overflow), 0x03=STATUS (query state), "
                    "0x04=RESET (return to INIT).",
        valid_values=[0x01, 0x02, 0x03, 0x04],
    ),
    GroundTruthField(
        name="length",
        offset_start=6,
        offset_end=8,
        wire_type="uint16_le",
        semantic_role="length",
        description="Payload length in bytes (uint16, little-endian). "
                    "Determines how many bytes after the 8-byte header belong "
                    "to the payload. Server uses this for memcpy size — no "
                    "bounds check against the 64-byte buffer in PROCESS_DATA.",
    ),
    GroundTruthField(
        name="payload",
        offset_start=8,
        offset_end=-1,
        wire_type="bytes",
        semantic_role="variable",
        description="Variable-length payload data. In PROCESS_DATA, "
                    "this is copied into a 64-byte stack buffer. "
                    "Payloads > 64 bytes (in AUTH state) trigger the "
                    "vulnerability.",
    ),
]

# Header size in bytes
LIFA_HEADER_SIZE = 8

# Vulnerability trigger: opcode=0x02 (PROCESS_DATA) in AUTHENTICATED state,
# payload length > 64.
LIFA_VULN_OPCODE = 0x02
LIFA_VULN_BUF_SIZE = 64


def get_ground_truth_summary() -> dict:
    """Return a summary dict of the ground truth for logging."""
    return {
        "protocol": "LIFA Binary Protocol",
        "header_size": LIFA_HEADER_SIZE,
        "magic": LIFA_MAGIC_HEX,
        "fields": [
            {
                "name": f.name,
                "offset": f"[{f.offset_start},{f.offset_end})",
                "type": f.wire_type,
                "role": f.semantic_role,
                "length": f.length,
            }
            for f in LIFA_GROUND_TRUTH
        ],
        "vulnerability": {
            "opcode": LIFA_VULN_OPCODE,
            "buffer_size": LIFA_VULN_BUF_SIZE,
            "trigger": f"opcode=0x{LIFA_VULN_OPCODE:02x}, state=AUTH, "
                       f"length > {LIFA_VULN_BUF_SIZE}",
            "type": "Stack buffer overflow → SIGSEGV (ASAN: SIGABRT)",
        },
    }
