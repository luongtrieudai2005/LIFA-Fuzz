"""
evaluation/ground_truth.py
───────────────────────────
Canonical definition of the LIFA vulnerable server protocol.

This module defines the TRUE protocol structure as implemented in
``sandbox/target/vulnerable_server.c``. It serves as the ground truth
for RQ1 accuracy evaluation — comparing what the LLM / DifferentialAnalyzer
infers against the actual wire format.

Protocol Layout (LIFA Binary Protocol):
    Bytes 0-3:  Magic Bytes  "LIFA"  (0x4C 0x49 0x46 0x41)  — STATIC
    Byte  4:    Opcode                                — ENUM (0x01=PING, 0x02=PROCESS_DATA)
    Byte  5:    Payload Length (uint8)                — CALCULATED / LENGTH
    Bytes 6+:   Payload data                         — VARIABLE / HIGH_ENTROPY

Vulnerability:
    Opcode 0x02 (PROCESS_DATA) copies payload into a fixed 32-byte
    stack buffer using memcpy without bounds checking.
    Trigger: opcode=0x02, length > 32 → stack buffer overflow → SIGSEGV.
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
        name="opcode",
        offset_start=4,
        offset_end=5,
        wire_type="uint8",
        semantic_role="enum",
        description="Command opcode. 0x01=PING (echo back), "
                    "0x02=PROCESS_DATA (vulnerable path — stack buffer overflow).",
        valid_values=[0x01, 0x02],
    ),
    GroundTruthField(
        name="length",
        offset_start=5,
        offset_end=6,
        wire_type="uint8",
        semantic_role="length",
        description="Payload length in bytes. Determines how many bytes "
                    "after the header belong to the payload. "
                    "Server uses this for memcpy size — no bounds check "
                    "against the 32-byte buffer in PROCESS_DATA.",
    ),
    GroundTruthField(
        name="payload",
        offset_start=6,
        offset_end=-1,
        wire_type="bytes",
        semantic_role="variable",
        description="Variable-length payload data. In PROCESS_DATA, "
                    "this is copied into a 32-byte stack buffer. "
                    "Payloads > 32 bytes trigger the vulnerability.",
    ),
]

# Header size in bytes
LIFA_HEADER_SIZE = 6

# Vulnerability trigger: opcode=0x02, length > 32
LIFA_VULN_OPCODE = 0x02
LIFA_VULN_BUF_SIZE = 32


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
            "trigger": f"opcode=0x{LIFA_VULN_OPCODE:02x}, length > {LIFA_VULN_BUF_SIZE}",
            "type": "Stack buffer overflow → SIGSEGV",
        },
    }
