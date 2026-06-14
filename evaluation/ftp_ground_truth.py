"""
evaluation/ftp_ground_truth.py
──────────────────────────────
Independent ground truth for RQ1 — the FTP control protocol per RFC 959.

Unlike LIFA_GROUND_TRUTH (a binary protocol designed by this project's
author — an *evaluation leak*), FTP is a public IETF standard with an
independent, citable specification. Inferring FTP grammar from traffic
therefore tests whether the LLM generalizes to a protocol it was NOT
built around.

RFC 959 control-connection command format (§4.1.1):

    <command> <SP> <argument> <CRLF>

  - command:  3–4 uppercase ASCII letters (USER, PASS, RETR, CWD, ...).
              Treated as an ENUM (discrete command vocabulary).
  - argument: variable-length ASCII text (username, password, pathname),
              or empty. Terminated by CRLF.

For the offset-based evaluator, the ground truth mirrors the four wire
parts RFC 959 §4.1.1 defines for a command with arguments:

    [0,4)    command    — enum   (USER/PASS/RETR/...)
    [4,5)    space      — static (0x20 delimiter)
    [5,-2)   argument   — string (variable, text before CRLF)
    [-2,-1)  crlf       — static (0x0D 0x0A terminator)

Offset semantics: ``-2`` means "2 bytes before end of packet" — i.e.
relative-to-end. The matcher handles negative offsets as anchors from
the packet tail, matching the way an LLM naturally describes a
terminator ("the last 2 bytes"). 3-letter commands (CWD/MKD/PWD) still
match the [0,4) GT via the ±1 start-tolerance in the evaluator.

References:
    Postel, J., Reynolds, J. "FILE TRANSFER PROTOCOL (FTP)."
    STD 9, RFC 959, October 1985. https://www.rfc-editor.org/rfc/rfc959
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class FTPGroundTruthField:
    """A single field in the true FTP command structure.

    Mirrors ``evaluation.ground_truth.GroundTruthField`` shape so the
    existing offset-based matcher (``rq1_accuracy.match_inferred_to_ground``)
    works without modification.
    """

    name: str
    offset_start: int
    offset_end: int  # -1 = variable/remainder
    wire_type: str
    semantic_role: str
    description: str = ""
    static_hex: Optional[str] = None
    valid_values: Optional[list[str]] = None

    @property
    def length(self) -> int:
        if self.offset_end == -1:
            return -1
        return self.offset_end - self.offset_start


# Common 4-letter FTP control commands (RFC 959 §4.1.1) — used as the
# enum vocabulary the LLM is expected to recognise.
FTP_COMMANDS_4LETTER = [
    "USER", "PASS", "ACCT", "QUIT", "PORT", "PASV", "TYPE", "STRU",
    "MODE", "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR",
    "RNTO", "ABOR", "DELE", "LIST", "NLST", "SITE", "STAT", "HELP",
    "NOOP",
]
# 3-letter commands (command offset becomes [0,3); still matches GT
# [0,4) via the ±1 start-tolerance in the evaluator).
FTP_COMMANDS_3LETTER = ["CWD", "CDUP"[:3], "SMNT"[:3], "RMD", "MKD", "PWD", "SYST"[:3], "REIN"[:3]]


FTP_GROUND_TRUTH: list[FTPGroundTruthField] = [
    FTPGroundTruthField(
        name="command",
        offset_start=0,
        offset_end=4,
        wire_type="enum",
        semantic_role="enum",
        description="FTP command verb (RFC 959 §4.1.1). 3–4 uppercase ASCII "
                    "letters. Discrete vocabulary — server dispatches on it. "
                    "On a canonical 4-letter command (USER/RETR/...) occupies "
                    "[0,4); 3-letter commands (CWD/MKD) occupy [0,3).",
        valid_values=FTP_COMMANDS_4LETTER + FTP_COMMANDS_3LETTER,
    ),
    FTPGroundTruthField(
        name="space",
        offset_start=4,
        offset_end=5,
        wire_type="bytes",
        semantic_role="static",
        description="Single space byte 0x20 separating command from argument "
                    "(RFC 959 §4.1.1: <command> <SP> <argument>). Constant.",
        static_hex="20",
    ),
    FTPGroundTruthField(
        name="argument",
        offset_start=5,
        offset_end=-2,
        wire_type="string",
        semantic_role="variable",
        description="Command argument — variable-length ASCII text after the "
                    "space (username, password, pathname, ...), before the "
                    "CRLF. Empty for argument-less commands (LIST, QUIT). "
                    "offset_end=-2 means 'up to 2 bytes before end' (CRLF).",
    ),
    FTPGroundTruthField(
        name="crlf",
        offset_start=-2,
        offset_end=-1,
        wire_type="bytes",
        semantic_role="static",
        description="CRLF line terminator (0x0D 0x0A) per RFC 959 §4.1.1. "
                    "Constant. offset_start=-2 means 'last 2 bytes'.",
        static_hex="0d0a",
    ),
]


def get_ftp_ground_truth_summary() -> dict:
    return {
        "protocol": "FTP Control Protocol (RFC 959)",
        "standard": "STD 9 / RFC 959 (1985)",
        "independent": True,
        "fields": [
            {
                "name": f.name,
                "offset": f"[{f.offset_start},{f.offset_end})",
                "type": f.wire_type,
                "role": f.semantic_role,
                "length": f.length,
            }
            for f in FTP_GROUND_TRUTH
        ],
    }
