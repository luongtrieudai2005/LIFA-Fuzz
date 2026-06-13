"""
slow_loop/ftp_response_analyzer.py
──────────────────────────────────
FTP Response Analyzer — extracts 3-digit FTP status codes from server
responses and maps protocol state transitions to execution reward
intensity for the EWMA adaptive controller.

Protocol (RFC 959):
    FTP responses follow the format:
        <3-digit-code><space><text><CRLF>
    Multi-line:  <code>-<text> ... <code><space><text>

Status Code Ranges:
    1xx — Positive Preliminary reply
    2xx — Positive Completion reply
    3xx — Positive Intermediate reply
    4xx — Transient Negative Completion
    5xx — Permanent Negative Completion

Auth Depth Mapping (for EWMA execution reward):
    0 — Pre-auth or rejected (220, 530, 500-599)
    1 — Username accepted, awaiting password (331)
    2 — Fully authenticated / deep state (230, 215, 257, 226, 150)
    The deeper the state, the higher the execution reward intensity,
    because reaching deep states exercises more parser code paths.

Integration:
    - Called from MutationEngine._record_response_sample() when the
      target is an FTP server (target_name == "lightftp").
    - Outputs an auth_depth metric to the EWMA response buffer so
      the Slow Loop can adjust coverage sampling accordingly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

from shared.logger import get_logger

log = get_logger("slow_loop.ftp_response_analyzer")


# =============================================================================
# FTP Status Code → Auth Depth Mapping
# =============================================================================

class FTPAuthDepth(IntEnum):
    """Authentication depth reached in the FTP session.

    Higher values indicate deeper protocol state reached, which means
    more server code paths exercised → higher execution reward intensity.
    """
    PRE_AUTH = 0       # Connection established, not yet authenticated
    USER_ACCEPTED = 1  # Username accepted, awaiting password
    AUTHENTICATED = 2  # Fully logged in — deep state


# Maps FTP status code → auth depth and description
_FTP_STATUS_MAP: dict[str, tuple[FTPAuthDepth, str]] = {
    # ── Positive Preliminary (1xx) ────────────────────────────────────
    "110": (FTPAuthDepth.AUTHENTICATED, "Restart marker reply"),
    "120": (FTPAuthDepth.AUTHENTICATED, "Service ready in NNN minutes"),
    "125": (FTPAuthDepth.AUTHENTICATED, "Data connection already open; transfer starting"),
    "150": (FTPAuthDepth.AUTHENTICATED, "File status okay; about to open data connection"),
    # ── Positive Completion (2xx) ─────────────────────────────────────
    "200": (FTPAuthDepth.PRE_AUTH, "Command okay"),
    "202": (FTPAuthDepth.PRE_AUTH, "Command not implemented, superfluous at this site"),
    "211": (FTPAuthDepth.AUTHENTICATED, "System status / HELP reply"),
    "212": (FTPAuthDepth.AUTHENTICATED, "Directory status"),
    "213": (FTPAuthDepth.AUTHENTICATED, "File status"),
    "214": (FTPAuthDepth.PRE_AUTH, "Help message"),
    "215": (FTPAuthDepth.AUTHENTICATED, "NAME system type"),
    "220": (FTPAuthDepth.PRE_AUTH, "Service ready for new user"),
    "221": (FTPAuthDepth.PRE_AUTH, "Service closing control connection"),
    "225": (FTPAuthDepth.AUTHENTICATED, "Data connection open; no transfer in progress"),
    "226": (FTPAuthDepth.AUTHENTICATED, "Closing data connection — transfer complete"),
    "227": (FTPAuthDepth.AUTHENTICATED, "Entering Passive Mode"),
    "228": (FTPAuthDepth.AUTHENTICATED, "Long Passive Mode"),
    "229": (FTPAuthDepth.AUTHENTICATED, "Extended Passive Mode Entered"),
    "230": (FTPAuthDepth.AUTHENTICATED, "User logged in, proceed"),
    "231": (FTPAuthDepth.AUTHENTICATED, "User logged out; service terminated"),
    "234": (FTPAuthDepth.PRE_AUTH, "Authenticate with TLS/SSL"),
    "250": (FTPAuthDepth.AUTHENTICATED, "Requested file action okay, completed"),
    "257": (FTPAuthDepth.AUTHENTICATED, '"PATHNAME" created'),
    # ── Positive Intermediate (3xx) ───────────────────────────────────
    "331": (FTPAuthDepth.USER_ACCEPTED, "User name okay, need password"),
    "332": (FTPAuthDepth.PRE_AUTH, "Need account for login"),
    "350": (FTPAuthDepth.AUTHENTICATED, "Requested file action pending further info"),
    # ── Transient Negative (4xx) ──────────────────────────────────────
    "421": (FTPAuthDepth.PRE_AUTH, "Service not available, closing control connection"),
    "425": (FTPAuthDepth.AUTHENTICATED, "Can't open data connection"),
    "426": (FTPAuthDepth.AUTHENTICATED, "Connection closed; transfer aborted"),
    "430": (FTPAuthDepth.PRE_AUTH, "Invalid username or password"),
    "434": (FTPAuthDepth.PRE_AUTH, "Requested host unavailable"),
    "450": (FTPAuthDepth.AUTHENTICATED, "Requested file action not taken"),
    "451": (FTPAuthDepth.AUTHENTICATED, "Requested action aborted: local error in processing"),
    "452": (FTPAuthDepth.AUTHENTICATED, "Insufficient storage space"),
    # ── Permanent Negative (5xx) ──────────────────────────────────────
    "500": (FTPAuthDepth.PRE_AUTH, "Syntax error, command unrecognized"),
    "501": (FTPAuthDepth.PRE_AUTH, "Syntax error in parameters or arguments"),
    "502": (FTPAuthDepth.PRE_AUTH, "Command not implemented"),
    "503": (FTPAuthDepth.PRE_AUTH, "Bad sequence of commands"),
    "504": (FTPAuthDepth.PRE_AUTH, "Command not implemented for that parameter"),
    "530": (FTPAuthDepth.PRE_AUTH, "Not logged in"),
    "532": (FTPAuthDepth.PRE_AUTH, "Need account for storing files"),
    "550": (FTPAuthDepth.AUTHENTICATED, "Requested action not taken — file unavailable"),
    "551": (FTPAuthDepth.AUTHENTICATED, "Requested action aborted: page type unknown"),
    "552": (FTPAuthDepth.AUTHENTICATED, "Requested file action aborted — exceeded storage"),
    "553": (FTPAuthDepth.AUTHENTICATED, "Requested action not taken — file name not allowed"),
}


# Regex for FTP response: 3 digits followed by space or hyphen
_FTP_RESPONSE_RE = re.compile(rb"^(\d{3})[ -]")


# =============================================================================
# FTP Response Analyzer
# =============================================================================


@dataclass
class FTPResponseResult:
    """Result of analyzing one or more FTP server responses."""
    status_code: str = "000"
    auth_depth: FTPAuthDepth = FTPAuthDepth.PRE_AUTH
    description: str = ""
    is_valid_ftp: bool = False

    def to_ewma_reward(self) -> float:
        """Convert auth depth to EWMA execution reward intensity.

        Returns:
            Reward ∈ [0.0, 1.0]. Higher = deeper state reached.
            - PRE_AUTH (0) → 0.1 (low reward, server only parsed header)
            - USER_ACCEPTED (1) → 0.5 (moderate, USER handler exercised)
            - AUTHENTICATED (2) → 1.0 (high, deep code paths exercised)
        """
        mapping = {
            FTPAuthDepth.PRE_AUTH: 0.1,
            FTPAuthDepth.USER_ACCEPTED: 0.5,
            FTPAuthDepth.AUTHENTICATED: 1.0,
        }
        return mapping.get(self.auth_depth, 0.1)


@dataclass
class FTPSessionState:
    """Tracks the cumulative auth depth across an FTP session.

    The EWMA controller uses the maximum auth depth reached in a session
    to compute execution reward intensity. This ensures that successfully
    authenticating even once yields high reward for the entire session.
    """
    max_auth_depth: FTPAuthDepth = FTPAuthDepth.PRE_AUTH
    response_count: int = 0
    status_codes_seen: set[str] = field(default_factory=set)

    def update(self, result: FTPResponseResult) -> None:
        """Update session state with a new response result."""
        self.response_count += 1
        if result.auth_depth > self.max_auth_depth:
            self.max_auth_depth = result.auth_depth
        self.status_codes_seen.add(result.status_code)

    def to_ewma_reward(self) -> float:
        """Return the reward based on max auth depth reached."""
        mapping = {
            FTPAuthDepth.PRE_AUTH: 0.1,
            FTPAuthDepth.USER_ACCEPTED: 0.5,
            FTPAuthDepth.AUTHENTICATED: 1.0,
        }
        return mapping.get(self.max_auth_depth, 0.1)


class FTPResponseAnalyzer:
    """Stateless analyzer for FTP server responses.

    Usage:
        analyzer = FTPResponseAnalyzer()
        result = analyzer.analyze(response_bytes)
        reward = result.to_ewma_reward()

    Example:
        >>> analyzer = FTPResponseAnalyzer()
        >>> r = analyzer.analyze(b"230 User logged in, proceed.\\r\\n")
        >>> r.status_code
        '230'
        >>> r.auth_depth
        <FTPAuthDepth.AUTHENTICATED: 2>
        >>> r.to_ewma_reward()
        1.0
    """

    def __init__(self) -> None:
        self._session = FTPSessionState()

    def analyze(self, response: bytes) -> FTPResponseResult:
        """Analyze a single FTP server response.

        Extracts the 3-digit status code and maps it to auth depth.

        Args:
            response: Raw bytes from the FTP server.

        Returns:
            FTPResponseResult with status code, auth depth, and reward.
        """
        if not response or len(response) < 3:
            return FTPResponseResult(
                status_code="000",
                auth_depth=FTPAuthDepth.PRE_AUTH,
                is_valid_ftp=False,
            )

        # Match the 3-digit status code at the start of the response
        match = _FTP_RESPONSE_RE.match(response)
        if not match:
            return FTPResponseResult(
                status_code="000",
                auth_depth=FTPAuthDepth.PRE_AUTH,
                is_valid_ftp=False,
            )

        code = match.group(1).decode("ascii", errors="replace")

        # Look up auth depth from the status map
        if code in _FTP_STATUS_MAP:
            auth_depth, description = _FTP_STATUS_MAP[code]
        else:
            # Unknown code — infer from first digit
            auth_depth = self._infer_depth_from_class(code)
            description = f"Unknown FTP status code: {code}"

        result = FTPResponseResult(
            status_code=code,
            auth_depth=auth_depth,
            description=description,
            is_valid_ftp=True,
        )

        # Only update session state for valid FTP responses — avoid pollution
        # from garbage/malformed data skewing the EWMA reward calculation.
        self._session.update(result)

        return result

    def analyze_multi(self, responses: list[bytes]) -> list[FTPResponseResult]:
        """Analyze multiple FTP responses (e.g., a multi-line response).

        Args:
            responses: List of raw response bytes.

        Returns:
            List of FTPResponseResult, one per response.
        """
        return [self.analyze(r) for r in responses]

    @staticmethod
    def _infer_depth_from_class(code: str) -> FTPAuthDepth:
        """Infer auth depth from the response class (first digit).

        Used when the exact status code is not in _FTP_STATUS_MAP.
        Conservative: default to PRE_AUTH unless we have strong evidence
        of a deeper state (class 3xx = intermediate = USER_ACCEPTED).
        """
        if not code or len(code) != 3 or not code[0].isdigit():
            return FTPAuthDepth.PRE_AUTH
        cls = int(code[0])
        if cls == 3:
            return FTPAuthDepth.USER_ACCEPTED
        # All other classes (1xx/2xx/4xx/5xx) default PRE_AUTH
        # to avoid inflating reward on unknown codes.
        return FTPAuthDepth.PRE_AUTH

    @property
    def session(self) -> FTPSessionState:
        """Current session state (accumulated across all responses)."""
        return self._session

    def reset_session(self) -> None:
        """Reset session state for a new FTP session."""
        self._session = FTPSessionState()


# =============================================================================
# Utility: Extract all FTP status codes from a raw response buffer
# =============================================================================


def extract_ftp_status_codes(data: bytes) -> list[str]:
    """Extract all 3-digit FTP status codes from a byte buffer.

    Handles multi-line responses where each line starts with a code.
    Useful for batch analysis of response_buffer.jsonl entries.

    Args:
        data: Raw bytes potentially containing multiple FTP responses.

    Returns:
        List of 3-digit status code strings (e.g., ["220", "331", "230"]).
    """
    codes: list[str] = []
    if not data:
        return codes
    try:
        text = data.decode("ascii", errors="replace")
        for line in text.split("\r\n"):
            line = line.strip()
            if len(line) >= 3 and line[:3].isdigit():
                codes.append(line[:3])
    except Exception:
        pass
    return codes
