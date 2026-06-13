"""
slow_loop/parser.py
───────────────────
Traffic Parser — reads raw JSONL traffic from the Fast Loop, groups into
Interaction Sessions, augments with ASCII representation, and outputs
structured data payloads optimized for LLM comprehension.

Data Flow:
    shared/raw_traffic.jsonl (written by Interceptor)
        │
        ▼
    TrafficParser.read_log()
        │
        ▼
    list[InteractionSession]  (grouped by temporal proximity)
        │
        ▼
    TrafficParser.format_for_llm()  → JSON payload for LLMAgent

Session Grouping Logic:
    Packets are grouped into "sessions" based on temporal gaps:
    - If the time delta between consecutive packets exceeds a threshold
      (default: 2 seconds), a new session begins.
    - This approximates TCP connection boundaries without needing session IDs
      in the raw log.

ASCII Augmentation:
    For each packet, the parser adds a readable ASCII column:
        - Printable ASCII chars (0x20-0x7E) are shown as-is.
        - Non-printable bytes are shown as ``.`` (dot).
    This gives the LLM immediate visual context alongside the hex.

Output Format:
    The LLM payload is a JSON object with:
    {
        "session_count": int,
        "sessions": [
            {
                "session_id": int,
                "packet_count": int,
                "total_bytes": int,
                "packets": [
                    {
                        "seq": int,
                        "direction": str,
                        "hex": "deadbeef0005",
                        "ascii": "....?",
                        "length": int
                    }
                ]
            }
        ]
    }
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Optional

from shared.logger import get_logger

logger = get_logger("slow_loop.parser")


class InteractionSession:
    """A group of packets representing one interaction sequence.

    Packets are grouped by temporal proximity (gap > threshold
    starts a new session).

    Attributes:
        session_id:      Monotonically increasing session identifier.
        packets:         List of parsed packet dicts (hex + ascii + direction).
        start_time:      Timestamp of the first packet in the session.
        end_time:        Timestamp of the last packet in the session.
        total_bytes:     Total bytes across all packets in the session.
    """

    def __init__(self, session_id: int) -> None:
        self.session_id: int = session_id
        self.packets: list[dict[str, Any]] = []
        self.start_time: float = 0.0
        self.end_time: float = 0.0

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def total_bytes(self) -> int:
        return sum(p.get("length", 0) for p in self.packets)

    def add_packet(self, packet: dict[str, Any]) -> None:
        """Add a parsed packet to this session."""
        if not self.packets:
            self.start_time = packet.get("timestamp", time.time())
        self.end_time = packet.get("timestamp", time.time())
        self.packets.append(packet)


class TrafficParser:
    """Reads raw JSONL traffic log and produces structured sessions.

    Args:
        log_path:              Path to the JSONL traffic log.
        read_interval_ms:      How often to check for new entries.
        session_gap_threshold: Seconds of silence before starting a new session.
        max_packets_per_scan:  Maximum packets to process per read cycle.
    """

    def __init__(
        self,
        log_path: str = "shared/raw_traffic.jsonl",
        read_interval_ms: int = 5000,
        session_gap_threshold: float = 2.0,
        max_packets_per_scan: int = 100,
    ) -> None:
        self.log_path = Path(log_path)
        self.read_interval_ms = read_interval_ms
        self.session_gap_threshold = session_gap_threshold
        self.max_packets_per_scan = max_packets_per_scan

        self._last_read_position: int = 0
        self._total_packets_read: int = 0
        self._last_file_mtime: float = 0.0

    # -----------------------------------------------------------------
    # Core API
    # -----------------------------------------------------------------

    async def read_log(self) -> list[InteractionSession]:
        """Read the JSONL log and return grouped interaction sessions.

        Reads incrementally from the last known position.
        Groups consecutive packets into sessions based on temporal gaps.

        Returns:
            List of InteractionSession objects, ordered oldest first.
        """
        if not self.log_path.exists():
            logger.debug(f"Traffic log not found: {self.log_path}")
            return []

        try:
            with open(self.log_path, "r") as f:
                lines = f.readlines()
        except OSError as e:
            logger.error(f"Failed to read traffic log: {e}")
            return []

        # Detect file rotation/truncation — reset position if the file
        # was replaced or shrank. Without this, the parser silently
        # stops reading new packets after a rotation.
        try:
            cur_mtime = self.log_path.stat().st_mtime
        except OSError:
            cur_mtime = 0.0

        rotation_detected = False
        if self._last_read_position > len(lines):
            # File shrank — classic truncation/rotation
            rotation_detected = True
        elif self._last_file_mtime > 0 and cur_mtime < self._last_file_mtime - 1.0:
            # mtime went backwards — file was replaced (new inode).
            # Allow 1s tolerance for filesystem timestamp granularity.
            rotation_detected = True

        if rotation_detected:
            logger.info(
                f"Traffic log rotated/truncated "
                f"(last_pos={self._last_read_position}, lines={len(lines)}, "
                f"mtime {self._last_file_mtime:.1f}→{cur_mtime:.1f}) "
                f"— resetting read position"
            )
            self._last_read_position = 0

        self._last_file_mtime = cur_mtime

        # Parse new lines (incremental)
        new_entries: list[dict[str, Any]] = []
        for line in lines[self._last_read_position:]:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                new_entries.append(entry)
            except json.JSONDecodeError as e:
                logger.warning(f"Skipping malformed JSONL line: {e}")
                continue

        self._last_read_position = len(lines)
        self._total_packets_read += len(new_entries)

        if not new_entries:
            return []

        # Group into sessions
        sessions = self._group_into_sessions(new_entries)

        logger.info(
            f"Read {len(new_entries)} new packets "
            f"-> {len(sessions)} interaction sessions"
        )
        return sessions

    def format_for_llm(self, sessions: list[InteractionSession]) -> dict[str, Any]:
        """Format sessions into a structured JSON payload for the LLM.

        The output is designed to give the LLM maximum context:
        - Clear session boundaries.
        - Both hex AND ASCII representation side by side.
        - Packet counts and byte totals for pattern detection.

        Args:
            sessions: The interaction sessions to format.

        Returns:
            A dict ready to be serialized as JSON and sent to the LLM.
        """
        session_dicts: list[dict[str, Any]] = []

        for session in sessions:
            packets: list[dict[str, Any]] = []
            for idx, pkt in enumerate(session.packets):
                hex_payload = pkt.get("payload", "")
                # Safe length calculation — tolerate bad hex data from
                # corrupted traffic log entries instead of crashing the
                # entire Slow Loop inference cycle.
                try:
                    pkt_len = pkt.get("length", len(bytes.fromhex(hex_payload)))
                except (ValueError, TypeError):
                    # Odd-length or non-hex chars: estimate byte count from
                    # hex string length (2 hex chars = 1 byte).
                    pkt_len = pkt.get("length", len(hex_payload) // 2)

                packets.append({
                    "seq": idx,
                    "direction": pkt.get("direction", "unknown"),
                    "hex": hex_payload,
                    "ascii": self._bytes_to_ascii(hex_payload),
                    "length": pkt_len,
                })
            session_dicts.append({
                "session_id": session.session_id,
                "packet_count": session.packet_count,
                "total_bytes": session.total_bytes,
                "packets": packets,
            })

        return {
            "session_count": len(session_dicts),
            "sessions": session_dicts,
            "parser_note": (
                "Analyze the hex dumps below. Identify magic bytes, "
                "length fields, checksums, enum values, and any "
                "field boundaries that repeat across sessions."
            ),
        }

    # -----------------------------------------------------------------
    # Session Grouping
    # -----------------------------------------------------------------

    def _group_into_sessions(
        self, entries: list[dict[str, Any]]
    ) -> list[InteractionSession]:
        """Group entries into sessions based on temporal gaps.

        Consecutive packets with a time gap <= ``session_gap_threshold``
        belong to the same session. A gap exceeding the threshold
        starts a new session.

        Args:
            entries: Parsed JSONL entries, ordered by timestamp.

        Returns:
            List of InteractionSession objects.
        """
        if not entries:
            return []

        # Sort by timestamp (should already be ordered, but ensure)
        entries.sort(key=lambda e: e.get("timestamp", 0))

        sessions: list[InteractionSession] = []
        current_session = InteractionSession(session_id=len(sessions))

        for entry in entries:
            timestamp = entry.get("timestamp", 0)

            if current_session.packets:
                gap = timestamp - current_session.end_time
                if gap > self.session_gap_threshold:
                    # Gap too large — start new session
                    sessions.append(current_session)
                    current_session = InteractionSession(
                        session_id=len(sessions)
                    )

            current_session.add_packet(entry)

        sessions.append(current_session)
        return sessions

    # -----------------------------------------------------------------
    # ASCII Conversion
    # -----------------------------------------------------------------

    @staticmethod
    def _bytes_to_ascii(hex_str: str) -> str:
        """Convert a hex string to a human-readable ASCII representation.

        Printable ASCII characters (0x20–0x7E) are shown as-is.
        All other bytes are represented as ``.`` (dot).

        Examples:
            "deadbeef0005" → "?????."
            "48454c4c4f"  → "HELLO"
            "00010203ff"   → "....?"

        Args:
            hex_str: Hex string (e.g., "deadbeef").

        Returns:
            ASCII representation string of the same length.
        """
        result: list[str] = []
        for i in range(0, len(hex_str), 2):
            hex_byte = hex_str[i:i+2]
            if len(hex_byte) < 2:
                result.append(".")
                continue
            try:
                byte_val = int(hex_byte, 16)
            except ValueError:
                # Non-hex character (e.g. 'g', 'z') — render as dot
                result.append(".")
                continue
            if 0x20 <= byte_val <= 0x7E:
                result.append(chr(byte_val))
            else:
                result.append(".")
        return "".join(result)

    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        """Convert a hex string to bytes.

        Handles both contiguous ("deadbeef") and space-separated
        ("de ad be ef") formats.

        Args:
            hex_str: Hex string to convert.

        Returns:
            Raw bytes.
        """
        cleaned = hex_str.replace(" ", "")
        if len(cleaned) % 2 != 0:
            raise ValueError(f"Odd-length hex string: {hex_str!r}")
        return bytes.fromhex(cleaned)

    # -----------------------------------------------------------------
    # Lightweight Pattern Detection (pre-analysis)
    # -----------------------------------------------------------------

    @staticmethod
    def find_common_prefix(
        sessions: list[InteractionSession],
        direction: str = "client_to_server",
    ) -> tuple[int, str]:
        """Find the longest common byte prefix across all client→server packets.

        Useful for detecting magic bytes / protocol headers.

        Args:
            sessions: Interaction sessions to analyze.
            direction: Which direction to analyze.

        Returns:
            Tuple of (prefix_length, hex_string).
        """
        all_hex: list[str] = []
        for session in sessions:
            for pkt in session.packets:
                if pkt.get("direction") == direction:
                    all_hex.append(pkt.get("payload", ""))

        if not all_hex:
            return (0, "")

        prefix = all_hex[0]
        for hex_data in all_hex[1:]:
            # Find common prefix length in characters (2 chars = 1 byte).
            # Iterate by 2 (byte-aligned) to avoid slicing across nibble
            # boundaries which produces odd-length hex strings.
            common_len = 0
            max_pos = min(len(prefix), len(hex_data))
            for i in range(0, max_pos - 1, 2):
                if prefix[i:i+2] == hex_data[i:i+2]:
                    common_len = i + 2
                else:
                    break
            prefix = prefix[:common_len]

        return (len(prefix) // 2, prefix)

    @staticmethod
    def detect_length_field(
        sessions: list[InteractionSession],
    ) -> Optional[dict[str, Any]]:
        """Heuristic: find a byte range whose decoded value correlates
        with packet length.

        Checks 1, 2, and 4-byte fields at each offset.

        Args:
            sessions: Interaction sessions to analyze.

        Returns:
            Dict with ``offset``, ``size``, ``correlation`` if found.
        """
        all_hex: list[str] = []
        for session in sessions:
            for pkt in session.packets:
                if pkt.get("direction") == "client_to_server":
                    all_hex.append(pkt.get("payload", ""))

        if len(all_hex) < 5:
            return None

        # Check offsets for 1, 2, 4-byte fields
        max_offset = min(len(h) for h in all_hex) // 2
        best_offset = 0
        best_size = 2
        best_corr = 0.0

        for offset in range(0, max(0, max_offset - 1)):
            for size in (1, 2, 4):
                byte_count = 0
                total_corr = 0.0
                for hex_data in all_hex:
                    pkt_len = len(hex_data) // 2
                    end = offset + size
                    if end * 2 > len(hex_data) or offset * 2 >= len(hex_data):
                        continue
                    try:
                        field_bytes = bytes.fromhex(hex_data[offset * 2:end * 2])
                        field_val = int.from_bytes(
                            field_bytes, byteorder="little"
                        )
                        if field_val == pkt_len - (offset + size):
                            total_corr += 1.0
                        byte_count += 1
                    except (ValueError, IndexError):
                        continue

                if byte_count > 0:
                    corr = total_corr / byte_count
                    if corr > best_corr:
                        best_corr = corr
                        best_offset = offset
                        best_size = size

        if best_corr >= 0.5:
            return {
                "offset": best_offset,
                "size": best_size,
                "correlation": round(best_corr, 2),
            }
        return None
