"""
fast_loop/binary_mutator.py
───────────────────────────
Low-level, high-throughput binary mutation engine.

Operates on raw ``bytearray`` / ``memoryview`` at microsecond speed.
All mutations are in-place — no copies, no allocations on the hot path.

The ``mutate()`` method accepts an optional list of ``FieldGroup`` objects
from ``differential_analyzer.py``.  Fields labeled ``STATIC`` are never
touched — preserving protocol headers / magic bytes.

Design contract:
    - No async, no networking, no I/O — pure computation on bytearrays.
    - Optional ``seed`` for reproducibility (uses ``random.Random(seed)``).
    - Returns the *same* bytearray (mutated in-place) for chaining.
"""

from __future__ import annotations

import random
import struct
from typing import Optional

from slow_loop.differential_analyzer import FieldGroup, OffsetLabel

# ---------------------------------------------------------------------------
# Interesting constants (borrowed from AFL / libFuzzer heuristics)
# ---------------------------------------------------------------------------
_INTERESTING_1: list[int] = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]
_INTERESTING_2: list[int] = [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF]
_INTERESTING_4: list[int] = [
    0x00000000, 0x00000001,
    0x7FFFFFFF, 0x80000000,
    0xFFFFFFFE, 0xFFFFFFFF,
]
_ARITH_DELTAS: list[int] = [-1, +1, -2, +2, -16, +16, -128, +128, -32768, +32768]

# ---------------------------------------------------------------------------
# FTP Protocol Constants — token dictionary for FTP-aware mutations
# ---------------------------------------------------------------------------
CRLF: bytes = b"\r\n"

# Core FTP command tokens the mutator can inject or swap into packets
FTP_TOKENS: list[bytes] = [
    b"USER ",
    b"PASS ",
    b"SYST\r\n",
    b"PORT ",
    b"RETR ",
    b"STOR ",
    b"MKD ",
    b"QUIT\r\n",
    b"LIST\r\n",
    b"TYPE ",
    b"PWD\r\n",
    b"CWD ",
    b"DELE ",
    b"RMD ",
    b"NOOP\r\n",
    b"FEAT\r\n",
    b"SIZE ",
    b"RNFR ",
    b"RNTO ",
    b"ABOR\r\n",
    b"ALLO ",
    b"APPE ",
    b"HELP\r\n",
    b"MODE ",
    b"NLST ",
    b"PASV\r\n",
    b"SITE ",
    b"STAT\r\n",
    b"STOU\r\n",
    b"STRU ",
]

# All strategy names in stable order
ALL_STRATEGIES: list[str] = [
    "bit_flip_1",
    "bit_flip_2",
    "bit_flip_4",
    "byte_overwrite_1",
    "byte_overwrite_2",
    "byte_overwrite_4",
    "arith_add",
    "arith_sub",
    "interesting_1",
    "interesting_2",
    "interesting_4",
    "block_dup",
    "block_del",
    "block_truncate",
    "payload_extend",     # Grow payload + update length byte (triggers buffer overflows)
    "ftp_token_inject",   # FTP: inject a random FTP command token
    "ftp_token_replace",  # FTP: replace the current command with a different FTP token
    "ftp_arg_fuzz",       # FTP: fuzz the argument after a command token
    "ftp_crlf_insert",    # FTP: inject extra CRLF delimiters
]

# Binary-only strategies (no FTP awareness — used by non-FTP targets)
BINARY_ONLY_STRATEGIES: list[str] = ALL_STRATEGIES[:15]  # Exclude FTP strategies


class BinaryMutator:
    """Pure byte-level mutation engine for fuzzing.

    Parameters
    ----------
    seed : int | None
        If provided, an isolated RNG is created for reproducibility.
        If ``None``, the system ``random`` module is used (non-deterministic).
    """

    def __init__(self, seed: int | None = None) -> None:
        if seed is not None:
            self._rng: random.Random | random._random.Random = random.Random(seed)
        else:
            self._rng = random

    # ===================================================================
    # Public API
    # ===================================================================

    def mutate(
        self,
        data: bytearray,
        field_groups: list[FieldGroup] | None = None,
        strategies: list[str] | None = None,
    ) -> bytearray:
        """Mutate *data* in-place using a random strategy.

        Parameters
        ----------
        data : bytearray
            The packet buffer. Mutated **in-place** and also returned.
        field_groups : list[FieldGroup] | None
            Optional field layout from DifferentialAnalyzer. ``STATIC``
            regions are never modified.
        strategies : list[str] | None
            Allowlist of strategy names. Defaults to ``BINARY_ONLY_STRATEGIES``
            (the 15 generic operators). Protocol-specific operators (e.g. the
            4 FTP token strategies) are ONLY used when a ProtocolModule
            supplies them via ``strategies=`` — the core never injects
            protocol knowledge by default (black-box thesis).

        Returns
        -------
        bytearray
            The same object passed in (mutated in-place).
        """
        if len(data) == 0:
            return data

        # Pre-compute static ranges and mutable offsets ONCE per call
        sr = _build_static_ranges(field_groups)
        mutable = _compute_mutable_offsets(data, sr)

        if not mutable:
            return data

        # Default to the GENERIC binary operators only. The 4 FTP strategies
        # (ftp_token_inject/replace/arg/crlf) are protocol knowledge — they
        # must NEVER be selected unless a ProtocolModule explicitly offers
        # them, otherwise the core leaks FTP knowledge into non-FTP targets.
        allowed = strategies if strategies is not None else BINARY_ONLY_STRATEGIES
        strategy = self._rng.choice(allowed)
        self._apply_strategy(data, strategy, sr, mutable)
        return data

    # ===================================================================
    # Strategy dispatch
    # ===================================================================

    def _apply_strategy(
        self,
        data: bytearray,
        strategy: str,
        sr: list[tuple[int, int]],
        mutable: list[int],
    ) -> None:
        """Dispatch to the correct strategy implementation."""
        dispatch = {
            "bit_flip_1":       self._strat_bit_flip_1,
            "bit_flip_2":       self._strat_bit_flip_2,
            "bit_flip_4":       self._strat_bit_flip_4,
            "byte_overwrite_1": self._strat_byte_overwrite_1,
            "byte_overwrite_2": self._strat_byte_overwrite_2,
            "byte_overwrite_4": self._strat_byte_overwrite_4,
            "arith_add":        self._strat_arith_add,
            "arith_sub":        self._strat_arith_sub,
            "interesting_1":    self._strat_interesting_1,
            "interesting_2":    self._strat_interesting_2,
            "interesting_4":    self._strat_interesting_4,
            "block_dup":        self._strat_block_dup,
            "block_del":        self._strat_block_del,
            "block_truncate":   self._strat_block_truncate,
            "payload_extend":   self._strat_payload_extend,
            "ftp_token_inject":  self._strat_ftp_token_inject,
            "ftp_token_replace": self._strat_ftp_token_replace,
            "ftp_arg_fuzz":      self._strat_ftp_arg_fuzz,
            "ftp_crlf_insert":   self._strat_ftp_crlf_insert,
        }
        fn = dispatch.get(strategy)
        if fn is not None:
            fn(data, sr, mutable)

    # ===================================================================
    # Internal offset pickers (use pre-computed mutable list)
    # ===================================================================

    def _pick_offset(self, mutable: list[int]) -> int | None:
        """Return a random mutable byte offset, or None."""
        if not mutable:
            return None
        return self._rng.choice(mutable)

    def _pick_range(
        self,
        n: int,
        length: int,
        sr: list[tuple[int, int]],
        mutable: list[int],
    ) -> int | None:
        """Find a random contiguous *length*-byte region that is fully mutable.

        Returns the start offset, or None if no such region exists.
        Uses the pre-computed ``mutable`` set for fast rejection.
        """
        if length > n:
            return None
        if not sr:
            return self._rng.randint(0, n - length)

        mutable_set = set(mutable)
        candidates: list[int] = []
        for start in range(n - length + 1):
            # Check if [start, start+length) is fully mutable
            if all((start + i) in mutable_set for i in range(length)):
                candidates.append(start)

        if not candidates:
            return None
        return self._rng.choice(candidates)

    # ===================================================================
    # Bit-flip strategies
    # ===================================================================

    def _strat_bit_flip_1(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Flip exactly 1 random bit in a random mutable byte."""
        offset = self._pick_offset(mutable)
        if offset is None:
            return
        bit = self._rng.randint(0, 7)
        data[offset] ^= (1 << bit)

    def _strat_bit_flip_2(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Flip 2 adjacent bits in a random mutable byte."""
        offset = self._pick_offset(mutable)
        if offset is None:
            return
        start_bit = self._rng.randint(0, 6)  # 0..6 so bit+1 ≤ 7
        data[offset] ^= (0b11 << start_bit)

    def _strat_bit_flip_4(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Flip a random nibble (4 adjacent bits) in a mutable byte."""
        offset = self._pick_offset(mutable)
        if offset is None:
            return
        nibble_start = self._rng.choice([0, 4])
        data[offset] ^= (0b1111 << nibble_start)

    # ===================================================================
    # Byte-overwrite strategies
    # ===================================================================

    def _strat_byte_overwrite_1(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Overwrite 1 mutable byte with a random value."""
        offset = self._pick_offset(mutable)
        if offset is None:
            return
        data[offset] = self._rng.randint(0, 255)

    def _strat_byte_overwrite_2(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Overwrite 2 mutable bytes with a random 16-bit value (random endian)."""
        start = self._pick_range(len(data), 2, sr, mutable)
        if start is None:
            return
        fmt = self._rng.choice([">H", "<H"])
        val = self._rng.randint(0, 0xFFFF)
        struct.pack_into(fmt, data, start, val)

    def _strat_byte_overwrite_4(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Overwrite 4 mutable bytes with a random 32-bit value (random endian)."""
        start = self._pick_range(len(data), 4, sr, mutable)
        if start is None:
            return
        fmt = self._rng.choice([">I", "<I"])
        val = self._rng.randint(0, 0xFFFFFFFF)
        struct.pack_into(fmt, data, start, val)

    # ===================================================================
    # Arithmetic strategies
    # ===================================================================

    def _strat_arith(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int], sign: int) -> None:
        """Shared implementation for add/sub — pick 1/2/4-byte region, add delta."""
        width = self._rng.choice([1, 2, 4])
        start = self._pick_range(len(data), width, sr, mutable)
        if start is None:
            return
        fmt_map = {
            1: ("B", 0xFF),
            2: (self._rng.choice([">H", "<H"]), 0xFFFF),
            4: (self._rng.choice([">I", "<I"]), 0xFFFFFFFF),
        }
        fmt, mask = fmt_map[width]
        current = struct.unpack_from(fmt, data, start)[0]
        delta = self._rng.choice(_ARITH_DELTAS) * sign
        new_val = (current + delta) & mask
        struct.pack_into(fmt, data, start, new_val)

    def _strat_arith_add(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        self._strat_arith(data, sr, mutable, sign=+1)

    def _strat_arith_sub(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        self._strat_arith(data, sr, mutable, sign=-1)

    # ===================================================================
    # Interesting-value strategies
    # ===================================================================

    def _strat_interesting_1(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Overwrite 1 mutable byte with a known-interesting value."""
        offset = self._pick_offset(mutable)
        if offset is None:
            return
        data[offset] = self._rng.choice(_INTERESTING_1)

    def _strat_interesting_2(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Overwrite 2 mutable bytes with a known-interesting 16-bit value."""
        start = self._pick_range(len(data), 2, sr, mutable)
        if start is None:
            return
        fmt = self._rng.choice([">H", "<H"])
        val = self._rng.choice(_INTERESTING_2)
        struct.pack_into(fmt, data, start, val)

    def _strat_interesting_4(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Overwrite 4 mutable bytes with a known-interesting 32-bit value."""
        start = self._pick_range(len(data), 4, sr, mutable)
        if start is None:
            return
        fmt = self._rng.choice([">I", "<I"])
        val = self._rng.choice(_INTERESTING_4)
        struct.pack_into(fmt, data, start, val)

    # ===================================================================
    # Block strategies (change data length)
    # ===================================================================

    def _strat_block_dup(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Duplicate a random chunk of 8-64 bytes and insert at a mutable position.

        When static ranges are present, insertion is restricted to positions that
        will **not shift** any static bytes.  This means inserting only at the
        boundary *after* the last static region, or at the very end of the data.
        """
        n = len(data)
        if n < 8:
            return  # Need at least 8 bytes to duplicate a chunk

        chunk_len = self._rng.randint(8, min(64, n))
        src_start = self._rng.randint(0, n - chunk_len)
        chunk = bytes(data[src_start : src_start + chunk_len])

        if sr:
            # Earliest safe insertion point = end of the last static region.
            # Anything before that would shift at least one static byte.
            last_static_end = max(e for _, e in sr)
            if last_static_end >= n:
                return
            insert_at = self._rng.randint(last_static_end, n)
        else:
            insert_at = self._rng.randint(0, n)

        data[insert_at:insert_at] = chunk

    def _strat_block_del(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Delete a random chunk of 8-64 bytes from a mutable region."""
        n = len(data)
        if n < 8:
            return

        chunk_len = self._rng.randint(8, min(64, n))

        # Find a range to delete that doesn't overlap static regions
        start = self._pick_range(n, chunk_len, sr, mutable)
        if start is None:
            return
        del data[start : start + chunk_len]

    def _strat_block_truncate(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Truncate the data to 25%-100% of its original length, preserving all static regions."""
        n = len(data)
        if n < 2:
            return

        # Minimum length = end of the rightmost static region.
        # We must never cut into or past any static bytes.
        min_keep = 0
        if sr:
            min_keep = max(e for _, e in sr)

        lower = max(min_keep, n // 4)
        upper = n

        if lower >= upper:
            return

        new_len = self._rng.randint(lower, upper)
        if new_len < n:
            del data[new_len:]

    # ===================================================================
    # Payload Extension — grow packet to trigger buffer overflows
    # ===================================================================

    def _strat_payload_extend(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Extend the payload region with random bytes and update the length field.

        Designed to trigger buffer-overflow vulnerabilities in protocols like LIFA
        where a length byte at a fixed offset controls how much data is copied.

        Strategy:
            1. Determine the header length (end of last static region, or 6 for LIFA).
            2. Append 64–512 random bytes after the existing payload.
            3. Update the length byte (assumed at offset 5 for LIFA-style protocols)
               to reflect the new total payload size, clamped to 255 (uint8 max).
               The actual data may exceed 255 bytes — this mismatch is intentional
               and tests whether the server trusts the length byte or actual data.
        """
        n = len(data)
        if n < 6:
            return  # Need at least a header to make sense

        # Header boundary: end of last static region, or fallback to 6
        header_end = 6
        if sr:
            header_end = max(e for _, e in sr)

        # Append random payload bytes
        extend_len = self._rng.randint(64, 512)
        data.extend(bytearray(self._rng.getrandbits(8) for _ in range(extend_len)))

        # Update the length byte at offset 5 (LIFA protocol: byte 5 = payload length)
        # Clamp to 255 but allow actual data to be larger → length mismatch → overflow
        if len(data) > 5:
            new_payload_len = len(data) - 6  # total - header
            # Two modes: honest length (255 cap) or lie (set to actual huge value)
            if self._rng.random() < 0.5:
                # Mode 1: Cap at 255 (honest uint8 max, but actual data is larger)
                data[5] = min(new_payload_len, 255)
            else:
                # Mode 2: Expose raw lower byte (wrap-around lie).
                # E.g. payload_len=300 → data[5]=44 → server reads 44 bytes
                # but 300 were actually sent → heap buffer overflow.
                data[5] = new_payload_len & 0xFF

    # ===================================================================
    # FTP-aware mutation strategies
    # ===================================================================

    def _strat_ftp_token_inject(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Inject a random FTP command token into the packet.

        Strategy:
            Pick a random FTP token (e.g., b"USER ", b"RETR ", b"MKD ") and
            inject it at a safe position. Ensures CRLF termination.
            Tests whether the FTP server can handle unexpected command injection
            mid-packet or multiple commands in one packet.

        Static range safety: when static ranges exist, injection only happens
        at or after the last static boundary (same pattern as block_dup).
        """
        n = len(data)
        if not mutable:
            return

        token = self._rng.choice(FTP_TOKENS)

        # Ensure CRLF termination if the token doesn't already end with one
        if not token.endswith(CRLF):
            # 50% chance: add argument + CRLF, 50%: add just CRLF
            if self._rng.random() < 0.5:
                arg_len = self._rng.randint(1, 64)
                arg = bytearray(self._rng.getrandbits(8) for _ in range(arg_len))
                token = token + bytes(arg) + CRLF
            else:
                token = token + CRLF

        # Determine safe insertion position
        if sr:
            # Only insert after the last static boundary to avoid shifting static bytes
            last_static_end = max(e for _, e in sr)
            if last_static_end >= n:
                # No room after static regions — append at end instead
                data.extend(token)
                return
            # Insert between last_static_end and end
            pos = self._rng.randint(last_static_end, n)
        else:
            pos = self._rng.choice(mutable)
        data[pos:pos] = token

    def _strat_ftp_token_replace(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Replace the FTP command at the start of the packet with a different one.

        Strategy:
            Find the first SPACE or CRLF in the packet to determine the command
            boundary, then replace the command keyword with a different FTP token.
            Tests the server's command dispatch with unexpected command swaps.

        Static range safety: if any static range overlaps the command region
        (typically offset 0–5), the mutation is skipped entirely.
        """
        n = len(data)
        if n < 4:
            return

        # Guard: if any static range starts at or before offset 5 (max command
        # length), skip — we can't safely replace the command without risking
        # corruption of magic bytes or other static header fields.
        if sr:
            for s_start, s_end in sr:
                if s_start < 6:
                    return

        # Find end of command keyword: first SPACE or CRLF
        cmd_end = n
        for i in range(min(n, 16)):  # Commands are at most ~5 chars
            if data[i] == 0x20 or data[i:i+2] == b"\r\n":
                cmd_end = i
                break

        if cmd_end < 2:
            return

        # Pick a random FTP token to replace with
        new_token = self._rng.choice(FTP_TOKENS)
        # Remove trailing CRLF from replacement (we keep original's arg + CRLF)
        new_cmd = new_token.rstrip(b"\r\n").rstrip(b" ")

        # Replace command bytes in-place — only if same length or shorter
        # (never grow, which would shift subsequent static bytes)
        old_cmd_len = cmd_end
        new_cmd_bytes = new_cmd[:old_cmd_len]  # truncate to fit exactly
        data[:len(new_cmd_bytes)] = new_cmd_bytes
        # Pad remaining with spaces if new command is shorter
        for i in range(len(new_cmd_bytes), old_cmd_len):
            data[i] = 0x20

    def _strat_ftp_arg_fuzz(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Fuzz the argument portion of an FTP command.

        Strategy:
            Find the argument (bytes after the first SPACE, before CRLF) and
            apply byte-level mutations to it. This targets argument parsing bugs
            in path traversal, buffer overflows in filename handling, etc.

        Static range safety: argument growth only happens when no static ranges
        exist after the argument region. In-place mutations are always safe.
        """
        n = len(data)
        if n < 5:
            return

        # Find SPACE (command separator) and CRLF (line end)
        space_pos = -1
        crlf_pos = n  # default: end of packet
        for i in range(min(n, 16)):
            if data[i] == 0x20 and space_pos == -1:
                space_pos = i
            if i + 1 < n and data[i] == 0x0D and data[i + 1] == 0x0A:
                crlf_pos = i
                break
            if data[i] == 0x0A:  # bare LF
                crlf_pos = i
                break

        if space_pos == -1:
            return  # No argument separator found

        arg_start = space_pos + 1
        arg_end = crlf_pos

        if arg_start >= arg_end:
            # No argument — inject one only if safe (no static ranges after)
            if sr and any(s > arg_start for s, _ in sr):
                return  # Can't grow — would shift static bytes
            fuzz_arg = self._ftp_fuzz_argument()
            data[arg_start:arg_start] = fuzz_arg + CRLF
            return

        # Mutate the existing argument bytes (in-place — always safe)
        arg_len = arg_end - arg_start
        if arg_len <= 0:
            return

        # Apply 1-3 random byte mutations to the argument
        num_mutations = min(self._rng.randint(1, 3), arg_len)
        for _ in range(num_mutations):
            pos = arg_start + self._rng.randint(0, arg_len - 1)
            mutation_type = self._rng.choice(["overwrite", "flip", "interesting"])

            if mutation_type == "overwrite":
                data[pos] = self._rng.randint(0, 255)
            elif mutation_type == "flip":
                bit = self._rng.randint(0, 7)
                data[pos] ^= (1 << bit)
            else:  # interesting
                data[pos] = self._rng.choice(_INTERESTING_1)

        # 20% chance: replace entire argument with a known-bad string
        # Only if it won't shift static bytes
        if self._rng.random() < 0.2:
            bad_arg = self._ftp_fuzz_argument()
            # Only grow if no static ranges exist after arg_end
            can_grow = not sr or not any(s > arg_end for s, _ in sr)
            if can_grow:
                replace_len = min(len(bad_arg), arg_len + 32)
                data[arg_start:arg_end] = bad_arg[:replace_len] + CRLF
            else:
                # Must stay in-place — truncate bad_arg to fit
                data[arg_start:arg_end] = bad_arg[:arg_len]

    def _strat_ftp_crlf_insert(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Inject extra CRLF delimiters at random positions.

        Tests whether the FTP server handles:
            - Extra CRLF before commands (blank lines)
            - CRLF injection mid-command (command splitting)
            - Multiple consecutive CRLF (request smuggling)

        Static range safety: insertion only happens at safe positions that
        won't shift any static bytes (after the last static boundary).
        """
        if not mutable or len(data) < 2:
            return

        n = len(data)

        # Determine the safe insertion boundary
        if sr:
            last_static_end = max(e for _, e in sr)
            # All modes must insert at or after last_static_end
            safe_start = last_static_end
        else:
            safe_start = 0

        if safe_start >= n:
            # No room to insert without shifting static bytes — append only
            data.extend(CRLF)
            return

        # 3 modes of CRLF injection
        mode = self._rng.choice(["inject", "duplicate", "append"])

        if mode == "inject":
            # Insert CRLF at a safe position
            pos = self._rng.randint(safe_start, n)
            data[pos:pos] = CRLF

        elif mode == "duplicate":
            # Double an existing CRLF at a safe position
            positions = []
            for i in range(safe_start, n - 1):
                if data[i] == 0x0D and data[i + 1] == 0x0A:
                    positions.append(i)
            if positions:
                pos = self._rng.choice(positions)
                data[pos:pos] = CRLF
            else:
                # No CRLF found — just append
                data.extend(CRLF)

        else:  # append
            # Append CRLF at the end (always safe — no shifting)
            data.extend(CRLF)

    def _ftp_fuzz_argument(self) -> bytes:
        """Generate a fuzzed FTP argument string for injection.

        Produces strings targeting common FTP server vulnerabilities:
            - Path traversal (../../../)
            - Format strings (%s%s%s%n)
            - Null bytes
            - Oversized strings
            - Special characters
        """
        generators = [
            # Path traversal
            lambda: b"../../../etc/passwd",
            lambda: b"..\\..\\..\\windows\\system32",
            lambda: b"/" * 100 + b"AAAA",
            # Format string
            lambda: b"%s%s%s%s%n",
            lambda: b"%x" * 50,
            lambda: b"%n" * 30,
            # Null bytes
            lambda: b"test\x00hidden",
            lambda: b"\x00" * 8,
            # Oversized
            lambda: b"A" * self._rng.randint(256, 2048),
            lambda: b"f" * 65536,
            # Special characters
            lambda: b"'; DROP TABLE users;--",
            lambda: b"$(rm -rf /)",
            lambda: b"`cat /etc/passwd`",
            # Random
            lambda: bytearray(self._rng.getrandbits(8) for _ in range(self._rng.randint(4, 128))),
        ]
        return self._rng.choice(generators)()


# ===================================================================
# Module-level helpers (no self — avoid repeated bound-method lookups)
# ===================================================================

def _build_static_ranges(
    field_groups: list[FieldGroup] | None,
) -> list[tuple[int, int]]:
    """Return sorted list of (start, end) ranges that are STATIC."""
    if not field_groups:
        return []
    return sorted(
        (fg.start, fg.end) for fg in field_groups if fg.label == OffsetLabel.STATIC
    )


def _compute_mutable_offsets(
    data: bytearray,
    sr: list[tuple[int, int]],
) -> list[int]:
    """Return all byte offsets that are NOT in a static range.

    Uses an interval-subtraction algorithm instead of per-offset iteration,
    making it O(mutable + static) rather than O(len(data) * num_static).
    """
    n = len(data)
    if not sr:
        return list(range(n))

    # Build mutable intervals by subtracting static ranges from [0, n)
    intervals: list[tuple[int, int]] = []
    cursor = 0
    for s, e in sr:
        if cursor < s:
            intervals.append((cursor, s))
        cursor = max(cursor, e)
    if cursor < n:
        intervals.append((cursor, n))

    # Flatten intervals into a list of offsets
    result: list[int] = []
    for start, end in intervals:
        result.extend(range(start, end))
    return result
