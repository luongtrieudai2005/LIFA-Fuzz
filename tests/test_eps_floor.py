"""
tests/test_eps_floor.py
───────────────────────
Performance regression test: assert EPS floor for both fresh and stateful
connection modes of the MutationEngine.

Uses a lightweight asyncio TCP echo server — no Docker or external deps.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from fast_loop.mutator import MutationEngine
from shared.schemas import ActiveRuleSet, Direction, SeedSequence, TrafficRecord


# ---------------------------------------------------------------------------
# TCP Echo Server
# ---------------------------------------------------------------------------

async def _start_echo_server(port: int) -> tuple[asyncio.Server, int]:
    """Start a simple TCP echo server on the given port."""
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle, "127.0.0.1", port)
    actual_port = server.sockets[0].getsockname()[1]
    return server, actual_port


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("connection_mode", ["fresh", "stateful"])
@pytest.mark.asyncio
async def test_eps_floor(connection_mode: str):
    """MutationEngine must sustain ≥200 EPS in both fresh and stateful modes."""
    # Start echo server on ephemeral port
    server, port = await _start_echo_server(0)

    try:
        seed_queue: asyncio.Queue = asyncio.Queue()

        # Pre-populate some seeds
        for i in range(5):
            seed_queue.put_nowait(
                SeedSequence(packets=[
                    TrafficRecord(
                        direction=Direction.CLIENT_TO_SERVER,
                        raw_data=b"\x01\x02\x03\x04\x05\x06\x07\x08",
                    ),
                ])
            )

        mutator = MutationEngine(
            target_host="127.0.0.1",
            target_port=port,
            seed_queue=seed_queue,
            k=2,
            max_eps=0,  # No throttling
            connection_timeout=2.0,
            recv_timeout=1.0,
            connection_mode=connection_mode,
        )

        # For stateful mode, set up packets
        if connection_mode == "stateful":
            rule_set = ActiveRuleSet(
                setup_packets=["48454C4C4F0A"],  # "HELLO\n" in hex
            )
            await mutator.update_rule_set(rule_set)

        # Send N payloads and measure throughput
        N = 100
        start = time.perf_counter()

        for _ in range(N):
            # Feed seeds continuously (wrap in SeedSequence for sequence-aware engine)
            seed_queue.put_nowait(
                SeedSequence(packets=[
                    TrafficRecord(
                        direction=Direction.CLIENT_TO_SERVER,
                        raw_data=b"\xDE\xAD\xBE\xEF" + os.urandom(4),
                    ),
                ])
            )
            # Drain + pick + mutate + send
            await mutator._drain_seeds()
            seq = mutator._pick_seed()
            if seq is None:
                continue

            target = mutator._split_sequence(seq)
            payload = await mutator._build_mutant(target.target_seed)

            if connection_mode == "stateful" and mutator._setup_packets:
                await mutator._send_stateful(payload, seq.sequence_id)
            else:
                await mutator._send(payload, seq.sequence_id)

        elapsed = time.perf_counter() - start
        eps = N / elapsed

        print(f"\n  [{connection_mode:9s}] {eps:,.0f} EPS ({elapsed:.3f}s for {N} payloads)")
        assert eps >= 200, (
            f"EPS floor violated: {eps:.0f} < 200 (mode={connection_mode})"
        )

    finally:
        server.close()
        await server.wait_closed()


# Need os for urandom
import os
