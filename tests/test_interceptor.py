"""
tests/test_interceptor.py
──────────────────────────
Unit tests for the Fast Loop Interceptor.
"""

import pytest
import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

from fast_loop.interceptor import Interceptor
from shared.schemas import Direction, TrafficRecord


class TestInterceptorInit:
    """Tests for Interceptor initialization."""

    def test_default_params(self):
        interceptor = Interceptor()
        assert interceptor.listen_host == "0.0.0.0"
        assert interceptor.listen_port == 8001
        assert interceptor.upstream_host == "127.0.0.1"
        assert interceptor.upstream_port == 9000
        assert not interceptor.is_running
        assert interceptor.active_connections == 0

    def test_custom_params(self):
        interceptor = Interceptor(
            listen_host="192.168.1.1",
            listen_port=9999,
            upstream_host="target.local",
            upstream_port=8080,
        )
        assert interceptor.listen_host == "192.168.1.1"
        assert interceptor.listen_port == 9999
        assert interceptor.upstream_host == "target.local"
        assert interceptor.upstream_port == 8080


class TestInterceptorCapture:
    """Tests for packet capture functionality."""

    @pytest.mark.asyncio
    async def test_capture_creates_traffic_record(self):
        """capture_packet returns a TrafficRecord with correct fields."""
        interceptor = Interceptor(traffic_log_path="/tmp/test_interceptor.log")
        record = await interceptor.capture_packet(
            direction=Direction.CLIENT_TO_SERVER,
            raw_data=b"\xDE\xAD\xBE\xEF\x00\x0B",
        )
        assert isinstance(record, TrafficRecord)
        assert record.direction == Direction.CLIENT_TO_SERVER
        assert record.raw_hex == "deadbeef000b"
        assert record.packet_length == 6
        assert not record.is_mutated

    @pytest.mark.asyncio
    async def test_capture_writes_log_file(self):
        """capture_packet writes a JSONL line to the log file."""
        log_path = "/tmp/test_interceptor_log.log"
        Path(log_path).unlink(missing_ok=True)
        interceptor = Interceptor(traffic_log_path=log_path)
        await interceptor.capture_packet(
            direction=Direction.SERVER_TO_CLIENT,
            raw_data=b"\xFF\xFF",
        )
        # Manually drain write queue → buffer → disk (background writer is not running)
        while not interceptor._write_queue.empty():
            interceptor._write_buffer.append(interceptor._write_queue.get_nowait())
        if interceptor._write_buffer:
            with open(log_path, "a") as f:
                for line in interceptor._write_buffer:
                    f.write(line + "\n")
            interceptor._write_buffer.clear()
        # Verify file has one valid JSON line
        lines = Path(log_path).read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["direction"] == "server_to_client"
        assert record["payload"] == "ffff"
        Path(log_path).unlink(missing_ok=True)


class TestInterceptorInjection:
    """Tests for mutation injection."""

    @pytest.mark.asyncio
    async def test_inject_queues_mutation(self):
        """inject_mutation puts data in the mutation queue."""
        interceptor = Interceptor()
        assert interceptor.total_injected == 0
        await interceptor.inject_mutation(b"\x00\x00\x00\x00")
        # Queue should have one item
        assert interceptor._mutation_queue.qsize() == 1
