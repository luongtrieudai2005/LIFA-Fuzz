"""
tests/test_network_executor.py
──────────────────────────────
Unit tests for fast_loop/network_executor.py — NetworkExecutor.

All socket I/O is mocked via ``unittest.mock`` — no real network traffic.
"""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

from fast_loop.network_executor import (
    ExecutionResult,
    ExecutionStatus,
    NetworkExecutor,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tcp_executor() -> NetworkExecutor:
    return NetworkExecutor("127.0.0.1", 9000, protocol="TCP", timeout=0.05)


@pytest.fixture
def udp_executor() -> NetworkExecutor:
    return NetworkExecutor("127.0.0.1", 9000, protocol="UDP", timeout=0.05)


# ---------------------------------------------------------------------------
# TCP — success
# ---------------------------------------------------------------------------

class TestTCPSuccess:
    @patch("fast_loop.network_executor.socket.socket")
    def test_successful_send_and_recv(self, mock_socket_cls, tcp_executor):
        """TCP: connect → sendall → recv → OK."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.recv.return_value = b"RESPONSE"

        result = tcp_executor.send_payload(bytearray(b"\x01\x02\x03"))

        assert result.status == ExecutionStatus.OK
        assert result.response == b"RESPONSE"
        assert result.latency_ms >= 0
        mock_sock.connect.assert_called_once_with(("127.0.0.1", 9000))
        mock_sock.sendall.assert_called_once_with(b"\x01\x02\x03")
        mock_sock.close.assert_called_once()

    @patch("fast_loop.network_executor.socket.socket")
    def test_empty_response_is_still_ok(self, mock_socket_cls, tcp_executor):
        """TCP: graceful close (recv returns b'') is still OK."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.recv.return_value = b""

        result = tcp_executor.send_payload(bytearray(b"\xAA"))

        assert result.status == ExecutionStatus.OK
        assert result.response == b""
        mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# TCP — error mapping
# ---------------------------------------------------------------------------

class TestTCPTimeout:
    @patch("fast_loop.network_executor.socket.socket")
    def test_connect_timeout(self, mock_socket_cls, tcp_executor):
        """TimeoutError on connect → TIMEOUT."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect.side_effect = TimeoutError()

        result = tcp_executor.send_payload(bytearray(b"\x01"))

        assert result.status == ExecutionStatus.TIMEOUT
        assert result.response == b""
        mock_sock.close.assert_called_once()

    @patch("fast_loop.network_executor.socket.socket")
    def test_recv_timeout(self, mock_socket_cls, tcp_executor):
        """TimeoutError on recv → TIMEOUT (connect succeeds)."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.recv.side_effect = TimeoutError()

        result = tcp_executor.send_payload(bytearray(b"\x01"))

        assert result.status == ExecutionStatus.TIMEOUT
        mock_sock.sendall.assert_called_once()  # payload was sent
        mock_sock.close.assert_called_once()


class TestTCPConnectionRefused:
    @patch("fast_loop.network_executor.socket.socket")
    def test_connection_refused(self, mock_socket_cls, tcp_executor):
        """ConnectionRefusedError → CONNECTION_REFUSED."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect.side_effect = ConnectionRefusedError()

        result = tcp_executor.send_payload(bytearray(b"\x01"))

        assert result.status == ExecutionStatus.CONNECTION_REFUSED
        assert result.response == b""
        mock_sock.close.assert_called_once()


class TestTCPConnectionReset:
    @patch("fast_loop.network_executor.socket.socket")
    def test_connection_reset_on_connect(self, mock_socket_cls, tcp_executor):
        """ConnectionResetError on connect → CONNECTION_RESET."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect.side_effect = ConnectionResetError()

        result = tcp_executor.send_payload(bytearray(b"\x01"))

        assert result.status == ExecutionStatus.CONNECTION_RESET
        mock_sock.close.assert_called_once()

    @patch("fast_loop.network_executor.socket.socket")
    def test_broken_pipe_on_send(self, mock_socket_cls, tcp_executor):
        """BrokenPipeError on sendall → CONNECTION_RESET."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.sendall.side_effect = BrokenPipeError()

        result = tcp_executor.send_payload(bytearray(b"\x01"))

        assert result.status == ExecutionStatus.CONNECTION_RESET
        mock_sock.close.assert_called_once()

    @patch("fast_loop.network_executor.socket.socket")
    def test_connection_reset_on_recv(self, mock_socket_cls, tcp_executor):
        """ConnectionResetError on recv → CONNECTION_RESET."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.recv.side_effect = ConnectionResetError()

        result = tcp_executor.send_payload(bytearray(b"\x01"))

        assert result.status == ExecutionStatus.CONNECTION_RESET
        mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# TCP — socket close safety
# ---------------------------------------------------------------------------

class TestTCPCloseSafety:
    @patch("fast_loop.network_executor.socket.socket")
    def test_close_error_does_not_propagate(self, mock_socket_cls, tcp_executor):
        """OSError on sock.close() should be silently swallowed."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.recv.return_value = b"OK"
        mock_sock.close.side_effect = OSError("already closed")

        result = tcp_executor.send_payload(bytearray(b"\x01"))

        # Should still return a valid result — close error is caught
        assert result.status == ExecutionStatus.OK
        assert result.response == b"OK"


# ---------------------------------------------------------------------------
# TCP — OSError catch-all
# ---------------------------------------------------------------------------

class TestTCPOtherOSError:
    @patch("fast_loop.network_executor.socket.socket")
    def test_generic_oserror_maps_to_connection_reset(self, mock_socket_cls, tcp_executor):
        """Any unclassified OSError → CONNECTION_RESET."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect.side_effect = OSError("network is unreachable")

        result = tcp_executor.send_payload(bytearray(b"\x01"))

        assert result.status == ExecutionStatus.CONNECTION_RESET


# ---------------------------------------------------------------------------
# UDP — fire-and-forget
# ---------------------------------------------------------------------------

class TestUDPSuccess:
    @patch("fast_loop.network_executor.socket.socket")
    def test_udp_send_no_response(self, mock_socket_cls, udp_executor):
        """UDP: sendto succeeds, no response (timeout on recvfrom) → TIMEOUT."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.recvfrom.side_effect = TimeoutError()

        result = udp_executor.send_payload(bytearray(b"\x01\x02"))

        # sendto was called with the payload and address
        mock_sock.sendto.assert_called_once_with(b"\x01\x02", ("127.0.0.1", 9000))
        # No connect() for UDP
        mock_sock.connect.assert_not_called()
        # recvfrom timeout → TIMEOUT status
        assert result.status == ExecutionStatus.TIMEOUT
        assert result.response == b""
        mock_sock.close.assert_called_once()

    @patch("fast_loop.network_executor.socket.socket")
    def test_udp_send_with_response(self, mock_socket_cls, udp_executor):
        """UDP: sendto succeeds, response received → OK."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.recvfrom.return_value = (b"PONG", ("127.0.0.1", 9000))

        result = udp_executor.send_payload(bytearray(b"\x01\x02"))

        assert result.status == ExecutionStatus.OK
        assert result.response == b"PONG"

    @patch("fast_loop.network_executor.socket.socket")
    def test_udp_connection_refused(self, mock_socket_cls, udp_executor):
        """UDP: ICMP port unreachable on recvfrom → CONNECTION_REFUSED."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.recvfrom.side_effect = ConnectionRefusedError()

        result = udp_executor.send_payload(bytearray(b"\x01"))

        assert result.status == ExecutionStatus.CONNECTION_REFUSED


# ---------------------------------------------------------------------------
# Constructor and repr
# ---------------------------------------------------------------------------

class TestConstructor:
    def test_default_protocol_is_tcp(self):
        ex = NetworkExecutor("10.0.0.1", 8080)
        assert ex.protocol == "TCP"

    def test_protocol_case_insensitive(self):
        ex = NetworkExecutor("10.0.0.1", 8080, protocol="udp")
        assert ex.protocol == "UDP"

    def test_default_timeout(self):
        ex = NetworkExecutor("10.0.0.1", 8080)
        assert ex.timeout == 0.05

    def test_custom_timeout(self):
        ex = NetworkExecutor("10.0.0.1", 8080, timeout=1.0)
        assert ex.timeout == 1.0

    def test_repr(self):
        ex = NetworkExecutor("192.168.1.1", 443, protocol="TCP", timeout=0.1)
        r = repr(ex)
        assert "TCP" in r
        assert "192.168.1.1" in r
        assert "443" in r
        assert "0.1" in r


# ---------------------------------------------------------------------------
# ExecutionResult dataclass
# ---------------------------------------------------------------------------

class TestExecutionResult:
    def test_fields(self):
        r = ExecutionResult(
            status=ExecutionStatus.OK,
            response=b"hello",
            latency_ms=1.23,
        )
        assert r.status == ExecutionStatus.OK
        assert r.response == b"hello"
        assert r.latency_ms == 1.23

    @patch("fast_loop.network_executor.socket.socket")
    def test_latency_is_positive(self, mock_socket_cls, tcp_executor):
        """Even a mocked call should produce non-negative latency."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.recv.return_value = b"X"

        result = tcp_executor.send_payload(bytearray(b"\x00"))
        assert result.latency_ms >= 0


# ---------------------------------------------------------------------------
# ExecutionStatus enum
# ---------------------------------------------------------------------------

class TestExecutionStatus:
    def test_all_values(self):
        expected = {"ok", "timeout", "connection_refused", "connection_reset"}
        actual = {s.value for s in ExecutionStatus}
        assert actual == expected

    def test_is_string_enum(self):
        assert isinstance(ExecutionStatus.OK, str)
        assert ExecutionStatus.OK == "ok"


# ---------------------------------------------------------------------------
# Socket type selection
# ---------------------------------------------------------------------------

class TestSocketType:
    @patch("fast_loop.network_executor.socket.socket")
    def test_tcp_creates_stream_socket(self, mock_socket_cls, tcp_executor):
        mock_sock = mock_socket_cls.return_value
        mock_sock.recv.return_value = b""

        tcp_executor.send_payload(bytearray(1))

        mock_socket_cls.assert_called_once_with(
            socket.AF_INET, socket.SOCK_STREAM
        )

    @patch("fast_loop.network_executor.socket.socket")
    def test_udp_creates_dgram_socket(self, mock_socket_cls, udp_executor):
        mock_sock = mock_socket_cls.return_value
        mock_sock.recvfrom.side_effect = TimeoutError()

        udp_executor.send_payload(bytearray(1))

        mock_socket_cls.assert_called_once_with(
            socket.AF_INET, socket.SOCK_DGRAM
        )

    @patch("fast_loop.network_executor.socket.socket")
    def test_timeout_applied_to_socket(self, mock_socket_cls, tcp_executor):
        mock_sock = mock_socket_cls.return_value
        mock_sock.recv.return_value = b""

        tcp_executor.send_payload(bytearray(1))

        mock_sock.settimeout.assert_called_once_with(0.05)
