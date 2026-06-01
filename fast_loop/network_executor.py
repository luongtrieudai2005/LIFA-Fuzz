"""
fast_loop/network_executor.py
──────────────────────────────
High-speed, synchronous network payload executor — the "Gun" of the fuzzing
pipeline.

Takes a mutated ``bytearray`` from ``BinaryMutator`` (the bullet), fires it
at the target over TCP or UDP, and classifies the outcome as a first-line
crash sensor.

Design contract:
    - **Synchronous** — no asyncio, no event loop.  Designed for a tight
      ``while True: executor.send_payload(m)`` hot loop.
    - **One-shot** — opens a fresh socket per call so crashes cannot corrupt
      the transport state.
    - **Exception-safe** — every socket error is caught and mapped to an
      ``ExecutionStatus``; the caller never sees a bare exception.
    - **Low-latency measurement** — uses ``time.perf_counter_ns()`` for
      sub-microsecond timing.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from shared.logger import get_logger

log = get_logger("fast_loop.network_executor")

# Maximum bytes to read from the target's response
_RECV_BUFFER_SIZE = 4096


# ===========================================================================
# Public types
# ===========================================================================

class ExecutionStatus(str, Enum):
    """Outcome of a single payload execution.

    Ordered from least to most suspicious — callers (CrashMonitor,
    MutationEngine) use this to decide what to do next.
    """

    OK                 = "ok"                  # Target responded or gracefully closed
    TIMEOUT            = "timeout"             # Target hung (potential infinite loop)
    CONNECTION_REFUSED = "connection_refused"  # Port closed — service may be DOWN
    CONNECTION_RESET   = "connection_reset"    # RST / broken pipe — strong CRASH signal


@dataclass(slots=True)
class ExecutionResult:
    """Result of firing one payload at the target.

    Attributes
    ----------
    status : ExecutionStatus
        How the target reacted.
    response : bytes
        Raw bytes the target sent back (``b""`` if no response or error).
    latency_ms : float
        Round-trip wall time in milliseconds (send + wait for response).
    """

    status: ExecutionStatus
    response: bytes
    latency_ms: float


# ===========================================================================
# NetworkExecutor — the Gun
# ===========================================================================

class NetworkExecutor:
    """Synchronous, one-shot payload executor.

    Parameters
    ----------
    target_ip : str
        IP address or hostname of the target service.
    target_port : int
        TCP/UDP port of the target service.
    protocol : str
        ``"TCP"`` (default) or ``"UDP"``.
    timeout : float
        Socket timeout in seconds (default 0.05 s / 50 ms).
        Controls both connect + recv deadline.
    """

    def __init__(
        self,
        target_ip: str,
        target_port: int,
        protocol: str = "TCP",
        timeout: float = 0.05,
    ) -> None:
        self.target_ip = target_ip
        self.target_port = target_port
        self.protocol = protocol.upper()
        self.timeout = timeout

        self._sock_family = socket.AF_INET
        self._sock_type = (
            socket.SOCK_STREAM if self.protocol == "TCP" else socket.SOCK_DGRAM
        )
        self._addr = (self.target_ip, self.target_port)

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def send_payload(self, payload: bytearray) -> ExecutionResult:
        """Fire *payload* at the target and return the classified result.

        Opens a fresh socket, sends, attempts to read a response (up to
        4096 bytes), and maps any exception to an ``ExecutionStatus``.

        Parameters
        ----------
        payload : bytearray
            The raw bytes to send.

        Returns
        -------
        ExecutionResult
            Status, response bytes, and measured latency.
        """
        t_start = time.perf_counter_ns()
        status = ExecutionStatus.OK
        response = b""

        sock = socket.socket(self._sock_family, self._sock_type)
        sock.settimeout(self.timeout)

        try:
            if self._sock_type == socket.SOCK_STREAM:
                # --- TCP: connect → send → recv ---
                sock.connect(self._addr)
                sock.sendall(payload)
                try:
                    response = sock.recv(_RECV_BUFFER_SIZE)
                except TimeoutError:
                    status = ExecutionStatus.TIMEOUT
                    response = b""
                except ConnectionResetError:
                    status = ExecutionStatus.CONNECTION_RESET
                    response = b""
            else:
                # --- UDP: sendto → optional recvfrom ---
                sock.sendto(payload, self._addr)
                try:
                    response, _ = sock.recvfrom(_RECV_BUFFER_SIZE)
                except TimeoutError:
                    status = ExecutionStatus.TIMEOUT
                    response = b""
                except ConnectionRefusedError:
                    # ICMP port unreachable — target is down
                    status = ExecutionStatus.CONNECTION_REFUSED
                    response = b""

        except ConnectionRefusedError:
            status = ExecutionStatus.CONNECTION_REFUSED
            response = b""
        except ConnectionResetError:
            status = ExecutionStatus.CONNECTION_RESET
            response = b""
        except BrokenPipeError:
            status = ExecutionStatus.CONNECTION_RESET
            response = b""
        except TimeoutError:
            status = ExecutionStatus.TIMEOUT
            response = b""
        except OSError as exc:
            # Catch-all: classify by errno or default to CONNECTION_RESET
            log.warning("OSError during send_payload: %s", exc)
            status = ExecutionStatus.CONNECTION_RESET
            response = b""
        finally:
            # Always close — never leak file descriptors
            try:
                sock.close()
            except OSError:
                pass

        t_end = time.perf_counter_ns()
        latency_ms = (t_end - t_start) / 1_000_000.0

        return ExecutionResult(
            status=status,
            response=response,
            latency_ms=latency_ms,
        )

    # -------------------------------------------------------------------
    # Utility
    # -------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"NetworkExecutor({self.protocol}://{self.target_ip}:"
            f"{self.target_port}, timeout={self.timeout}s)"
        )
