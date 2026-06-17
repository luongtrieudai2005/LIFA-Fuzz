"""
shared/protocol_module.py
─────────────────────────
ProtocolModule abstraction — keeps the Fast Loop CORE free of hardcoded
protocol knowledge (the black-box thesis), while allowing an explicit,
disclosed, opt-in module per case-study target.

Why this exists
---------------
LIFA-Fuzz's thesis is a *black-box fuzzer for unknown/proprietary protocols
with no documents*. That holds for the inference layer (Slow Loop: LLM +
DifferentialAnalyzer infer grammar from raw bytes) and the generic mutation
operators (``mutation_operators.py``). But the Fast Loop execution layer had
FTP knowledge HARDCODED — FTP status-code parsing, CRLF framing, an FTP-only
state tracker, and FTP token-injection operators that leaked into every
target via the ε-greedy havoc path. That prior knowledge contradicted the
"unknown protocol" claim.

This module defines the seam: the core depends only on the
``ProtocolModule`` interface. The default ``NullModule`` is pure black-box
(no protocol knowledge → no mutation/state/response assumptions). A target
may OPTIONALLY supply a richer module (e.g. ``FTPModule`` in
``fast_loop/ftp_module.py``) for a disclosed case study — but it is never
the default, and the core runs identically without it.

Layering: this file is in ``shared`` (low layer) and must NOT import from
``fast_loop``. Concrete modules with protocol-specific implementations live
in ``fast_loop`` and register themselves; the core only sees the interface.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:  # avoid runtime import cycle
    from shared.schemas import PacketStatus


class ProtocolModule(ABC):
    """Pluggable protocol knowledge for the Fast Loop execution layer.

    The core (MutationEngine) holds ONE ProtocolModule instance and delegates
    all protocol-specific decisions to it. ``NullModule`` (the default) makes
    the core behave as a pure black-box fuzzer. A case-study target supplies
    a concrete subclass (e.g. FTPModule) to add disclosed protocol knowledge.

    Implementations must be stateless w.r.t. mutation state (the engine owns
    send state); per-protocol *response* state (e.g. an FTP state-transition
    tracker) is owned by the object returned from :meth:`state_tracker`.
    """

    #: Human-readable module name (for logs/config).
    name: str = "null"

    @abstractmethod
    def binary_operators(self) -> list[str]:
        """Protocol-specific BinaryMutator strategy names to ADD to the
        generic set for this target. Empty list ⇒ core uses only the generic
        binary operators (pure black-box)."""

    @abstractmethod
    def extract_state_code(self, response: bytes) -> str:
        """Parse a server response into a discrete "state code" string
        (e.g. FTP "220", "331"). Return ``""`` if the protocol has no
        status-code concept (NullModule) so the engine skips state tracking."""

    @abstractmethod
    def extract_command(self, payload: bytes) -> str:
        """Parse a client→server payload into a command/label string for
        state-transition tracking. Return ``""`` if not applicable."""

    @abstractmethod
    def classify(self, response: bytes, payload: bytes) -> "PacketStatus":
        """Classify a server response into ACCEPTED / REJECTED (or other
        PacketStatus). Default black-box behaviour: any non-empty response ⇒
        ACCEPTED (server is alive and replied)."""

    @abstractmethod
    def ensure_framing(self, payload: bytes) -> bytes:
        """Apply protocol framing to an outbound payload (e.g. append CRLF
        for FTP). Identity (return payload unchanged) for protocols with no
        framing requirement."""

    @abstractmethod
    def state_tracker(self) -> Optional[Any]:
        """Return a state-transition tracker instance, or ``None`` to disable
        state tracking (the pure black-box default). The tracker's public
        surface is ``record_edge(prev_code, command, new_code, seq_id)``,
        ``unique_states``, ``unique_edges``, ``stats()`` — see
        ``fast_loop/state_transition_graph.py``."""

    @abstractmethod
    def response_sample_extra(self, response: bytes) -> dict[str, Any]:
        """Extra fields to log when sampling a response (e.g. FTP status
        code). Empty dict for protocols with no such concept."""

    @abstractmethod
    def response_category(self, response: bytes, payload: bytes) -> str:
        """SemFuzz-style 2-category response oracle (paper §3.4, Appendix C).

        Map a server response to ``"normal"`` or ``"error"`` per the
        protocol's response semantics (HTTP 200 vs 4xx/5xx, TLS
        handshake-continue vs Alert, etc.). Used by the semantic-violation
        oracle: a test that expects *error* but elicits *normal* is a
        potential semantic bug. Default black-box behaviour: an empty/absent
        reply ⇒ ``"error"``; any non-empty reply ⇒ ``"normal"`` (conservative).
        """

    @abstractmethod
    def violation_strategies(self) -> list:
        """Protocol-specific semantic-violation strategies (SemFuzz add/remove/
        update actions, each with an expected response category). Disclosed
        case-study content (e.g. RFC-959 FTP). Empty list ⇒ the core runs no
        semantic-violation path (pure black-box)."""


class NullModule(ProtocolModule):
    """The pure black-box core: NO protocol knowledge.

    This is the DEFAULT. With it, the Fast Loop:
      - mutates only with the generic binary operators (no token injection),
      - does no response/status parsing (any reply ⇒ ACCEPTED),
      - does no framing (payloads sent as-is),
      - runs NO state-transition tracking.

    A reviewer running the benchmark on any unknown protocol with this module
    gets a genuine black-box fuzzer — exactly the thesis. FTPModule is an
    opt-in, disclosed case-study extension, never the default.
    """

    name = "null"

    def binary_operators(self) -> list[str]:
        return []

    def extract_state_code(self, response: bytes) -> str:
        return ""

    def extract_command(self, payload: bytes) -> str:
        return ""

    def classify(self, response: bytes, payload: bytes) -> "PacketStatus":
        # Imported lazily to keep shared/ free of runtime schemas coupling at
        # module load (schemas is also shared, so this is fine).
        from shared.schemas import PacketStatus
        if not response:
            return PacketStatus.REJECTED
        return PacketStatus.ACCEPTED

    def ensure_framing(self, payload: bytes) -> bytes:
        return payload

    def state_tracker(self) -> Optional[Any]:
        """Return an InferredStateTracker if a P-PSM has been inferred
        (shared/state_machine.json exists), else None.

        Lazy import avoids circular dependency (fast_loop imports shared).
        The tracker re-reads the P-PSM file periodically, so it picks up
        the Slow Loop's output even though the file may not exist yet at
        init time.
        """
        try:
            from fast_loop.state_machine_tracker import InferredStateTracker
            return InferredStateTracker()
        except ImportError:
            return None

    def response_sample_extra(self, response: bytes) -> dict[str, Any]:
        return {}

    def response_category(self, response: bytes, payload: bytes) -> str:
        """Black-box default: empty reply ⇒ error, any reply ⇒ normal."""
        return "error" if not response else "normal"

    def violation_strategies(self) -> list:
        """No disclosed case-study violations — pure black-box."""
        return []


#: Registry of available module names → factory (populated by fast_loop modules).
#: The core resolves a config string ("ftp", "null") to a module here.
_MODULE_REGISTRY: dict[str, Any] = {"null": NullModule}


def register_protocol_module(name: str, factory: Any) -> None:
    """Register a concrete ProtocolModule factory under ``name``.

    Called by fast_loop protocol modules (e.g. FTPModule) at import time so
    the core can resolve ``protocol_module: ftp`` from config without a
    hard dependency on fast_loop from shared.
    """
    _MODULE_REGISTRY[name] = factory


def get_protocol_module(name: str) -> ProtocolModule:
    """Resolve a config name to a ProtocolModule instance (default NullModule)."""
    factory = _MODULE_REGISTRY.get(name, NullModule)
    return factory() if isinstance(factory, type) else factory
