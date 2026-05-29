"""
shared/__init__.py
──────────────────
Shared utilities, schemas, and configuration for LIFA-Fuzz.

Re-exports commonly used symbols for convenient imports:
    >>> from shared import SemanticRule, TrafficRecord, get_logger
    >>> from shared import BaseSandbox, get_driver, SandboxDriver
"""

from shared.logger import get_logger, setup_root_logger
from shared.sandbox_abstraction import (
    BaseSandbox,
    CrashInfo,
    ContainerInfo,
    SANDBOX_DRIVERS,
    SandboxDriver,
    SandboxError,
    SandboxNetworkError,
    SandboxResetError,
    SandboxStartError,
    get_driver,
    register_driver,
)
from shared.schemas import (
    ActiveRuleSet,
    CrashRecord,
    Direction,
    FieldType,
    InferredField,
    MutationConstraints,
    ProtocolGrammar,
    RuleType,
    SemanticRule,
    Signal,
    TrafficRecord,
)

__all__ = [
    # Schemas
    "TrafficRecord",
    "SemanticRule",
    "MutationConstraints",
    "ActiveRuleSet",
    "CrashRecord",
    "ProtocolGrammar",
    "InferredField",
    # Enums
    "Direction",
    "RuleType",
    "FieldType",
    "Signal",
    "SandboxDriver",
    # Sandbox
    "BaseSandbox",
    "ContainerInfo",
    "CrashInfo",
    "SandboxError",
    "SandboxStartError",
    "SandboxResetError",
    "SandboxNetworkError",
    "get_driver",
    "register_driver",
    "SANDBOX_DRIVERS",
    # Logger
    "get_logger",
    "setup_root_logger",
]
