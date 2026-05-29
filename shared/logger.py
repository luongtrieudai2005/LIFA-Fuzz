"""
shared/logger.py
────────────────
Structured asynchronous logging setup for LIFA-Fuzz.

Why a custom setup?
    LIFA-Fuzz has 3+ async processes (Fast Loop, Slow Loop, Crash Monitor)
    generating high-volume event streams. Standard ``print()`` is useless
    for debugging async race conditions. This module provides:

    1. **Per-component loggers** — each block gets its own named logger
       so you can filter by component (e.g., ``fast_loop.interceptor``).

    2. **Structured output** — JSON format for machine parsing, text for humans.
       Controlled via ``config.yaml``.

    3. **File rotation** — prevent disk exhaustion during long fuzz campaigns.

    4. **Correlation IDs** — every packet/mutation/rule/crash gets a unique ID
       that propagates through the entire pipeline for traceability.

Usage:
    >>> from shared.logger import get_logger
    >>> log = get_logger("fast_loop.interceptor")
    >>> log.info("packet_captured", packet_id="abc123", length=64, direction="c2s")
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Any, Optional


# =============================================================================
# Constants
# =============================================================================

DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_FORMAT = "text"  # "text" or "json"
DEFAULT_LOG_FILE: Optional[str] = None  # None = stdout only

# Cache of created loggers to avoid duplicate handler setup
_logger_cache: dict[str, logging.Logger] = {}


# =============================================================================
# Custom JSON Formatter
# =============================================================================


class JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON line.

    This is ideal for:
    - Piping into jq / grep
    - Feeding into ELK / Loki / Datadog
    - Structured analysis by the LLM (Block 3)
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Attach any extra fields passed via the ``extra`` kwarg
        if hasattr(record, "correlation_id"):
            log_entry["correlation_id"] = record.correlation_id  # type: ignore[attr-defined]
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Merge any arbitrary extra kwargs
        for key, value in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "created", "relativeCreated",
                "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                "pathname", "filename", "module", "thread", "threadName",
                "process", "processName", "levelname", "levelno", "message",
                "msecs", "taskName", "correlation_id",
            }:
                log_entry[key] = value

        return json.dumps(log_entry, default=str)


class RichTextFormatter(logging.Formatter):
    """Human-readable format with level prefixes for quick scanning.

    Example output:
        [2025-01-15 10:30:45] [INFO] fast_loop.interceptor: packet_captured length=64 dir=c2s
    """

    LEVEL_PREFIXES = {
        "DEBUG": "DBG",
        "INFO": "INF",
        "WARNING": "WRN",
        "ERROR": "ERR",
        "CRITICAL": "CRT",
    }

    def format(self, record: logging.LogRecord) -> str:
        emoji = self.LEVEL_PREFIXES.get(record.levelname, "  ")
        timestamp = self.formatTime(record, self.datefmt)

        # Build extra fields string
        extra_parts = []
        for key, value in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "created", "relativeCreated",
                "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                "pathname", "filename", "module", "thread", "threadName",
                "process", "processName", "levelname", "levelno", "message",
                "msecs", "taskName", "correlation_id",
            }:
                extra_parts.append(f"{key}={value}")
        extra_str = " ".join(extra_parts)

        base = f"[{timestamp}] {emoji} [{record.levelname}] {record.name}: {record.getMessage()}"
        if extra_str:
            base += f" | {extra_str}"
        if record.exc_info and record.exc_info[0] is not None:
            base += "\n" + self.formatException(record.exc_info)
        return base


# =============================================================================
# Logger Factory
# =============================================================================


def get_logger(
    name: str,
    level: str = DEFAULT_LOG_LEVEL,
    log_format: str = DEFAULT_LOG_FORMAT,
    log_file: Optional[str] = DEFAULT_LOG_FILE,
) -> logging.Logger:
    """Create or retrieve a named logger with the appropriate handlers.

    This function is **idempotent** — calling it twice with the same ``name``
    returns the same logger instance without adding duplicate handlers.

    Args:
        name:       Logger name (dot-namespaced, e.g. ``"fast_loop.interceptor"``).
        level:      Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_format: Output format — ``"json"`` or ``"text"``.
        log_file:   Optional file path for log output (in addition to stderr).

    Returns:
        A configured ``logging.Logger`` instance.

    Example:
        >>> log = get_logger("slow_loop.llm_agent", level="DEBUG")
        >>> log.info("llm_call_started", model="gpt-4o", tokens=1500)
    """
    cache_key = name

    if cache_key in _logger_cache:
        return _logger_cache[cache_key]

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False  # Prevent double-output to root logger

    # --- Stderr Handler ---
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(getattr(logging, level.upper(), logging.INFO))

    if log_format.lower() == "json":
        stderr_handler.setFormatter(JSONFormatter(datefmt="%Y-%m-%dT%H:%M:%S"))
    else:
        stderr_handler.setFormatter(RichTextFormatter(datefmt="%Y-%m-%d %H:%M:%S"))

    logger.addHandler(stderr_handler)

    # --- Optional File Handler (with rotation) ---
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=50 * 1024 * 1024,  # 50 MB per file
            backupCount=5,  # Keep 5 rotated files
            encoding="utf-8",
        )
        file_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
        file_handler.setFormatter(JSONFormatter(datefmt="%Y-%m-%dT%H:%M:%S"))
        logger.addHandler(file_handler)

    _logger_cache[cache_key] = logger
    return logger


def setup_root_logger(
    level: str = DEFAULT_LOG_LEVEL,
    log_format: str = DEFAULT_LOG_FORMAT,
    log_file: Optional[str] = DEFAULT_LOG_FILE,
) -> None:
    """Configure the root logger for all of LIFA-Fuzz.

    Call this once at process startup (e.g., in ``main.py`` or ``__main__.py``)
    before creating any component-specific loggers.

    Args:
        level:      Global minimum log level.
        log_format: ``"json"`` or ``"text"``.
        log_file:   Optional file path for log output.
    """
    root = logging.getLogger("lifa_fuzz")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(getattr(logging, level.upper(), logging.INFO))

    if log_format.lower() == "json":
        handler.setFormatter(JSONFormatter(datefmt="%Y-%m-%dT%H:%M:%S"))
    else:
        handler.setFormatter(RichTextFormatter(datefmt="%Y-%m-%d %H:%M:%S"))

    root.addHandler(root_logger := handler)

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=50 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
        file_handler.setFormatter(JSONFormatter(datefmt="%Y-%m-%dT%H:%M:%S"))
        root.addHandler(file_handler)
