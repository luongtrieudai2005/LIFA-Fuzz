"""
shared/logger.py
────────────────
Centralized, structured, async-safe logging for LIFA-Fuzz.

DESIGN GOALS:
    1. ASYNC-SAFE — Standard logging handlers call blocking I/O (file writes,
       socket sends) on the same thread as the caller. In an asyncio program
       this blocks the event loop. We solve this with a QueueHandler that
       enqueues log records non-blocking and drains them in a background thread.

    2. STRUCTURED — Every record from application code can attach a `context`
       dict of key-value pairs. These appear inline on the console and are
       embedded as a "ctx" key in the JSON file — machine-parseable with jq.

    3. COLOR-CODED CONSOLE — ANSI colors per severity and per block make it
       trivially easy to visually track which component emitted each line
       during a live fuzzing run.

    4. DUAL OUTPUT — Simultaneously writes:
       - Colored, human-readable lines to stdout
       - Newline-delimited JSON to a rotating file (10 MB × 5 backups)

USAGE:
    # At application startup (call exactly once):
    from shared.logger import setup_logging
    setup_logging(log_level="DEBUG")

    # In every module:
    from shared.logger import get_logger
    log = get_logger("fast_loop.interceptor")

    log.info("Interceptor started", extra={"context": {"port": 8080}})
    log.warning("Fuzzer stuck", extra={"context": {"rejection_rate": "87%"}})
    log.error("Crash detected!", extra={"context": {"payload": "deadbeef"}})
"""

import json
import logging
import logging.handlers
import queue
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ===========================================================================
# ANSI Color Palette
# ===========================================================================
_R   = "\033[0m"        # RESET
_BLD = "\033[1m"        # BOLD
_DIM = "\033[2m"        # DIM
_UND = "\033[4m"        # UNDERLINE

_RED  = "\033[91m"
_YEL  = "\033[93m"
_GRN  = "\033[92m"
_CYN  = "\033[96m"
_MAG  = "\033[95m"
_BLU  = "\033[94m"
_WHT  = "\033[97m"

_LEVEL_COLORS: dict[str, str] = {
    "DEBUG":    _DIM + _WHT,
    "INFO":     _CYN,
    "WARNING": _YEL + _BLD,
    "ERROR":    _RED + _BLD,
    "CRITICAL": _RED + _BLD + _UND,
}

# Map logger name prefix → display color
_BLOCK_COLORS: dict[str, str] = {
    "fast_loop": _GRN,
    "slow_loop": _MAG,
    "sandbox":   _BLU,
    "shared":    _DIM + _WHT,
    "tests":     _YEL,
}


# ===========================================================================
# Custom Formatters
# ===========================================================================

class _ColoredConsoleFormatter(logging.Formatter):
    """
    Rich ANSI-colored formatter for live terminal output.

    Output line format:
        HH:MM:SS.mmm [LEVEL   ] [logger.name               ] Message  key=val …

    The logger name prefix (fast_loop, slow_loop, etc.) is color-coded so
    you can immediately see which block emitted each line during a run.
    """

    def format(self, record: logging.LogRecord) -> str:
        ts      = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        level   = record.levelname
        name    = record.name
        message = record.getMessage()

        level_color = _LEVEL_COLORS.get(level, _WHT)

        # Color by block (first segment of logger name after "lifa_fuzz.")
        parts      = name.replace("lifa_fuzz.", "").split(".")
        block_key  = parts[0] if parts else "shared"
        block_color = _BLOCK_COLORS.get(block_key, _DIM + _WHT)

        # Build optional context suffix from extra["context"]
        ctx     = getattr(record, "context", None)
        ctx_str = ""
        if ctx and isinstance(ctx, dict):
            ctx_str = "  " + _DIM + "  ".join(f"{k}={v}" for k, v in ctx.items()) + _R

        exc_str = ""
        if record.exc_info:
            exc_str = "\n" + self.formatException(record.exc_info)

        return (
            f"{_DIM}{ts}{_R} "
            f"{level_color}{level:<8}{_R} "
            f"{block_color}[{name:<32}]{_R} "
            f"{message}"
            f"{ctx_str}"
            f"{exc_str}"
        )


class _JsonFileFormatter(logging.Formatter):
    """
    Newline-delimited JSON formatter for structured log files.

    Each line is a complete JSON object — trivially parseable with:
        jq 'select(.level=="ERROR")' logs/lifa_fuzz.log
        jq 'select(.ctx.rejection_rate != null)' logs/lifa_fuzz.log
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts":     datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level":  record.levelname,
            "logger": record.name,
            "msg":    record.getMessage(),
            "pid":    record.process,
        }
        ctx = getattr(record, "context", None)
        if ctx:
            payload["ctx"] = ctx
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


# ===========================================================================
# Module-level State
# ===========================================================================
_log_queue: Optional[queue.Queue]                     = None
_listener:   Optional[logging.handlers.QueueListener]  = None
_initialized: bool                                   = False


# ===========================================================================
# Public API
# ===========================================================================

def setup_logging(
    log_level:   str  = "DEBUG",
    log_dir:     str  = "logs",
    log_file:    str  = "lifa_fuzz.log",
    enable_file: bool = True,
) -> None:
    """
    Initialize the global logging pipeline for LIFA-Fuzz.

    MUST be called exactly once at application startup before any module
    calls get_logger(). Subsequent calls are no-ops.

    Implementation detail — the async-safe pipeline:
        application code
            → QueueHandler.emit()  [non-blocking, puts record on queue]
            → queue.Queue          [in-memory, unbounded by default]
            → QueueListener        [background daemon thread]
            → [ColoredConsoleHandler, RotatingFileHandler]

    Args:
        log_level:   Minimum severity to capture ("DEBUG", "INFO", etc.).
        log_dir:     Directory for rotating log files (created if absent).
        log_file:    Base filename for JSON log output.
        enable_file: Set False to disable file output (e.g. in CI).
    """
    global _log_queue, _listener, _initialized

    if _initialized:
        return

    _log_queue = queue.Queue(maxsize=-1)  # Unbounded — prevents blocking under burst

    # -----------------------------------------------------------------------
    # Handlers (run in background thread via QueueListener)
    # -----------------------------------------------------------------------
    handlers: list[logging.Handler] = []

    # Console (colored)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(_ColoredConsoleFormatter())
    console.setLevel(logging.DEBUG)
    handlers.append(console)

    # Rotating JSON file
    if enable_file:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        rotating = logging.handlers.RotatingFileHandler(
            filename    = log_path / log_file,
            maxBytes    = 10 * 1024 * 1024,  # 10 MB per file
            backupCount = 5,
            encoding    = "utf-8",
        )
        rotating.setFormatter(_JsonFileFormatter())
        rotating.setLevel(logging.DEBUG)
        handlers.append(rotating)

    # -----------------------------------------------------------------------
    # QueueListener — drains the queue in a background daemon thread
    # -----------------------------------------------------------------------
    _listener = logging.handlers.QueueListener(
        _log_queue,
        *handlers,
        respect_handler_level=True,
    )
    _listener.start()

    # -----------------------------------------------------------------------
    # QueueHandler — attached to root logger, used by all get_logger() calls
    # -----------------------------------------------------------------------
    q_handler = logging.handlers.QueueHandler(_log_queue)
    q_handler.setLevel(getattr(logging, log_level.upper(), logging.DEBUG))

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers.clear()
    root.addHandler(q_handler)

    # Silence noisy third-party loggers
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("litellm").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    # Suppress Docker SDK / urllib3 debug spam (one line per is_target_alive
    # poll when using the Docker driver — floods the log with container JSON
    # GETs that are not actionable).
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    logging.getLogger("docker").setLevel(logging.WARNING)
    logging.getLogger("docker.auth").setLevel(logging.WARNING)
    logging.getLogger("docker.utils").setLevel(logging.WARNING)

    _initialized = True
    _boot_log = logging.getLogger("lifa_fuzz.shared.logger")
    _boot_log.info(
        "Logging pipeline initialized",
        extra={"context": {
            "level": log_level,
            "file":   str(Path(log_dir) / log_file) if enable_file else "disabled",
            "async":  "QueueHandler → background thread",
        }},
    )


def get_logger(name: str) -> logging.Logger:
    """
    Retrieve a named logger scoped to the lifa_fuzz namespace.

    Performs lazy initialization with default settings if setup_logging()
    has not been called yet (useful in unit tests).

    Naming convention — use dot-separated module paths:
        get_logger("fast_loop.interceptor")   → lifa_fuzz.fast_loop.interceptor
        get_logger("slow_loop.llm_agent")     → lifa_fuzz.slow_loop.llm_agent
        get_logger("shared.schemas")          → lifa_fuzz.shared.schemas

    Args:
        name: Logger name (will be prefixed with "lifa_fuzz." automatically).

    Returns:
        A standard logging.Logger configured with the async-safe pipeline.
    """
    if not _initialized:
        setup_logging()  # Lazy init — safe for tests

    full = f"lifa_fuzz.{name}" if not name.startswith("lifa_fuzz.") else name
    return logging.getLogger(full)


def setup_root_logger(
    log_level: str = "DEBUG",
    log_format: str = "text",  # noqa: ARG001 — accepted for API compat
    log_file: str = "",
    *,
    level: str | None = None,
    enable_file: bool | None = None,
) -> None:
    """Backward-compatible alias for ``setup_logging()``.

    Accepts both ``level`` and ``log_level``, plus ``log_format`` and
    ``log_file``, so that all existing call-sites work:

    - ``setup_root_logger(level="DEBUG", log_format="text")``
    - ``setup_root_logger(log_level="INFO", log_file="/tmp/out.log")``
    """
    resolved_level = level if level is not None else log_level
    resolved_file = enable_file if enable_file is not None else bool(log_file)
    setup_logging(log_level=resolved_level, enable_file=resolved_file)


def shutdown_logging() -> None:
    """
    Flush the log queue and stop the background listener thread.

    Call this at the very end of your main() or in a shutdown hook.
    Logs emitted after this call may be silently dropped.
    """
    global _initialized
    if _listener is not None:
        _listener.stop()
    _initialized = False
