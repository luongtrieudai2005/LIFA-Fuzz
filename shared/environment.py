"""
shared/environment.py
─────────────────────
Centralized environment loader for LIFA-Fuzz.

Single entry point for loading .env, validating API keys, and ensuring
the correct credentials reach every entry point (main.py, run_slow_loop.py,
evaluation_runner.py) regardless of stale shell environment variables.

Usage:
    from shared.environment import load_env_once
    load_env_once()
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional


_PROJECT_ROOT: Optional[Path] = None


def _find_project_root() -> Path:
    """Find the project root by looking for config.yaml upward from this file."""
    return Path(__file__).resolve().parent.parent


def _load_dotenv(path: Optional[Path] = None, override: bool = False) -> None:
    """Load .env file using python-dotenv if available."""
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=str(path) if path else None, override=override)
    except ImportError:
        pass


def _key_matches_provider(key: str, provider: str) -> bool:
    """Check if an API key looks appropriate for the given LLM provider.

    Each provider uses a distinct key format:
      - ``openai`` / ``openai-compatible`` → ``sk-...``
      - ``anthropic``                     → ``sk-ant-...``
      - ``ollama``                        → no key needed (always valid)
    """
    if not key:
        return provider == "ollama"
    if provider == "openai":
        return key.startswith("sk-")
    if provider == "anthropic":
        return key.startswith("sk-ant-")
    if provider == "ollama":
        return True
    return True


def _detect_provider() -> str:
    """Detect the configured LLM provider from config.yaml (best-effort)."""
    try:
        import yaml
        cfg = _find_project_root() / "config.yaml"
        if cfg.exists():
            data = yaml.safe_load(cfg.read_text()) or {}
            return (data.get("slow_loop", {}).get("llm_agent", {}) or {}).get("provider", "openai")
    except Exception:
        pass
    return "openai"


def load_env_once() -> None:
    """Load the .env file ONCE, validate API keys, and override stale ones.

    Call this at the top of every entry point's ``main()`` function.
    Idempotent: subsequent calls are no-ops.

    Strategy:
      1. Load .env without override first (so shell-set vars take precedence
         in the normal case).
      2. Check critical API keys:
         - If ``OPENAI_API_KEY`` is set but looks like it belongs to a
           DIFFERENT provider than what config.yaml expects, override it
           from .env.
         - If ``OPENAI_API_KEY`` is not set at all, set it from .env.
      3. Log a warning when an override occurs so the operator knows.
    """
    global _PROJECT_ROOT
    if _PROJECT_ROOT is None:
        _PROJECT_ROOT = _find_project_root()

    env_path = _PROJECT_ROOT / ".env"
    if not env_path.exists():
        return

    provider = _detect_provider()

    # Step 1: load without override (normal case)
    _load_dotenv(env_path, override=False)

    # Step 2: validate and fix critical keys
    api_key_env = "OPENAI_API_KEY"

    # Read what we got (may be stale shell value)
    current_key = os.environ.get(api_key_env, "")

    # Read what .env wants
    _load_dotenv(env_path, override=True)
    desired_key = os.environ.get(api_key_env, "")

    # Restore the shell value (we only want to check it, not keep the override)
    if current_key:
        os.environ[api_key_env] = current_key
    else:
        # No shell value → keep the .env value (already set by override=True above)
        desired_key = os.environ.get(api_key_env, "")
        if desired_key:
            return

    # Step 3: decide whether to override
    override_needed = False
    reason = ""

    if not current_key and desired_key:
        # Key not set at all — use .env
        override_needed = True
        reason = "not set in environment, loaded from .env"
    elif current_key and desired_key and current_key != desired_key:
        # Both set but different — check which key matches the configured provider
        shell_ok = _key_matches_provider(current_key, provider)
        dotenv_ok = _key_matches_provider(desired_key, provider)

        if dotenv_ok and not shell_ok:
            # Shell key is for a DIFFERENT provider than what config.yaml expects
            # (e.g. Z.ai key in shell but provider=openai in config). Override.
            override_needed = True
            reason = (
                f"shell key '{current_key[:16]}...' does not look like a "
                f"{provider}-compatible key (expected 'sk-...')"
            )
        elif not dotenv_ok and shell_ok:
            # Shell key matches provider, .env key doesn't — keep shell but warn
            logging.getLogger("lifa_fuzz.environment").warning(
                f"OPENAI_API_KEY in .env ('{desired_key[:16]}...') does not look "
                f"valid for provider '{provider}'. Keeping shell key."
            )
        elif shell_ok and dotenv_ok and current_key != desired_key:
            # Both keys match the provider but differ — prefer shell (user intent)
            logging.getLogger("lifa_fuzz.environment").warning(
                f"OPENAI_API_KEY differs between shell and .env. Using shell key "
                f"('{current_key[:16]}...'). To use .env key, run: unset OPENAI_API_KEY"
            )

    if override_needed:
        os.environ[api_key_env] = desired_key
        logging.getLogger("lifa_fuzz.environment").warning(
            f"OPENAI_API_KEY overridden from .env ({reason})"
        )
