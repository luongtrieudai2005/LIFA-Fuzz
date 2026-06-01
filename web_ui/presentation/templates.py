"""
web_ui/presentation/templates.py
──────────────────────────────────
HTML template loader with section support.

Templates use ``<!-- SECTION: name -->`` markers to split one file
into multiple named sections. This keeps related HTML together while
still allowing fine-grained rendering.

Usage:
    # Load an entire file:
    html = load_template("footer.html", last_seen="12:00 UTC")

    # Load one section from a file:
    html = load_section("metrics.html", "eps", eps=5.2)

Edit the .html files in ``presentation/templates/`` to change the layout.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# In-memory cache: {filename: raw_content}
_cache: dict[str, str] = {}

_SECTION_PATTERN = re.compile(
    r"<!--\s*SECTION:\s*(\w+)\s*-->\s*\n(.*?)(?=<!--\s*SECTION:|\Z)",
    re.DOTALL,
)


def _read_file(filename: str) -> str:
    """Read a template file, with caching."""
    if filename not in _cache:
        path = _TEMPLATES_DIR / filename
        if not path.exists():
            return f"<!-- template {filename} not found -->"
        _cache[filename] = path.read_text(encoding="utf-8")
    return _cache[filename]


def load_template(filename: str, **kwargs: Any) -> str:
    """Load an entire HTML template file and substitute variables.

    Args:
        filename: Template file name in ``templates/``.
        **kwargs:  Variables to substitute (Python str.format syntax).

    Returns:
        Rendered HTML string.
    """
    template = _read_file(filename)
    if kwargs:
        return template.format(**kwargs)
    return template


def load_section(filename: str, section: str, **kwargs: Any) -> str:
    """Load one named section from a template file.

    Sections are marked with ``<!-- SECTION: name -->`` in the HTML file.

    Args:
        filename: Template file name in ``templates/``.
        section:  Section name (e.g. ``"eps"``, ``"title"``).
        **kwargs:  Variables to substitute.

    Returns:
        Rendered HTML string for that section.
    """
    content = _read_file(filename)

    # Find the requested section
    for match in _SECTION_PATTERN.finditer(content):
        if match.group(1) == section:
            template = match.group(2).strip()
            if kwargs:
                return template.format(**kwargs)
            return template

    return f"<!-- section '{section}' not found in {filename} -->"


def clear_cache() -> None:
    """Clear the template cache (useful during development)."""
    _cache.clear()
