"""
web_ui/presentation/styles.py
──────────────────────────────
Loads CSS from the static/ directory at runtime.

Edit ``presentation/static/styles.css`` to change the dashboard appearance.
No Python changes needed.
"""

from pathlib import Path

_STATIC_DIR = Path(__file__).parent / "static"


def load_css() -> str:
    """Load dashboard CSS from static/styles.css.

    Returns:
        The CSS string wrapped in ``<style>`` tags,
        ready for ``st.markdown(..., unsafe_allow_html=True)``.
    """
    css_path = _STATIC_DIR / "styles.css"
    if not css_path.exists():
        return "<style>/* styles.css not found */</style>"
    css_content = css_path.read_text(encoding="utf-8")
    return f"<style>\n{css_content}\n</style>"
