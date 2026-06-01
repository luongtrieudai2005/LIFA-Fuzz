"""
web_ui/dashboard.py
────────────────────
Backward-compatible entry point.

Prefer using the new entry point directly:
    streamlit run web_ui/app.py

This file remains for backward compatibility with existing scripts
and Docker configurations that reference ``dashboard.py``.
"""

from web_ui.app import main

if __name__ == "__main__":
    main()
