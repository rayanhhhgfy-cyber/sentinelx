"""SentinelX jsruntime: real JavaScript execution via js2py.

Pure Python + js2py. No Playwright, no Selenium, no headless browser —
Termux compatible.

js2py is a HARD dependency. Importing this package verifies js2py loads
and initializes; if it cannot, an explanatory RuntimeError is raised
immediately (the CLI converts this into a clean startup error).

Contents:
- _js2py_compat: runtime patch making js2py importable on Python 3.12+
- mock: browser-like JS environment (window/document/location/fetch/...)
- executor: execute() — run page JS with timeouts, size limits, isolation
- instrument: structured execution traces (network/DOM/sinks/storage)
- taint: reusable taint-tracking for all vulnerability modules
"""

from __future__ import annotations

from ._js2py_compat import ensure_js2py

# Hard dependency check at import time. No silent fallback.
ensure_js2py()

import js2py  # noqa: E402  (import after compat patch)

from .executor import execute, execute_scripts, ExecutionResult  # noqa: E402
from . import mock, instrument, taint, assists  # noqa: E402

__all__ = [
    "js2py",
    "execute",
    "execute_scripts",
    "ExecutionResult",
    "mock",
    "instrument",
    "taint",
    "assists",
    "ensure_js2py",
]
