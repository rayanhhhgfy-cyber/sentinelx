"""SentinelX jsruntime: real JavaScript execution via node subprocess.

Pure Python scanner + node for JS execution. No Playwright, no Selenium,
no headless browser — Termux compatible (pkg install nodejs).

node is a HARD dependency. Importing this package verifies node exists and
can execute JavaScript; if it cannot, an explanatory RuntimeError is raised
immediately (the CLI converts this into a clean startup error).

Contents:
- node_exec: node subprocess backend (execute_js_node, ensure_node)
- mock_preamble.js: browser-like JS environment (window/document/fetch/...)
- mock: thin Python wrapper loading the preamble
- executor: execute() — run page JS with timeouts, size limits, isolation
- instrument: structured execution traces (network/DOM/sinks/storage)
- taint: reusable taint-tracking for all vulnerability modules
"""

from __future__ import annotations

from .node_exec import ensure_node, node_available

# Hard dependency check at import time. No silent fallback.
ensure_node()

from .executor import execute, execute_scripts, ExecutionResult  # noqa: E402
from . import mock, instrument, taint, assists  # noqa: E402

__all__ = [
    "execute",
    "execute_scripts",
    "ExecutionResult",
    "mock",
    "instrument",
    "taint",
    "assists",
    "ensure_node",
    "node_available",
]
