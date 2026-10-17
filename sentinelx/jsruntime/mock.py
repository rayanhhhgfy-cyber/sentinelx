"""SentinelX jsruntime.mock: browser-like JS environment (node backend).

The mock environment itself lives in ``mock_preamble.js`` (pure JavaScript).
This module is a thin Python wrapper that loads it and injects the
per-execution config (page URL, canary values).

Every mock records to ``__sx_trace``. Nothing is silent. Unsupported APIs
log as "unsupported:<name>" — observable, never a silent no-op.
"""

from __future__ import annotations

import json

from .node_exec import PREAMBLE_PATH


def _js_str(s: str) -> str:
    """Encode a Python string as a JS string literal."""
    return json.dumps(s)


def build_preamble(page_url: str = "", hash_canary: str = "SX_CANARY",
                   search_canary: str = "SX_CANARY") -> str:
    """Return the JS preamble: config block + mock browser environment."""
    with open(PREAMBLE_PATH, "r", encoding="utf-8") as f:
        preamble = f.read()
    config = (
        "var __SX_PAGE_URL = %s;\n"
        "var __SX_SEARCH = %s;\n"
        "var __SX_HASH = %s;\n"
    ) % (
        _js_str(page_url),
        _js_str("?" + search_canary.lstrip("?")),
        _js_str("#" + hash_canary.lstrip("#")),
    )
    return config + preamble


#: APIs we explicitly do NOT emulate; access is logged as "unsupported".
UNSUPPORTED_APIS = (
    "indexedDB", "Notification", "geolocation", "serviceWorker",
    "BroadcastChannel", "Worker", "SharedWorker", "EventSource",
    "RTCPeerConnection",
)
