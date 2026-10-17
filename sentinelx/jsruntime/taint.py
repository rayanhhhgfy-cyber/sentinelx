"""SentinelX jsruntime.taint: reusable taint tracking for all modules.

Two complementary mechanisms:

1. **Canary-based flow verification** (primary, for JS execution):
   Sources are seeded with unique canary strings. After execution, sink
   recordings are scanned for canaries. A canary appearing in a sink is
   PROOF of source → sink data flow — no guessing.

2. **Python-side tainted strings** (for modules):
   ``TaintedStr`` is a ``str`` subclass carrying taint metadata through
   common string operations (concat, formatting, replace, encode/decode,
   split/join). Modules use it to track attacker-controlled data through
   payload transformations.

Neither is symbolic execution — this is practical, string-level taint
designed for real scanner workloads.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Taint sources
# ---------------------------------------------------------------------------

class Source:
    URL_PARAM = "url-param"
    QUERY = "query"
    FRAGMENT = "fragment"
    FORM_INPUT = "form-input"
    HEADER = "header"
    COOKIE = "cookie"
    STORAGE = "storage"
    WEBSOCKET_MSG = "websocket-msg"


@dataclass
class TaintMark:
    """A canary seeded into a source."""
    source: str          # Source.* constant
    source_id: str       # e.g. "location.hash", "q", "X-Forwarded-For"
    canary: str          # unique canary string


@dataclass
class TaintFlow:
    """Proven source → sink flow."""
    source: str
    source_id: str
    sink: str            # e.g. "sink:innerHTML"
    sink_detail: dict = field(default_factory=dict)
    evidence: str = ""   # the sink value containing the canary

    def describe(self) -> str:
        return f"{self.source}({self.source_id}) → {self.sink}"


class TaintTracker:
    """Issues canaries and matches them against observed sink values."""

    def __init__(self, prefix: str = "SX_TAINT"):
        self.prefix = prefix
        self._marks: dict[str, TaintMark] = {}

    def new_mark(self, source: str, source_id: str) -> TaintMark:
        canary = f"{self.prefix}_{uuid.uuid4().hex[:12]}"
        mark = TaintMark(source=source, source_id=source_id, canary=canary)
        self._marks[canary] = mark
        return mark

    def check_value(self, value: str) -> list[TaintMark]:
        """Return all taint marks whose canary appears in value."""
        if not value or not isinstance(value, str):
            return []
        return [m for c, m in self._marks.items() if c in value]

    def flows_from_trace(self, trace: list[dict]) -> list[TaintFlow]:
        """Build proven flows from an execution trace.

        Trace entries: {"kind": "sink:innerHTML", "data": {...}}.
        Matches dangerous sinks (sink:*) and navigation sinks (nav:*,
        used for client-side open-redirect detection).
        """
        flows: list[TaintFlow] = []
        seen: set[tuple] = set()
        for entry in trace:
            kind = entry.get("kind", "")
            if not (kind.startswith("sink:") or kind.startswith("nav:")):
                continue
            data = entry.get("data")
            # extract the string value from the sink recording
            if isinstance(data, dict):
                value = data.get("value", "") or ""
            else:
                value = str(data or "")
            for mark in self.check_value(value):
                key = (mark.canary, kind, mark.source_id)
                if key in seen:
                    continue
                seen.add(key)
                flows.append(TaintFlow(
                    source=mark.source,
                    source_id=mark.source_id,
                    sink=kind,
                    sink_detail=data if isinstance(data, dict) else {},
                    evidence=value[:1000],
                ))
        return flows


# ---------------------------------------------------------------------------
# Python-side tainted strings (for vulnerability modules)
# ---------------------------------------------------------------------------

class TaintedStr(str):
    """str subclass that carries taint metadata through operations.

    Any operation producing a new string propagates the taint. Use
    ``.taint_sources`` to inspect where the data came from.
    """

    def __new__(cls, value: str = "", sources: tuple = ()):
        obj = super().__new__(cls, value)
        obj.taint_sources: tuple = tuple(sources)
        return obj

    @property
    def tainted(self) -> bool:
        return bool(self.taint_sources)

    def _with(self, value: str) -> "TaintedStr":
        return TaintedStr(value, self.taint_sources)

    # -- core propagation --
    def __add__(self, other):
        src = self.taint_sources
        if isinstance(other, TaintedStr):
            src = src + other.taint_sources
        return TaintedStr(str.__add__(self, other), src)

    def __radd__(self, other):
        return TaintedStr(str.__add__(other, self), self.taint_sources)

    def __mul__(self, n):
        return self._with(str.__mul__(self, n))

    def __mod__(self, other):
        src = self.taint_sources
        if isinstance(other, TaintedStr):
            src = src + other.taint_sources
        elif isinstance(other, tuple):
            for o in other:
                if isinstance(o, TaintedStr):
                    src = src + o.taint_sources
        return TaintedStr(str.__mod__(self, other), src)

    def __getitem__(self, key):
        return self._with(str.__getitem__(self, key))

    # -- common transforms --
    def replace(self, old, new, *a):
        src = self.taint_sources
        if isinstance(new, TaintedStr):
            src = src + new.taint_sources
        return TaintedStr(str.replace(self, old, new, *a), src)

    def encode(self, *a, **k):
        # bytes can't carry the subclass; wrap result back on decode
        return str.encode(self, *a, **k)

    def format(self, *a, **k):
        src = self.taint_sources
        for o in list(a) + list(k.values()):
            if isinstance(o, TaintedStr):
                src = src + o.taint_sources
        return TaintedStr(str.format(self, *a, **k), src)

    def join(self, iterable):
        src = self.taint_sources
        parts = []
        for o in iterable:
            parts.append(o)
            if isinstance(o, TaintedStr):
                src = src + o.taint_sources
        return TaintedStr(str.join(self, parts), src)

    def split(self, *a, **k):
        return [self._with(p) for p in str.split(self, *a, **k)]

    def strip(self, *a):
        return self._with(str.strip(self, *a))

    def lower(self):
        return self._with(str.lower(self))

    def upper(self):
        return self._with(str.upper(self))


def taint(value: str, source: str, source_id: str = "") -> TaintedStr:
    """Mark a string as attacker-controlled."""
    return TaintedStr(value, ((source, source_id),))


def is_tainted(value) -> bool:
    return isinstance(value, TaintedStr) and value.tainted


def taint_sources(value) -> tuple:
    if isinstance(value, TaintedStr):
        return value.taint_sources
    return ()
