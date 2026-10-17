"""SentinelX jsruntime.instrument: structured traces + static/dynamic correlation.

Takes an ExecutionResult (dynamic) and optional static findings, and
produces:

- ExecutionSummary: what the page's JS actually did
- CorrelatedFinding: static pattern + runtime observation → confidence

Correlation rule: a static indicator (e.g. "innerHTML present") becomes
a real finding only when runtime execution shows attacker-controlled data
reaching it. Static-only indicators are labeled as such, never CONFIRMED.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .executor import ExecutionResult
from .taint import TaintTracker, TaintFlow


@dataclass
class ExecutionSummary:
    url: str = ""
    scripts_executed: bool = False
    api_endpoints: list = field(default_factory=list)  # {url, method}
    websockets: list = field(default_factory=list)
    dom_sink_hits: list = field(default_factory=list)  # kinds hit
    eval_hits: int = 0
    storage_keys_written: list = field(default_factory=list)
    route_changes: list = field(default_factory=list)
    unsupported_apis: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    elapsed: float = 0.0


def summarize(result: ExecutionResult, url: str = "") -> ExecutionSummary:
    """Build a high-level summary of what the page's JS did."""
    s = ExecutionSummary(url=url, scripts_executed=result.executed,
                         errors=list(result.errors), elapsed=result.elapsed)
    seen_eps: set[tuple] = set()
    for e in result.api_calls:
        d = e.get("data") or {}
        key = (str(d.get("method", "GET")), str(d.get("url", "")))
        if key[1] and key not in seen_eps:
            seen_eps.add(key)
            s.api_endpoints.append({"method": key[0], "url": key[1]})
    for e in result.websockets:
        d = e.get("data") or {}
        u = str(d.get("url", ""))
        if u and u not in s.websockets:
            s.websockets.append(u)
    for e in result.dom_writes:
        k = str(e.get("kind", ""))
        if k not in s.dom_sink_hits:
            s.dom_sink_hits.append(k)
    s.eval_hits = len(result.eval_calls)
    for e in result.storage_access:
        d = e.get("data") or {}
        if str(e.get("kind", "")).endswith(":set"):
            k = str(d.get("key", ""))
            if k and k not in s.storage_keys_written:
                s.storage_keys_written.append(k)
    for e in result.routes:
        d = e.get("data") or {}
        u = str(d.get("data") if isinstance(d, str) else d)
        if u and u not in s.route_changes:
            s.route_changes.append(u)
    for e in result.unsupported:
        d = e.get("data")
        name = str(d) if d else ""
        if name and name not in s.unsupported_apis:
            s.unsupported_apis.append(name)
    return s


# Confidence levels (shared vocabulary for findings)
CONFIRMED = "CONFIRMED"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFORMATIONAL = "INFORMATIONAL"


@dataclass
class CorrelatedFinding:
    """A static indicator enriched (or not) with runtime evidence."""
    check: str                      # e.g. "dom-xss"
    static_evidence: str = ""       # what static analysis found
    runtime_evidence: str = ""      # what execution observed
    flows: list = field(default_factory=list)  # list[TaintFlow]
    confidence: str = INFORMATIONAL
    static_only: bool = True

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "static_evidence": self.static_evidence,
            "runtime_evidence": self.runtime_evidence,
            "flows": [f.describe() for f in self.flows],
            "confidence": self.confidence,
            "static_only": self.static_only,
        }


def correlate_dom_xss(static_sinks: list[str], result: ExecutionResult,
                      tracker: TaintTracker) -> CorrelatedFinding:
    """Correlate static DOM-XSS sinks with runtime taint flows.

    - Static sinks + proven canary flow → CONFIRMED
    - Static sinks + sink hit (no canary) → MEDIUM (sink reachable)
    - Static sinks only → LOW, static_only=True (indicator, not a finding)
    - Nothing → INFORMATIONAL
    """
    cf = CorrelatedFinding(check="dom-xss")
    if static_sinks:
        cf.static_evidence = "sinks in JS: " + ", ".join(static_sinks[:8])
    flows = tracker.flows_from_trace(result.trace)
    cf.flows = flows
    if flows:
        cf.confidence = CONFIRMED
        cf.static_only = False
        cf.runtime_evidence = "canary flow proven: " + "; ".join(
            f.describe() for f in flows[:3])
    elif result.dom_writes or result.eval_calls:
        cf.confidence = MEDIUM
        cf.static_only = False
        kinds = sorted({str(e.get("kind", "")) for e in
                        result.dom_writes + result.eval_calls})
        cf.runtime_evidence = "sinks executed at runtime: " + ", ".join(kinds[:8])
    elif static_sinks:
        cf.confidence = LOW
        cf.static_only = True
        cf.runtime_evidence = "no runtime sink execution observed"
    return cf


def extract_api_endpoints(result: ExecutionResult) -> list[dict]:
    """Deduped API endpoints observed at runtime: [{method, url}]."""
    out: list[dict] = []
    seen: set[tuple] = set()
    for e in result.api_calls:
        d = e.get("data") or {}
        url = str(d.get("url", "")).strip()
        method = str(d.get("method", "GET")).upper()
        if not url or url.startswith(("javascript:", "data:", "#")):
            continue
        key = (method, url)
        if key not in seen:
            seen.add(key)
            out.append({"method": method, "url": url})
    return out
