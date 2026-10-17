"""SentinelX core: response diffing engine — fuzzy hash, length delta,
status, timing, and reflection analysis with baseline subtraction."""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass


def _shingles(text: str, k: int = 5) -> set[str]:
    t = re.sub(r"\s+", " ", text.lower())
    if len(t) < k:
        return {t} if t else set()
    return {t[i:i + k] for i in range(len(t) - k + 1)}


def fuzzy_similarity(a: str, b: str) -> float:
    """Jaccard similarity over 5-char shingles. 1.0 = identical."""
    sa, sb = _shingles(a), _shingles(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


@dataclass
class Baseline:
    status: int
    length: int
    body_hash: str
    elapsed: float


def body_fingerprint(body: str) -> str:
    norm = re.sub(r"[0-9a-fA-F]{16,}", "<HEX>", body)
    norm = re.sub(r"\d{4,}", "<NUM>", norm)
    return hashlib.sha256(norm.encode(errors="replace")).hexdigest()[:16]


@dataclass
class DiffResult:
    length_delta: int
    length_ratio: float
    similarity: float
    status_changed: bool
    reflected: bool
    timing_delta: float
    significant: bool
    details: str = ""


def diff_responses(
    base: Baseline,
    test_status: int,
    test_body: str,
    test_elapsed: float,
    canary: str = "",
    length_threshold: float = 0.15,
    similarity_threshold: float = 0.85,
) -> DiffResult:
    """Compare a test response against a baseline. Returns significance verdict."""
    tlen = len(test_body)
    length_delta = tlen - base.length
    length_ratio = abs(length_delta) / max(base.length, 1)
    sim = fuzzy_similarity(test_body, "")  # placeholder replaced below
    # similarity needs the baseline body; caller passes via base_body param pattern:
    # we compute against stored fingerprint only for exact match, so instead
    # callers should use diff_bodies() for full analysis. This keeps a fast path.
    status_changed = test_status != base.status
    reflected = bool(canary) and canary in test_body
    timing_delta = test_elapsed - base.elapsed
    significant = (
        reflected
        or status_changed
        or length_ratio >= length_threshold
    )
    details = (
        f"len {base.length}->{tlen} (Δ{length_delta:+d}, {length_ratio:.1%}), "
        f"status {base.status}->{test_status}, "
        f"timing {base.elapsed:.2f}s->{test_elapsed:.2f}s"
    )
    return DiffResult(
        length_delta=length_delta, length_ratio=length_ratio,
        similarity=sim, status_changed=status_changed,
        reflected=reflected, timing_delta=timing_delta,
        significant=significant, details=details,
    )


def diff_bodies(base_body: str, test_body: str) -> tuple[float, int]:
    """Return (similarity, length_delta) between two bodies."""
    return fuzzy_similarity(base_body, test_body), len(test_body) - len(base_body)


def is_significant_change(
    base_body: str, test_body: str, base_status: int, test_status: int,
    canary: str = "", sim_threshold: float = 0.85,
) -> tuple[bool, str]:
    sim, delta = diff_bodies(base_body, test_body)
    reasons = []
    if canary and canary in test_body and canary not in base_body:
        reasons.append(f"canary reflected (+{len(canary)}b marker)")
    if test_status != base_status:
        reasons.append(f"status {base_status}->{test_status}")
    if sim < sim_threshold:
        reasons.append(f"content similarity {sim:.2f} < {sim_threshold}")
    ratio = abs(delta) / max(len(base_body), 1)
    if ratio >= 0.15 and not reasons:
        reasons.append(f"length changed {ratio:.1%}")
    return bool(reasons), "; ".join(reasons)
