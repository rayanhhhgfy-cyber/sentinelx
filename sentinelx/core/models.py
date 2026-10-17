"""SentinelX core: finding model, severity, CVSS 3.1 scoring, evidence."""

from __future__ import annotations

import hashlib
import html as html_lib
import shlex
import time
from dataclasses import dataclass, field, asdict
from typing import Optional


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def cvss31_score(vector: str) -> float:
    """Compute CVSS 3.1 base score from a vector string like
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"""
    vals = {}
    for part in vector.split("/"):
        if ":" in part and not part.startswith("CVSS"):
            k, v = part.split(":", 1)
            vals[k] = v
    # Metric values per CVSS 3.1 spec
    AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC = {"L": 0.77, "H": 0.44}
    PR = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
    PR_S = {"N": 0.85, "L": 0.68, "H": 0.5}  # scope changed
    UI = {"N": 0.85, "R": 0.62}
    CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
    try:
        av = AV[vals["AV"]]; ac = AC[vals["AC"]]
        ui = UI[vals["UI"]]
        scope_changed = vals.get("S", "U") == "C"
        pr = (PR_S if scope_changed else PR)[vals["PR"]]
        c = CIA[vals["C"]]; i = CIA[vals["I"]]; a = CIA[vals["A"]]
    except KeyError:
        return 0.0
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        impact = max(impact, 0)
    else:
        impact = 6.42 * iss
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        score = min(1.08 * (impact + exploit), 10.0)
    else:
        score = min(impact + exploit, 10.0)
    # roundup to 1 decimal per spec
    import math
    return math.ceil(score * 10) / 10


def severity_from_cvss(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score > 0.0: return "low"
    return "info"


@dataclass
class Evidence:
    request_raw: str = ""
    response_raw: str = ""
    proof: str = ""


@dataclass
class Finding:
    id: str = ""
    type: str = ""
    subtype: str = ""
    severity: str = "info"
    cvss_vector: str = ""
    cvss_score: float = 0.0
    confidence: float = 0.0
    url: str = ""
    method: str = "GET"
    param: str = ""
    payload: str = ""
    evidence: Evidence = field(default_factory=Evidence)
    cwe: str = ""
    owasp: str = ""
    remediation: str = ""
    references: list = field(default_factory=list)
    curl_command: str = ""
    timestamp: float = field(default_factory=time.time)

    def finalize(self, seq: int) -> "Finding":
        self.id = f"sx-{seq:03d}"
        if self.cvss_vector and not self.cvss_score:
            self.cvss_score = cvss31_score(self.cvss_vector)
        if self.cvss_score and self.severity == "info":
            self.severity = severity_from_cvss(self.cvss_score)
        self.curl_command = build_curl(self)
        return self

    def dedup_key(self) -> str:
        return hashlib.sha256(
            f"{self.type}|{self.subtype}|{self.method}|{self.url}|{self.param}".encode()
        ).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = asdict(self.evidence)
        return d


def build_curl(f: Finding) -> str:
    """Build a copy-paste curl command that reproduces the finding."""
    parts = ["curl", "-i", "-s", "-X", f.method]
    parts.append(shlex.quote(f.url))
    if f.method in ("POST", "PUT", "PATCH") and f.payload:
        # payload was in body for POST; URL already carries GET payloads
        pass
    return " ".join(parts)


def raw_request(method: str, url: str, headers: dict, body: Optional[bytes]) -> str:
    from urllib.parse import urlsplit
    u = urlsplit(url)
    path = u.path or "/"
    if u.query: path += "?" + u.query
    lines = [f"{method} {path} HTTP/1.1", f"Host: {u.netloc}"]
    for k, v in headers.items():
        if k.lower() not in ("host", "content-length"):
            lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("")
    head = "\r\n".join(lines)
    if body:
        try: return head + "\r\n" + body.decode("utf-8", "replace")
        except Exception: return head + "\r\n<binary body>"
    return head


def raw_response(status: int, headers: dict, body: bytes, limit: int = 6000) -> str:
    lines = [f"HTTP/1.1 {status}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    head = "\r\n".join(lines)
    text = body[:limit].decode("utf-8", "replace")
    if len(body) > limit:
        text += f"\n... [truncated {len(body) - limit} bytes]"
    return head + "\r\n" + text


def esc(s: str) -> str:
    return html_lib.escape(s)
