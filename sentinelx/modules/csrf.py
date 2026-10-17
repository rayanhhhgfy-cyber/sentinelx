"""SentinelX module [14]: Cross-Site Request Forgery (CSRF).

Techniques: hidden-token presence detection on state-changing
endpoints (POST/PUT/DELETE/PATCH), token predictability (double
fetch comparison), Shannon-entropy strength check, Origin-header
validation test, and session-cookie SameSite analysis. All via
real HTTP requests.
"""

from __future__ import annotations

import math
import re
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response

STATE_CHANGING = {"POST", "PUT", "DELETE", "PATCH"}

TOKEN_INPUT_RE = re.compile(
    r'<input[^>]+(?:name|id)\s*=\s*["\']?([^"\'>\s]*)["\']?[^>]*>',
    re.I,
)
TOKEN_NAME_RE = re.compile(
    r"csrf|_token|authenticity_token|__RequestVerificationToken|xsrf|csrf_token",
    re.I,
)
VALUE_RE = re.compile(r'value\s*=\s*["\']([^"\']*)["\']', re.I)

REMEDIATION_CSRF = (
    "Issue an unguessable, per-session CSRF token and require it on every "
    "state-changing request (synchronizer token pattern or encrypted token "
    "pattern). Validate the Origin/Referer header as defense in depth, set "
    "session cookies with SameSite=Lax (or Strict), and never accept "
    "state-changing GET requests."
)


def extract_csrf_tokens(html: str) -> dict[str, str]:
    """Return {token_name: token_value} for hidden inputs with CSRF-ish names."""
    out: dict[str, str] = {}
    for m in TOKEN_INPUT_RE.finditer(html):
        name = m.group(1) or ""
        if TOKEN_NAME_RE.search(name):
            tag = m.group(0)
            v = VALUE_RE.search(tag)
            out[name] = v.group(1) if v else ""
    return out


def shannon_bits(token: str) -> float:
    """Total Shannon entropy bits of a token string."""
    if not token:
        return 0.0
    freq: dict[str, int] = {}
    for ch in token:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(token)
    per_char = -sum((c / n) * math.log2(c / n) for c in freq.values())
    return per_char * n


def _evidence(method, url, req_headers, body_sent, resp) -> Evidence:
    rbody = resp.content if resp else b""
    return Evidence(
        request_raw=raw_request(method, url, req_headers, body_sent),
        response_raw=raw_response(resp.status_code if resp else 0,
                                  dict(resp.headers) if resp else {}, rbody),
        proof="",
    )


def _session_cookies(resp) -> list[str]:
    if not resp:
        return []
    return [v.decode("latin1") for k, v in resp.headers.raw
            if k.lower() == b"set-cookie"]


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    headers = {"User-Agent": config.user_agent}

    # Only state-changing endpoints are CSRF-relevant
    if method.upper() not in STATE_CHANGING:
        return findings

    # ---------- 1. fetch form page, look for CSRF token ----------
    page = await client.get(url, headers=headers)
    if not page:
        return findings
    html = page.text
    tokens = extract_csrf_tokens(html)

    if not tokens:
        # ---------- missing token ----------
        snippet = html[:600].replace("\n", " ")
        ev = _evidence("GET", url, headers, None, page)
        ev.proof = (f"State-changing endpoint {method} {url} serves a form with "
                    f"NO hidden CSRF token input. Page snippet: {snippet[:400]}")
        findings.append(Finding(
            type="Cross-Site Request Forgery", subtype="missing-csrf-token",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            confidence=0.8, url=url, method=method, param="",
            payload="(no token present)", evidence=ev, cwe="CWE-352",
            owasp="A01:2021 – Broken Access Control",
            remediation=REMEDIATION_CSRF,
            references=["https://owasp.org/www-community/attacks/csrf"],
        ))
    else:
        token_name, token_value = next(iter(tokens.items()))
        # ---------- 2. predictability: fetch twice, compare ----------
        page2 = await client.get(url, headers=headers)
        tokens2 = extract_csrf_tokens(page2.text) if page2 else {}
        value2 = tokens2.get(token_name)
        if value2 is not None and value2 == token_value:
            ev = _evidence("GET", url, headers, None, page2 or page)
            ev.proof = (f"CSRF token '{token_name}' returned the IDENTICAL value "
                        f"on two consecutive requests: {token_value[:40]}")
            findings.append(Finding(
                type="Cross-Site Request Forgery", subtype="predictable-csrf-token",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
                confidence=0.75, url=url, method=method, param=token_name,
                payload=token_value[:60], evidence=ev, cwe="CWE-352",
                owasp="A01:2021 – Broken Access Control",
                remediation=REMEDIATION_CSRF,
                references=["https://owasp.org/www-community/attacks/csrf"],
            ))
        # ---------- 3. entropy check (< 64 bits total) ----------
        bits = shannon_bits(token_value)
        if bits < 64:
            ev = _evidence("GET", url, headers, None, page)
            ev.proof = (f"CSRF token '{token_name}' carries only {bits:.1f} bits "
                        f"of Shannon entropy (< 64-bit minimum)")
            findings.append(Finding(
                type="Cross-Site Request Forgery", subtype="low-entropy-csrf-token",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
                confidence=0.7, url=url, method=method, param=token_name,
                payload=token_value[:60], evidence=ev, cwe="CWE-352",
                owasp="A01:2021 – Broken Access Control",
                remediation=REMEDIATION_CSRF,
                references=["https://owasp.org/www-community/attacks/csrf"],
            ))

    # ---------- 4. Origin validation: forged cross-site origin ----------
    evil_headers = {**headers, "Origin": "https://evil.example",
                    "Referer": "https://evil.example/"}
    p = dict(params or {})
    if method.upper() == "POST":
        resp = await client.post(url, data=p, headers=evil_headers)
        body_sent = _urlencode(p).encode()
    elif method.upper() == "PUT":
        resp = await client.request("PUT", url, data=p, headers=evil_headers)
        body_sent = _urlencode(p).encode()
    elif method.upper() == "DELETE":
        resp = await client.request("DELETE", url, headers=evil_headers)
        body_sent = None
    else:  # PATCH
        resp = await client.request("PATCH", url, data=p, headers=evil_headers)
        body_sent = _urlencode(p).encode()
    if resp and resp.status_code in (200, 201, 202, 302, 303):
        ev = _evidence(method.upper(), url, evil_headers, body_sent, resp)
        ev.proof = (f"State-changing request with forged Origin "
                    f"https://evil.example was accepted (HTTP {resp.status_code}); "
                    f"server performs no Origin/Referer validation")
        findings.append(Finding(
            type="Cross-Site Request Forgery", subtype="missing-origin-validation",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            confidence=0.75, url=url, method=method.upper(), param="Origin",
            payload="https://evil.example", evidence=ev, cwe="CWE-352",
            owasp="A01:2021 – Broken Access Control",
            remediation=REMEDIATION_CSRF,
            references=["https://owasp.org/www-community/attacks/csrf"],
        ))

    # ---------- 5. session cookie SameSite analysis ----------
    for cookie in _session_cookies(page):
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        if re.search(r"session|auth|sid|token", name, re.I) and "samesite" not in low:
            ev = _evidence("GET", url, headers, None, page)
            ev.proof = f"Set-Cookie: {cookie[:200]}"
            findings.append(Finding(
                type="Cross-Site Request Forgery", subtype="session-cookie-no-samesite",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
                confidence=0.9, url=url, method="GET", param=name,
                payload="missing SameSite attribute", evidence=ev, cwe="CWE-352",
                owasp="A01:2021 – Broken Access Control",
                remediation=("Set session cookies with SameSite=Lax (minimum) — "
                             "Strict for high-value sessions — to blunt CSRF."),
                references=["https://owasp.org/www-community/attacks/csrf"],
            ))
            break  # one per endpoint is enough

    return findings
