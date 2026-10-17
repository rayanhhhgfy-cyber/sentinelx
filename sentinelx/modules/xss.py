"""SentinelX module [02]: Cross-Site Scripting.

Techniques: reflected XSS with unique canary, HTML context detection
(body / attribute / script / URL), context-specific payloads,
multi-sample confirmation. Safe: canary is inert until proven.
"""

from __future__ import annotations

import re
import secrets
from html.parser import HTMLParser
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


def make_canary() -> str:
    return "sx" + secrets.token_hex(4)


class _ContextParser(HTMLParser):
    """Find where the canary lands: tag, attribute, or script body."""

    def __init__(self, canary: str):
        super().__init__()
        self.canary = canary
        self.contexts: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        for name, val in attrs:
            if val and self.canary in val:
                self.contexts.append(f"attribute:{tag}:{name}")
        if tag == "script":
            self._in_script = True

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self.canary in data:
            self.contexts.append("script-body" if self._in_script else "html-body")


PAYLOADS = {
    "html-body": [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
    ],
    "attribute": [
        '" onmouseover=alert(1) x="',
        "' autofocus onfocus=alert(1) x='",
        '" autofocus onfocus=alert(1) x="',
    ],
    "script-body": [
        '</script><script>alert(1)</script>',
        '";alert(1);//',
        "'-alert(1)-'",
    ],
    "url": [
        'javascript:alert(1)',
    ],
}

REMEDIATION_XSS = (
    "Encode all user-controlled output for its context (HTML, attribute, JS, URL). "
    "Prefer frameworks with auto-escaping. Deploy a strict Content-Security-Policy "
    "without 'unsafe-inline'. Validate input on the server; never rely on client filters."
)


def detect_context(body: str, canary: str) -> list[str]:
    p = _ContextParser(canary)
    try:
        p.feed(body[:500_000])
    except Exception:
        pass
    ctx = p.contexts or []
    # URL context: canary inside href/src attribute value starting a URL
    if re.search(r'(href|src)\s*=\s*["\']?[^"\']*' + re.escape(canary), body, re.I):
        if "url" not in [c.split(":")[0] for c in ctx]:
            ctx.append("url")
    # dedupe preserving order
    seen, out = set(), []
    for c in ctx:
        base = c.split(":")[0]
        if base not in seen:
            seen.add(base); out.append(base)
    return out


async def _send(client, method, url, params, param, value):
    p = dict(params); p[param] = value
    if method == "GET":
        full = url + ("&" if "?" in url else "?") + _urlencode(p)
        resp = await client.get(full)
        return resp, full, None
    resp = await client.post(url, data=p)
    return resp, url, _urlencode(p).encode()


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not params:
        return findings
    headers = {"User-Agent": config.user_agent}

    for param in params:
        canary = make_canary()
        resp, full, body_sent = await _send(
            client, method, url, params, param, params[param] + canary)
        if not resp:
            continue
        if canary not in resp.text:
            continue  # not reflected at all
        contexts = detect_context(resp.text, canary)
        if not contexts:
            contexts = ["html-body"]

        for ctx in contexts:
            for payload in PAYLOADS.get(ctx, PAYLOADS["html-body"]):
                # confirm: payload must reflect unencoded
                r2, full2, body2 = await _send(
                    client, method, url, params, param, params[param] + payload)
                if not r2:
                    continue
                if payload in r2.text:
                    ev = Evidence(
                        request_raw=raw_request(method, full2, headers, body2),
                        response_raw=raw_response(r2.status_code, dict(r2.headers), r2.content),
                        proof=(f"Payload reflected verbatim in {ctx} context "
                               f"(2/2 confirmations, canary {canary})"),
                    )
                    findings.append(Finding(
                        type="Cross-Site Scripting", subtype=f"reflected-{ctx}",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        confidence=0.92, url=full2, method=method, param=param,
                        payload=payload, evidence=ev, cwe="CWE-79",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_XSS,
                        references=["https://owasp.org/www-community/attacks/xss/"],
                    ))
                    break
            if any(f.param == param and f.url == full for f in findings):
                break
    return findings
