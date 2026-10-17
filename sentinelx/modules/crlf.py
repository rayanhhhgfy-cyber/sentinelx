"""SentinelX module [28]: CRLF / HTTP Response Splitting.

Real implementation: injects %0d%0a into params reflected in headers,
verifies via injected header reflection. Safe: inert header name.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


CRLF_PAYLOADS = [
    "%0d%0aX-SX-Injected: true",
    "%0aX-SX-Injected: true",
    "%0dX-SX-Injected: true",
    "\r\nX-SX-Injected: true",
]

REMEDIATION_CRLF = (
    "Strip CR/LF characters from user input before placing in headers. "
    "Use framework header APIs that reject control characters."
)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not params:
        return findings
    headers = {"User-Agent": config.user_agent}

    for param in params:
        for payload in CRLF_PAYLOADS:
            p = dict(params); p[param] = params[param] + payload
            if method == "GET":
                full = url + ("&" if "?" in url else "?") + _urlencode(p)
                resp = await client.get(full, dedupe=False)
                body_sent = None
            else:
                resp = await client.post(url, data=p, dedupe=False)
                full, body_sent = url, _urlencode(p).encode()
            if not resp:
                continue
            # signal 1: injected header present in response
            injected = resp.headers.get("x-sx-injected", "")
            # signal 2: confirm with resend (rules out coincidence)
            if injected:
                if method == "GET":
                    r2 = await client.get(full, dedupe=False)
                else:
                    r2 = await client.post(url, data=p, dedupe=False)
                if r2 and r2.headers.get("x-sx-injected"):
                    ev = Evidence(
                        request_raw=raw_request(method, full, headers, body_sent),
                        response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                        proof="CRLF injection confirmed (2/2): injected header reflected in response",
                    )
                    findings.append(Finding(
                        type="CRLF Injection", subtype="http-response-splitting",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        confidence=0.90, url=full, method=method, param=param,
                        payload=payload, evidence=ev, cwe="CWE-113",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_CRLF,
                        references=["https://owasp.org/www-community/attacks/CRLF_Injection"],
                    ))
                    break
        if findings:
            break
    return findings
