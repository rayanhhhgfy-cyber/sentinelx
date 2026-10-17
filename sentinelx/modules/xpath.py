"""SentinelX module [26]: XPath Injection.

Real implementation: error-based (XPath parser errors) + boolean-blind
(' or '1'='1 vs ' or '1'='2 differential). Safe: read-only queries.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.core.baseline import get_baseline


XPATH_ERRORS = [
    (re.compile(r"XPathException|xpath.*error|invalid.*xpath", re.I), "XPath parser error"),
    (re.compile(r"unexpected token|unclosed string literal", re.I), "XPath syntax error"),
]

BOOLEAN_TRUE = "' or '1'='1"
BOOLEAN_FALSE = "' or '1'='2"

REMEDIATION_XPATH = (
    "Use parameterized XPath queries with variable binding. Never "
    "concatenate user input into XPath expressions. Validate input strictly."
)


async def _send(client, method, url, params, param, value):
    p = dict(params); p[param] = value
    if method == "GET":
        full = url + ("&" if "?" in url else "?") + _urlencode(p)
        resp = await client.get(full, dedupe=False)
        return resp, full, None
    resp = await client.post(url, data=p, dedupe=False)
    return resp, url, _urlencode(p).encode()


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not params:
        return findings
    headers = {"User-Agent": config.user_agent}

    for param in params:
        bl = await get_baseline(client, method, url, params)
        base_body = bl.body if bl else ""

        # 1. error-based
        for payload in ["'", "' or '1'='1"]:
            resp, full, body_sent = await _send(
                client, method, url, params, param, params[param] + payload)
            if not resp:
                continue
            for rx, label in XPATH_ERRORS:
                if rx.search(resp.text) and not rx.search(base_body):
                    r2, _, _ = await _send(
                        client, method, url, params, param, params[param] + payload)
                    if r2 and rx.search(r2.text):
                        ev = Evidence(
                            request_raw=raw_request(method, full, headers, body_sent),
                            response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                            proof=f"XPath injection confirmed (2/2): {label}",
                        )
                        findings.append(Finding(
                            type="XPath Injection", subtype="error-based",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            confidence=0.88, url=full, method=method, param=param,
                            payload=payload, evidence=ev, cwe="CWE-643",
                            owasp="A03:2021 – Injection",
                            remediation=REMEDIATION_XPATH,
                            references=["https://owasp.org/www-community/attacks/XPATH_Injection"],
                        ))
                        break
            if findings:
                break
        if findings:
            break

        # 2. boolean-blind
        rt, _, _ = await _send(client, method, url, params, param, params[param] + BOOLEAN_TRUE)
        rf, _, _ = await _send(client, method, url, params, param, params[param] + BOOLEAN_FALSE)
        if rt and rf and rt.text != rf.text:
            rt2, _, _ = await _send(client, method, url, params, param, params[param] + BOOLEAN_TRUE)
            if rt2 and rt2.text == rt.text:
                ev = Evidence(
                    request_raw=raw_request(method, url, headers, None),
                    response_raw=raw_response(rt.status_code, dict(rt.headers), rt.content),
                    proof="XPath boolean-blind: TRUE/FALSE payloads return different results (2/2)",
                )
                findings.append(Finding(
                    type="XPath Injection", subtype="boolean-blind",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    confidence=0.85, url=url, method=method, param=param,
                    payload=BOOLEAN_TRUE, evidence=ev, cwe="CWE-643",
                    owasp="A03:2021 – Injection",
                    remediation=REMEDIATION_XPATH,
                    references=["https://owasp.org/www-community/attacks/XPATH_Injection"],
                ))
                break
    return findings
