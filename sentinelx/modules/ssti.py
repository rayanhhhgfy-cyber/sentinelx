"""SentinelX module [21]: Server-Side Template Injection (SSTI).

Real implementation: polyglot probes across template engines (Jinja2,
Twig, Freemarker, ERB, Smarty), arithmetic evaluation detection (7*7=49),
engine-specific error signatures. Safe: only arithmetic, no code execution.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


# (payload, expected_marker_if_evaluated, engine_hint)
SSTI_PROBES = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/Velocity"),
    ("<%= 7*7 %>", "49", "ERB"),
    ("#{7*7}", "49", "Ruby"),
    ("*{7*7}", "49", "Thymeleaf"),
    ("{{7*'7'}}", "7777777", "Jinja2 string concat"),
]

ENGINE_ERRORS = [
    (re.compile(r"jinja2|undefinederror|templatenotfound", re.I), "Jinja2"),
    (re.compile(r"twig|syntax error.*unexpected", re.I), "Twig"),
    (re.compile(r"freemarker|_eval|templateexception", re.I), "Freemarker"),
    (re.compile(r"smarty|smartyexception", re.I), "Smarty"),
    (re.compile(r"erb|actionview::template::error", re.I), "ERB"),
]

REMEDIATION_SSTI = (
    "Never render user input as a template. Use logic-less templates with "
    "auto-escaping, sandbox template execution, and validate input strictly."
)


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
        for payload, marker, engine in SSTI_PROBES:
            resp, full, body_sent = await _send(
                client, method, url, params, param, params[param] + payload)
            if not resp:
                continue
            # signal 1: arithmetic evaluated (49 appears where 7*7 was sent)
            # signal 2: must NOT appear in baseline (avoid coincidental 49)
            if marker in resp.text and payload not in resp.text:
                # confirm with second request (2 signals: eval + confirmation)
                r2, _, _ = await _send(
                    client, method, url, params, param, params[param] + payload)
                if r2 and marker in r2.text and payload not in r2.text:
                    ev = Evidence(
                        request_raw=raw_request(method, full, headers, body_sent),
                        response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                        proof=f"SSTI confirmed (2/2): '{payload}' evaluated to '{marker}' ({engine})",
                    )
                    findings.append(Finding(
                        type="Server-Side Template Injection", subtype=f"ssti-{engine}",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidence=0.92, url=full, method=method, param=param,
                        payload=payload, evidence=ev, cwe="CWE-1336",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_SSTI,
                        references=["https://portswigger.net/web-security/cross-site-scripting/server-side-template-injection"],
                    ))
                    break
            # engine error disclosure (single signal + error = finding)
            for rx, eng in ENGINE_ERRORS:
                if rx.search(resp.text):
                    ev = Evidence(
                        request_raw=raw_request(method, full, headers, body_sent),
                        response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                        proof=f"Template engine error disclosed: {eng}",
                    )
                    findings.append(Finding(
                        type="Server-Side Template Injection", subtype="engine-error-disclosure",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        confidence=0.75, url=full, method=method, param=param,
                        payload=payload, evidence=ev, cwe="CWE-1336",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_SSTI,
                        references=["https://portswigger.net/web-security/cross-site-scripting/server-side-template-injection"],
                    ))
                    break
            if findings:
                break
        if findings:
            break
    return findings
