"""SentinelX module [25]: LDAP Injection.

Real implementation: error-based (LDAP error signatures) + boolean-blind
differential (wildcard vs non-matching filter). Safe: read-only filters.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.core.baseline import get_baseline


ERROR_PAYLOADS = ["*", ")(", "*)(&", "*)(", "\\", "\x00"]

LDAP_ERRORS = [
    (re.compile(r"LDAPException|LDAP.*error|invalid.*filter", re.I), "LDAP error disclosed"),
    (re.compile(r"unbalanced.*parenth|bad search filter", re.I), "LDAP filter syntax error"),
]

BOOLEAN_PAIRS = [
    ("*", "nonexistent-sx-98765"),  # wildcard (true) vs garbage (false)
]

REMEDIATION_LDAP = (
    "Escape LDAP metacharacters (*, (, ), \\, NUL) in user input. Use "
    "parameterized LDAP APIs, apply least-privilege bind accounts."
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
    # focus on params that look like usernames/search
    ldapish = [p for p in params
               if re.search(r"user|name|search|query|filter|login|uid|cn", p, re.I)]
    targets = ldapish or list(params)[:1]

    for param in targets:
        bl = await get_baseline(client, method, url, params)
        base_body = bl.body if bl else ""

        # 1. error-based
        for payload in ERROR_PAYLOADS:
            resp, full, body_sent = await _send(
                client, method, url, params, param, params[param] + payload)
            if not resp:
                continue
            for rx, label in LDAP_ERRORS:
                if rx.search(resp.text) and not rx.search(base_body):
                    # confirm
                    r2, _, _ = await _send(
                        client, method, url, params, param, params[param] + payload)
                    if r2 and rx.search(r2.text):
                        ev = Evidence(
                            request_raw=raw_request(method, full, headers, body_sent),
                            response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                            proof=f"LDAP injection confirmed (2/2): {label}",
                        )
                        findings.append(Finding(
                            type="LDAP Injection", subtype="error-based",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            confidence=0.88, url=full, method=method, param=param,
                            payload=payload, evidence=ev, cwe="CWE-90",
                            owasp="A03:2021 – Injection",
                            remediation=REMEDIATION_LDAP,
                            references=["https://owasp.org/www-community/attacks/LDAP_Injection"],
                        ))
                        break
            if findings:
                break
        if findings:
            break

        # 2. boolean-blind: wildcard vs non-existent
        for true_p, false_p in BOOLEAN_PAIRS:
            rt, _, _ = await _send(client, method, url, params, param, true_p)
            rf, _, _ = await _send(client, method, url, params, param, false_p)
            if rt and rf and rt.text != rf.text:
                # confirm both
                rt2, _, _ = await _send(client, method, url, params, param, true_p)
                rf2, _, _ = await _send(client, method, url, params, param, false_p)
                if rt2 and rf2 and rt2.text != rf2.text and rt.text == rt2.text:
                    ev = Evidence(
                        request_raw=raw_request(method, url, headers, None),
                        response_raw=raw_response(rt.status_code, dict(rt.headers), rt.content),
                        proof="LDAP boolean-blind: wildcard filter returns different results than non-matching (2/2)",
                    )
                    findings.append(Finding(
                        type="LDAP Injection", subtype="boolean-blind",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        confidence=0.85, url=url, method=method, param=param,
                        payload=true_p, evidence=ev, cwe="CWE-90",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_LDAP,
                        references=["https://owasp.org/www-community/attacks/LDAP_Injection"],
                    ))
                    break
        if findings:
            break
    return findings
