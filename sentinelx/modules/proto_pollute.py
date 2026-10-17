"""SentinelX module [34]: Prototype Pollution.

Real implementation: injects __proto__/constructor/prototype payloads via
query params and JSON bodies, detects via polluted property reflection in
subsequent responses. Safe: uses inert 'sxPolluted' marker property.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


MARKER = "sxPolluted"

POLLUTION_PAYLOADS = [
    ("__proto__[sxPolluted]", "polluted1"),
    ("__proto__.sxPolluted", "polluted2"),
    ("constructor[prototype][sxPolluted]", "polluted3"),
]

REMEDIATION_PROTO = (
    "Use Object.create(null) for dictionaries, validate keys against "
    "__proto__/constructor/prototype, or use Map instead of plain objects. "
    "Freeze Object.prototype in critical contexts."
)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    headers = {"User-Agent": config.user_agent,
               "Content-Type": "application/json"}

    # 1. query param pollution
    for pkey, pval in POLLUTION_PAYLOADS:
        p = {pkey: pval, "a": "b"}
        full = url + ("&" if "?" in url else "?") + _urlencode(p)
        resp = await client.get(full, dedupe=False)
        if not resp:
            continue
        # signal 1: marker reflected in JS context
        if MARKER in resp.text:
            # signal 2: check it's in a prototype-ish context, confirm resend
            r2 = await client.get(full, dedupe=False)
            if r2 and MARKER in r2.text:
                # verify it's not just verbatim echo of our param name
                # (real pollution: marker appears as a JS property)
                if re.search(rf"['\"]?{MARKER}['\"]?\s*[:=]", r2.text):
                    ev = Evidence(
                        request_raw=raw_request("GET", full, headers, None),
                        response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                        proof=f"Prototype pollution confirmed (2/2): '{MARKER}' reflected as JS property",
                    )
                    findings.append(Finding(
                        type="Prototype Pollution", subtype="query-param",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        confidence=0.80, url=full, method="GET", param=pkey,
                        payload=f"{pkey}={pval}", evidence=ev, cwe="CWE-1321",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_PROTO,
                        references=["https://portswigger.net/web-security/prototype-pollution"],
                    ))
                    break
        if findings:
            break

    # 2. JSON body pollution (POST)
    if not findings:
        for pkey, pval in POLLUTION_PAYLOADS:
            body = json.dumps({"__proto__": {MARKER: pval}}).encode()
            resp = await client.post(url, data=body, headers=headers, dedupe=False)
            if resp and MARKER in resp.text:
                r2 = await client.post(url, data=body, headers=headers, dedupe=False)
                if r2 and MARKER in r2.text:
                    ev = Evidence(
                        request_raw=raw_request("POST", url, headers, body[:300]),
                        response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                        proof=f"Prototype pollution via JSON confirmed (2/2): '{MARKER}' in response",
                    )
                    findings.append(Finding(
                        type="Prototype Pollution", subtype="json-body",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        confidence=0.80, url=url, method="POST", param="__proto__",
                        payload=body[:100].decode(), evidence=ev, cwe="CWE-1321",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_PROTO,
                        references=["https://portswigger.net/web-security/prototype-pollution"],
                    ))
                    break
            if findings:
                break
    return findings
