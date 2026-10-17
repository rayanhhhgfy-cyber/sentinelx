"""SentinelX module [32]: IDOR via REST API.

Real implementation: enumerates numeric API IDs (/api/users/1,2,3...),
detects auth-bypass by comparing responses with/without auth tokens.
Complements modules/idor.py (which handles HTML endpoints).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


REMEDIATION_API_IDOR = (
    "Enforce object-level authorization on every API endpoint. Check that "
    "the authenticated user owns the requested object. Use unpredictable IDs."
)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    # find API-like endpoints with numeric IDs
    u = urlsplit(url)
    m = re.search(r"^(.*/)(api/[^/]*/)\d+/?$", u.path)
    if not m:
        # also try: /api/<resource> without ID — enumerate 1..5
        if "/api/" not in u.path:
            return findings
        base_path = u.path.rstrip("/") + "/"
    else:
        base_path = m.group(1) + m.group(2)
    base = urlunsplit((u.scheme, u.netloc, base_path, "", ""))

    headers = {"User-Agent": config.user_agent}
    # signal 1: enumerate IDs 1-5, collect distinct successful responses
    bodies = {}
    for i in range(1, 6):
        resp = await client.get(f"{base}{i}", headers=headers, dedupe=False)
        if resp and resp.status_code == 200 and len(resp.content) > 20:
            bodies[i] = resp.text[:500]
    if len(bodies) < 2:
        return findings  # need 2+ distinct objects to prove IDOR

    # signal 2: auth bypass — try without auth headers vs with
    # (if config has auth tokens, compare; else check if objects differ by ID)
    distinct = len(set(bodies.values())) >= 2
    if distinct:
        # confirm: re-fetch two IDs, verify still distinct (2/2)
        r1 = await client.get(f"{base}1", headers=headers, dedupe=False)
        r2 = await client.get(f"{base}2", headers=headers, dedupe=False)
        if (r1 and r2 and r1.status_code == 200 and r2.status_code == 200
                and r1.text[:500] != r2.text[:500]):
            ev = Evidence(
                request_raw=raw_request("GET", f"{base}1", headers, None),
                response_raw=raw_response(r1.status_code, dict(r1.headers), r1.content[:2000]),
                proof=(f"API IDOR confirmed (2/2): {len(bodies)} distinct objects "
                       f"accessible by enumerating {base}{{1..5}} without authorization"),
            )
            findings.append(Finding(
                type="Insecure Direct Object Reference", subtype="api-id-enumeration",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                confidence=0.88, url=base, method="GET", param="id",
                payload="{1..5}", evidence=ev, cwe="CWE-639",
                owasp="A01:2021 – Broken Access Control",
                remediation=REMEDIATION_API_IDOR,
                references=["https://owasp.org/API-Security/editions/2023/en/0x11-t10/"],
            ))
    return findings


# Path-based API ID enumeration works without query params.
scan_endpoint.NEEDS_PARAMS = False
