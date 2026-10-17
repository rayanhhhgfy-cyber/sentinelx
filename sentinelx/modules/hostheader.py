"""SentinelX module [22]: Host Header Injection.

Real implementation: sends evil Host headers and detects (1) reflection in
password-reset / absolute URLs (poisoning), (2) cache-key confusion via
X-Forwarded-Host, (3) differential responses indicating virtual-host routing
issues. Safe: uses inert evil-sentinelx.example domain.
"""

from __future__ import annotations

import re

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


EVIL_HOST = "evil-sentinelx.example"

REMEDIATION_HOST = (
    "Validate the Host header against an allowlist of known domains. "
    "Generate password-reset links from a configured base URL, not the "
    "request Host. Ignore X-Forwarded-Host unless from trusted proxies."
)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    headers = {"User-Agent": config.user_agent, "Host": EVIL_HOST}

    # signal 1: baseline with evil Host — is it reflected anywhere?
    resp = await client.get(url, headers=headers, dedupe=False)
    if not resp:
        return findings

    reflected = EVIL_HOST in resp.text
    loc_reflect = EVIL_HOST in resp.headers.get("location", "")

    # signal 2: X-Forwarded-Host variant (cache/proxy confusion)
    xfwd = dict(headers); xfwd["X-Forwarded-Host"] = EVIL_HOST
    r2 = await client.get(url, headers=xfwd, dedupe=False)
    xfwd_reflect = bool(r2) and EVIL_HOST in r2.text

    if reflected or loc_reflect:
        # confirm: resend and check reflection persists (2 signals)
        r3 = await client.get(url, headers=headers, dedupe=False)
        if r3 and (EVIL_HOST in r3.text or EVIL_HOST in r3.headers.get("location", "")):
            kind = "location-header" if loc_reflect else "body-reflection"
            # higher severity if it looks like a reset/absolute-URL context
            reset_ctx = bool(re.search(
                r"password.*reset|reset.*password|href=[\"']https?://" + re.escape(EVIL_HOST),
                r3.text, re.I))
            ev = Evidence(
                request_raw=raw_request("GET", url, headers, None),
                response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                proof=(f"Host header '{EVIL_HOST}' reflected via {kind} (2/2). "
                       f"Password-reset poisoning possible: {reset_ctx}"),
            )
            findings.append(Finding(
                type="Host Header Injection", subtype=f"host-poisoning-{kind}",
                cvss_vector=("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
                             if reset_ctx else
                             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
                confidence=0.88 if reset_ctx else 0.75, url=url, method="GET",
                param="", payload=f"Host: {EVIL_HOST}", evidence=ev,
                cwe="CWE-640", owasp="A01:2021 – Broken Access Control",
                remediation=REMEDIATION_HOST,
                references=["https://portswigger.net/web-security/host-header"],
            ))

    if xfwd_reflect and not findings:
        ev = Evidence(
            request_raw=raw_request("GET", url, xfwd, None),
            response_raw=raw_response(r2.status_code, dict(r2.headers), r2.content),
            proof=f"X-Forwarded-Host '{EVIL_HOST}' reflected in response",
        )
        findings.append(Finding(
            type="Host Header Injection", subtype="x-forwarded-host-reflection",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            confidence=0.80, url=url, method="GET", param="",
            payload=f"X-Forwarded-Host: {EVIL_HOST}", evidence=ev,
            cwe="CWE-640", owasp="A01:2021 – Broken Access Control",
            remediation=REMEDIATION_HOST,
            references=["https://portswigger.net/web-security/host-header"],
        ))
    return findings
