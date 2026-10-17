"""SentinelX module [23]: Web Cache Poisoning.

Real implementation: cache-buster differential analysis. Sends a request
with a unique cache buster + potentially-poisoning header; if a second
request with the same buster returns the poisoned content, the cache is
poisonable. Safe: uses inert markers, no destructive payloads.
"""

from __future__ import annotations

import re
import secrets

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


def _buster() -> str:
    return "sxb" + secrets.token_hex(4)


POISON_HEADERS = [
    {"X-Forwarded-Host": "evil-sentinelx.example"},
    {"X-Host": "evil-sentinelx.example"},
    {"X-Forwarded-Scheme": "http"},
]

REMEDIATION_CACHE = (
    "Ensure caches key on all security-relevant headers. Never cache "
    "responses containing user input unkeyed. Strip X-Forwarded-* at the "
    "edge unless explicitly trusted."
)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    headers = {"User-Agent": config.user_agent}

    # signal 1: is there a cache? (HIT/MISS/AGE headers or timing consistency)
    r0 = await client.get(url, headers=headers, dedupe=False)
    if not r0:
        return findings
    cache_hdrs = {k.lower(): v for k, v in r0.headers.items()
                  if k.lower() in ("x-cache", "x-cache-hits", "age",
                                   "cf-cache-status", "x-varnish", "via")}
    if not cache_hdrs:
        return findings  # no cache signals; skip to save requests

    for pheaders in POISON_HEADERS:
        buster = _buster()
        h = dict(headers); h.update(pheaders)
        sep = "&" if "?" in url else "?"
        pwn_url = f"{url}{sep}cb={buster}"
        # poison attempt
        r1 = await client.request("GET", pwn_url, headers=h, dedupe=False)
        if not r1:
            continue
        poisoned = any("evil-sentinelx.example" in v or "evil-sentinelx.example" in r1.text
                       for v in [r1.headers.get("location", "")])
        poisoned = poisoned or "evil-sentinelx.example" in r1.text
        if not poisoned:
            continue
        # signal 2: second request WITHOUT poison headers, same buster —
        # if still poisoned, the cache served our poisoned copy
        r2 = await client.request("GET", pwn_url, headers=headers, dedupe=False)
        if r2 and "evil-sentinelx.example" in r2.text:
            ev = Evidence(
                request_raw=raw_request("GET", pwn_url, h, None),
                response_raw=raw_response(r2.status_code, dict(r2.headers), r2.content),
                proof=(f"Cache poisoning confirmed (2/2): poisoned header "
                       f"{list(pheaders)[0]} persisted in cached response for buster {buster}"),
            )
            findings.append(Finding(
                type="Web Cache Poisoning", subtype="unkeyed-header",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
                confidence=0.85, url=pwn_url, method="GET", param="",
                payload=str(pheaders), evidence=ev, cwe="CWE-444",
                owasp="A05:2021 – Security Misconfiguration",
                remediation=REMEDIATION_CACHE,
                references=["https://portswigger.net/web-security/web-cache-poisoning"],
            ))
            break
    return findings
