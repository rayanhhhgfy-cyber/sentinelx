"""SentinelX module [27]: Command Injection via HTTP Headers.

Real implementation: injects time-based payloads into User-Agent, Referer,
X-Forwarded-For and detects via baseline-subtracted timing. Safe: sleep only.
"""

from __future__ import annotations

import re
import time

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.core.baseline import adaptive_delay


TARGET_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP", "Cookie"]

REMEDIATION_HDR = (
    "Never pass HTTP headers to shells. Treat all headers as untrusted input. "
    "Log headers safely without shell interpretation."
)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    headers = {"User-Agent": config.user_agent}

    # baseline timing (2 samples, no injection)
    base_times = []
    for _ in range(2):
        t0 = time.monotonic()
        resp = await client.get(url, headers=headers, dedupe=False)
        if not resp:
            return findings
        base_times.append(time.monotonic() - t0)
    base_avg = sum(base_times) / len(base_times)
    base_max = max(base_times)
    delay = adaptive_delay(base_avg)

    for hname in TARGET_HEADERS:
        payload = f"sx; sleep {int(delay)}"
        h = dict(headers)
        if hname == "Cookie":
            h["Cookie"] = f"sx={payload}"
        else:
            h[hname] = payload
        samples = []
        for _ in range(2):
            t0 = time.monotonic()
            resp = await client.get(url, headers=h, dedupe=False)
            el = time.monotonic() - t0
            if not resp:
                break
            samples.append(el)
        if len(samples) < 2:
            continue
        threshold = base_max + delay * 0.7
        if all(s >= threshold for s in samples) and base_max < delay * 0.5:
            ev = Evidence(
                request_raw=raw_request("GET", url, h, None),
                response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                proof=(f"Header command injection via {hname} (2/2): "
                       f"{samples[0]:.1f}s/{samples[1]:.1f}s vs baseline {base_max:.2f}s"),
            )
            findings.append(Finding(
                type="OS Command Injection", subtype=f"header-{hname}",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                confidence=0.85, url=url, method="GET", param=hname,
                payload=payload, evidence=ev, cwe="CWE-78",
                owasp="A03:2021 – Injection",
                remediation=REMEDIATION_HDR,
                references=["https://owasp.org/www-community/attacks/Command_Injection"],
            ))
            break
    return findings
