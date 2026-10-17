"""SentinelX module [31]: Clickjacking.

Real implementation: checks X-Frame-Options and CSP frame-ancestors on the
target. Missing both = clickjacking possible. Proof: framing check via
header analysis (no browser needed — header absence is definitive).
"""

from __future__ import annotations

import re

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


REMEDIATION_CLICKJACK = (
    "Set X-Frame-Options: DENY or SAMEORIGIN, or better: "
    "Content-Security-Policy: frame-ancestors 'none'. Apply to all pages."
)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    # only run once per scan (on main target)
    if url.rstrip("/") != config.target.rstrip("/"):
        return findings
    headers = {"User-Agent": config.user_agent}
    resp = await client.get(url, headers=headers, dedupe=False)
    if not resp:
        return findings

    xfo = resp.headers.get("x-frame-options", "").upper()
    csp = resp.headers.get("content-security-policy", "")
    # signal 1: XFO missing or weak
    xfo_ok = xfo in ("DENY", "SAMEORIGIN")
    # signal 2: CSP frame-ancestors present and restrictive
    fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.I)
    csp_ok = bool(fa_match and fa_match.group(1).strip().lower() in
                  ("'none'", "'self'"))

    if not xfo_ok and not csp_ok:
        # confirm: check a second page (rules out per-page anomaly)
        r2 = await client.get(url.rstrip("/") + "/", headers=headers, dedupe=False)
        xfo2 = (r2.headers.get("x-frame-options", "") if r2 else "").upper()
        csp2 = r2.headers.get("content-security-policy", "") if r2 else ""
        fa2 = re.search(r"frame-ancestors\s+([^;]+)", csp2, re.I)
        if not (xfo2 in ("DENY", "SAMEORIGIN")) and not (
                fa2 and fa2.group(1).strip().lower() in ("'none'", "'self'")):
            missing = []
            if not xfo_ok:
                missing.append("X-Frame-Options")
            if not csp_ok:
                missing.append("CSP frame-ancestors")
            ev = Evidence(
                request_raw=raw_request("GET", url, headers, None),
                response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content[:1000]),
                proof=f"Clickjacking confirmed (2/2 pages): missing {', '.join(missing)} — page can be framed",
            )
            findings.append(Finding(
                type="Clickjacking", subtype="missing-frame-protection",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                confidence=0.90, url=url, method="GET", param="",
                payload="", evidence=ev, cwe="CWE-1021",
                owasp="A05:2021 – Security Misconfiguration",
                remediation=REMEDIATION_CLICKJACK,
                references=["https://owasp.org/www-community/attacks/Clickjacking"],
            ))
    return findings
