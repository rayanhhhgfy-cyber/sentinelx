"""SentinelX modules: security headers audit, cookie audit, CORS, HTTP methods.

All passive or single-request active checks with real evidence.
"""

from __future__ import annotations

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


def _ev(method, url, headers, resp) -> Evidence:
    body = resp.content if resp else b""
    return Evidence(
        request_raw=raw_request(method, url, headers, None),
        response_raw=raw_response(resp.status_code if resp else 0,
                                  dict(resp.headers) if resp else {}, body[:2000]),
        proof="",
    )


REQUIRED_HEADERS = {
    "strict-transport-security": (
        "Missing HSTS header",
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    ),
    "content-security-policy": (
        "Missing Content-Security-Policy",
        "Deploy a strict CSP without 'unsafe-inline' / 'unsafe-eval'.",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    ),
    "x-frame-options": (
        "Missing X-Frame-Options (clickjacking risk)",
        "Set X-Frame-Options: DENY or SAMEORIGIN (or frame-ancestors in CSP).",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options",
        "Set X-Content-Type-Options: nosniff.",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
    ),
    "referrer-policy": (
        "Missing Referrer-Policy",
        "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    # --- deep-check additions: modern isolation headers ---
    "permissions-policy": (
        "Missing Permissions-Policy",
        "Set Permissions-Policy to disable unused browser features "
        "(e.g. camera=(), microphone=(), geolocation=()).",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    "cross-origin-embedder-policy": (
        "Missing Cross-Origin-Embedder-Policy",
        "Set Cross-Origin-Embedder-Policy: require-corp to enable "
        "cross-origin isolation (Spectre defense).",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    "cross-origin-opener-policy": (
        "Missing Cross-Origin-Opener-Policy",
        "Set Cross-Origin-Opener-Policy: same-origin to isolate the "
        "browsing context from cross-origin popups.",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    "cross-origin-resource-policy": (
        "Missing Cross-Origin-Resource-Policy",
        "Set Cross-Origin-Resource-Policy: same-origin (or same-site) "
        "to control which sites may load this resource.",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
}


def _check_csp_weaknesses(csp: str) -> list[tuple[str, str]]:
    """Return (issue, detail) for weak CSP directives. Only flags real gaps."""
    issues = []
    low = csp.lower()
    if "'unsafe-inline'" in low:
        issues.append(("csp-unsafe-inline",
                       "CSP allows 'unsafe-inline' — XSS payloads can execute inline"))
    if "'unsafe-eval'" in low:
        issues.append(("csp-unsafe-eval",
                       "CSP allows 'unsafe-eval' — enables JS code-generation attacks"))
    if "data:" in low and "script-src" in low:
        # data: in script-src is dangerous
        for directive in low.split(";"):
            if directive.strip().startswith("script-src") and "data:" in directive:
                issues.append(("csp-data-in-script-src",
                               "CSP script-src allows data: URIs — XSS bypass vector"))
                break
    if "*" in low:
        for directive in low.split(";"):
            d = directive.strip()
            if d.startswith(("script-src", "object-src")) and "*" in d.split():
                issues.append(("csp-wildcard",
                               f"CSP {d.split()[0]} uses wildcard — overly permissive"))
                break
    return issues


async def scan_headers(client: ScanClient, config: ScanConfig, url: str) -> list[Finding]:
    findings = []
    headers = {"User-Agent": config.user_agent}
    resp = await client.get(url)
    if not resp:
        return findings
    present = {k.lower(): v for k, v in resp.headers.items()}
    for hname, (title, remediation, vector) in REQUIRED_HEADERS.items():
        if hname not in present:
            ev = _ev("GET", url, headers, resp)
            ev.proof = f"Response headers: {', '.join(sorted(present)) or '(none)'}"
            findings.append(Finding(
                type="Security Misconfiguration", subtype=f"missing-header:{hname}",
                cvss_vector=vector, confidence=1.0, url=url, method="GET",
                param="", payload=title, evidence=ev, cwe="CWE-693",
                owasp="A05:2021 – Security Misconfiguration",
                remediation=remediation,
                references=["https://owasp.org/www-project-secure-headers/"],
            ))
    # weak HSTS check
    hsts = present.get("strict-transport-security", "")
    if hsts and "max-age" in hsts:
        try:
            age = int(hsts.split("max-age=")[1].split(";")[0].strip())
            if age < 31536000:
                ev = _ev("GET", url, headers, resp)
                ev.proof = f"HSTS max-age={age} (< 31536000)"
                findings.append(Finding(
                    type="Security Misconfiguration", subtype="weak-hsts",
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    confidence=1.0, url=url, method="GET", param="",
                    payload="Weak HSTS max-age", evidence=ev, cwe="CWE-693",
                    owasp="A05:2021 – Security Misconfiguration",
                    remediation="Set HSTS max-age to at least 31536000.",
                    references=["https://owasp.org/www-project-secure-headers/"],
                ))
        except (ValueError, IndexError):
            pass
    # weak CSP directive analysis (only when CSP is present)
    csp = present.get("content-security-policy", "")
    if csp:
        for subtype, detail in _check_csp_weaknesses(csp):
            ev = _ev("GET", url, headers, resp)
            ev.proof = f"CSP: {csp[:300]} — {detail}"
            findings.append(Finding(
                type="Security Misconfiguration", subtype=subtype,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                confidence=0.9, url=url, method="GET", param="",
                payload=detail, evidence=ev, cwe="CWE-693",
                owasp="A05:2021 – Security Misconfiguration",
                remediation="Tighten the CSP: remove 'unsafe-inline'/'unsafe-eval', "
                            "avoid wildcards and data: in script-src.",
                references=["https://owasp.org/www-project-secure-headers/"],
            ))
    return findings


async def scan_cookies(client: ScanClient, config: ScanConfig, url: str) -> list[Finding]:
    findings = []
    headers = {"User-Agent": config.user_agent}
    resp = await client.get(url)
    if not resp:
        return findings
    raw_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    if not raw_cookies:
        # httpx: use raw headers
        raw_cookies = [v.decode("latin1") for k, v in resp.headers.raw
                       if k.lower() == b"set-cookie"]
    for cookie in raw_cookies:
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        issues = []
        if "secure" not in low:
            issues.append(("missing Secure flag",
                           "Set the Secure flag so cookies only travel over HTTPS.",
                           "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"))
        if "httponly" not in low:
            issues.append(("missing HttpOnly flag",
                           "Set HttpOnly so JavaScript cannot read the cookie (XSS defense).",
                           "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"))
        if "samesite" not in low:
            issues.append(("missing SameSite attribute",
                           "Set SameSite=Lax or Strict to reduce CSRF risk.",
                           "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"))
        for title, remediation, vector in issues:
            ev = _ev("GET", url, headers, resp)
            ev.proof = f"Set-Cookie: {cookie[:200]}"
            findings.append(Finding(
                type="Security Misconfiguration", subtype=f"cookie:{title}",
                cvss_vector=vector, confidence=1.0, url=url, method="GET",
                param=name, payload=title, evidence=ev, cwe="CWE-614",
                owasp="A05:2021 – Security Misconfiguration",
                remediation=remediation,
                references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
            ))
    return findings


async def scan_cors(client: ScanClient, config: ScanConfig, url: str) -> list[Finding]:
    findings = []
    evil = "https://evil-sentinelx.example"
    headers = {"User-Agent": config.user_agent, "Origin": evil}
    resp = await client.get(url, headers=headers)
    if not resp:
        return findings
    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        ev = _ev("GET", url, headers, resp)
        ev.proof = "Access-Control-Allow-Origin: * with Allow-Credentials: true"
        findings.append(Finding(
            type="Security Misconfiguration", subtype="cors-wildcard-credentials",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            confidence=0.95, url=url, method="GET", param="Origin",
            payload=evil, evidence=ev, cwe="CWE-942",
            owasp="A05:2021 – Security Misconfiguration",
            remediation="Never combine ACAO:* with credentials. Echo only trusted origins.",
            references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
        ))
    elif acao == evil:
        ev = _ev("GET", url, headers, resp)
        ev.proof = f"Server reflected attacker Origin: {acao}"
        findings.append(Finding(
            type="Security Misconfiguration", subtype="cors-origin-reflection",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            confidence=0.9, url=url, method="GET", param="Origin",
            payload=evil, evidence=ev, cwe="CWE-942",
            owasp="A05:2021 – Security Misconfiguration",
            remediation="Validate Origin against an allowlist; do not reflect arbitrary origins.",
            references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
        ))
    return findings


async def scan_methods(client: ScanClient, config: ScanConfig, url: str) -> list[Finding]:
    findings = []
    headers = {"User-Agent": config.user_agent}
    resp = await client.request("OPTIONS", url, headers=headers)
    if not resp:
        return findings
    allow = resp.headers.get("allow", "")
    dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in allow.upper()]
    if dangerous:
        ev = _ev("OPTIONS", url, headers, resp)
        ev.proof = f"Allow: {allow}"
        findings.append(Finding(
            type="Security Misconfiguration", subtype="dangerous-http-methods",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            confidence=0.85, url=url, method="OPTIONS", param="",
            payload=",".join(dangerous), evidence=ev, cwe="CWE-749",
            owasp="A05:2021 – Security Misconfiguration",
            remediation="Disable unneeded HTTP methods (TRACE, PUT, DELETE) at the server.",
            references=["https://owasp.org/www-community/attacks/HTTP_Methods_Testing"],
        ))
    return findings
