"""SentinelX module [15]: Broken Access Control.

Real implementation: forced browsing of sensitive paths, HTTP method
tampering, path-tricks, header bypasses (X-Original-URL etc.),
case/trailing-char variations. Detection: 200/302 on restricted paths.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


SENSITIVE_PATHS = [
    "admin", "administrator", "wp-admin", "phpmyadmin", "adminer",
    ".git/HEAD", ".env", ".svn/entries", "backup.zip", "backup.sql", "db.sql",
    "debug", "console", "actuator", "actuator/env", "actuator/heapdump",
    "api/v1/admin", "graphql", "graphiql", "swagger-ui.html", "phpinfo.php",
    "server-status", "metrics", "health", "config", ".well-known/security.txt",
    ".DS_Store", "web.config", ".htaccess", "server.key",
]

HEADER_BYPASSES = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
]

PATH_TRICKS = [
    "/admin/../admin", "/admin/.", "/ADMIN", "/Admin", "/aDmIn",
    "/admin/", "/admin%20", "/admin%09", "/admin.json", "/admin?",
    "/admin;/user", "/;/admin",
]

REMEDIATION_BAC = (
    "Enforce access control server-side on every endpoint. Deny by default; "
    "do not rely on obscurity, client-side checks, or easily-spoofed headers "
    "(X-Forwarded-For etc.). Normalize paths before authorization checks."
)


async def scan_target(client: ScanClient, config: ScanConfig, target: str) -> list[Finding]:
    findings: list[Finding] = []
    base = urlsplit(target)
    root = f"{base.scheme}://{base.netloc}"
    headers = {"User-Agent": config.user_agent}
    sem = asyncio.Semaphore(15)

    async def check(method: str, path: str, extra_headers: dict | None = None):
        async with sem:
            full = root + path
            h = dict(headers); h.update(extra_headers or {})
            resp = await client.request(method, full, headers=h)
            if not resp:
                return
            # interesting: 200 with content, or redirect to non-login
            if resp.status_code == 200 and len(resp.content) > 200:
                loginish = re.search(r"password|log\s*in|sign\s*in", resp.text, re.I)
                if not loginish:
                    ev = Evidence(
                        request_raw=raw_request(method, full, h, None),
                        response_raw=raw_response(resp.status_code, dict(resp.headers),
                                                  resp.content[:2000]),
                        proof=f"{method} {path} → 200 ({len(resp.content)}b), no login form",
                    )
                    findings.append(Finding(
                        type="Broken Access Control", subtype=f"forced-browsing:{path}",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        confidence=0.75, url=full, method=method, param="",
                        payload=path, evidence=ev, cwe="CWE-425",
                        owasp="A01:2021 – Broken Access Control",
                        remediation=REMEDIATION_BAC,
                        references=["https://owasp.org/www-community/attacks/Forced_browsing"],
                    ))
            elif resp.status_code in (301, 302):
                loc = resp.headers.get("location", "")
                if not re.search(r"login|signin|auth", loc, re.I):
                    ev = Evidence(
                        request_raw=raw_request(method, full, h, None),
                        response_raw=raw_response(resp.status_code, dict(resp.headers), b""),
                        proof=f"{method} {path} → {resp.status_code} → {loc} (not a login page)",
                    )
                    findings.append(Finding(
                        type="Broken Access Control", subtype=f"redirect-bypass:{path}",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        confidence=0.65, url=full, method=method, param="",
                        payload=path, evidence=ev, cwe="CWE-425",
                        owasp="A01:2021 – Broken Access Control",
                        remediation=REMEDIATION_BAC,
                        references=["https://owasp.org/www-community/attacks/Forced_browsing"],
                    ))

    jobs = []
    for p in SENSITIVE_PATHS:
        jobs.append(check("GET", "/" + p))
    # method tampering on /admin
    for m in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
        jobs.append(check(m, "/admin"))
    # header bypasses
    for hb in HEADER_BYPASSES:
        jobs.append(check("GET", "/admin", hb))
    # path tricks
    for t in PATH_TRICKS:
        jobs.append(check("GET", t))
    await asyncio.gather(*jobs)
    return findings
