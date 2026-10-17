"""SentinelX module: open redirect + directory bruteforce."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlencode as _urlencode, urlsplit

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


REDIRECT_PAYLOADS = [
    "//evil-sentinelx.example", "https://evil-sentinelx.example",
    "http://evil-sentinelx.example", "/%2F%2Fevil-sentinelx.example",
    "https:evil-sentinelx.example", "//evil-sentinelx.example/%2F..",
]

REMEDIATION_REDIRECT = (
    "Validate redirect targets against an allowlist of relative paths or "
    "trusted domains. Never use raw user input in Location headers or "
    "window.location assignments."
)


async def scan_openredirect(client: ScanClient, config: ScanConfig,
                            method: str, url: str, params: dict) -> list[Finding]:
    findings = []
    if not params:
        return findings
    headers = {"User-Agent": config.user_agent}
    interesting = [p for p in params
                   if re.search(r"url|redirect|next|return|dest|target|continue|ref", p, re.I)]
    targets = interesting or list(params)
    for param in targets:
        for payload in REDIRECT_PAYLOADS:
            p = dict(params); p[param] = payload
            if method == "GET":
                full = url + ("&" if "?" in url else "?") + _urlencode(p)
                resp = await client.get(full)
                body_sent = None
            else:
                resp = await client.post(url, data=p)
                full, body_sent = url, _urlencode(p).encode()
            if not resp:
                continue
            loc = resp.headers.get("location", "")
            evil_hit = "evil-sentinelx.example" in loc
            meta_hit = re.search(
                r'meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url\s*=\s*[^>]*evil-sentinelx\.example',
                resp.text, re.I)
            js_hit = ("evil-sentinelx.example" in resp.text and
                      re.search(r"location\s*(\.href|=)|assign\s*\(", resp.text))
            if evil_hit or meta_hit or js_hit:
                kind = ("location-header" if evil_hit
                        else "meta-refresh" if meta_hit else "js-redirect")
                ev = Evidence(
                    request_raw=raw_request(method, full, headers, body_sent),
                    response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                    proof=f"Attacker URL reflected via {kind}",
                )
                findings.append(Finding(
                    type="Open Redirect", subtype=kind,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    confidence=0.9, url=full, method=method, param=param,
                    payload=payload, evidence=ev, cwe="CWE-601",
                    owasp="A01:2021 – Broken Access Control",
                    remediation=REMEDIATION_REDIRECT,
                    references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
                ))
                break
    return findings


ADMIN_PATHS = [
    "admin", "administrator", "wp-admin", "phpmyadmin", "adminer",
    ".git/HEAD", ".env", ".svn/entries", "backup.zip", "backup.sql",
    "debug", "console", "actuator", "actuator/env", "api/v1/admin",
    "graphql", "swagger-ui.html", "phpinfo.php", "server-status",
    "metrics", "health", "config", ".well-known/security.txt",
    "robots.txt", "sitemap.xml",
]


async def scan_dirfuzz(client: ScanClient, config: ScanConfig, url: str) -> list[Finding]:
    findings = []
    base = urlsplit(url)
    root = f"{base.scheme}://{base.netloc}"
    headers = {"User-Agent": config.user_agent}
    sem = asyncio.Semaphore(20)

    async def probe(path: str):
        async with sem:
            full = root + "/" + path.lstrip("/")
            resp = await client.get(full, headers=headers)
            if not resp:
                return
            # interesting: 200 with non-trivial body, or revealing status
            if resp.status_code == 200 and len(resp.content) > 100:
                # filter out soft-404s: same length as base 404 page heuristic
                ev = Evidence(
                    request_raw=raw_request("GET", full, headers, None),
                    response_raw=raw_response(resp.status_code, dict(resp.headers),
                                              resp.content[:2000]),
                    proof=f"HTTP 200, {len(resp.content)} bytes at /{path}",
                )
                findings.append(Finding(
                    type="Sensitive Path Exposure", subtype=f"path:/{path}",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    confidence=0.7, url=full, method="GET", param="",
                    payload=f"/{path}", evidence=ev, cwe="CWE-538",
                    owasp="A05:2021 – Security Misconfiguration",
                    remediation="Remove or protect sensitive paths; block /.git, /.env, backups at the edge.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                ))

    await asyncio.gather(*[probe(p) for p in ADMIN_PATHS])
    return findings
