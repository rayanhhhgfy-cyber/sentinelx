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

    # --- runtime evidence layer (jsruntime): does page JS navigate using
    # attacker-controlled data? Proven taint flows to nav sinks raise this
    # from heuristic to CONFIRMED client-side open redirect.
    try:
        from sentinelx.jsruntime import assists as _assists
        _rt = await _assists.analyze_page(client, config, url, timeout=6.0)
        if _rt and _rt.executed:
            _nav_flows = [f for f in _rt.flows
                          if f.sink.startswith("nav:")]
            seen_nav: set[str] = set()
            for flow in _nav_flows:
                key = (flow.sink, flow.source_id)
                if key in seen_nav:
                    continue
                seen_nav.add(key)
                _ev = Evidence(
                    request_raw=raw_request(method, url, headers, None),
                    response_raw="",
                    proof=(f"Client-side open redirect CONFIRMED by real JS "
                           f"execution: tainted data from {flow.source}"
                           f"({flow.source_id}) reached {flow.sink}. "
                           f"Destination: {flow.evidence[:200]}"),
                )
                _f = Finding(
                    type="Open Redirect", subtype="js-navigation-tainted",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    confidence=0.9, url=url, method=method,
                    param=flow.source_id, evidence=_ev, cwe="CWE-601",
                    owasp="A01:2021 – Broken Access Control",
                    remediation=REMEDIATION_REDIRECT,
                    references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
                )
                _f.set_confidence("CONFIRMED")
                _f.source = f"{flow.source}({flow.source_id})"
                _f.sink = flow.sink
                findings.append(_f)
    except Exception:
        pass  # runtime layer is assist-only; never break the core detector

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

    # soft-404 baseline: fetch a definitely-missing path to learn the 404 signature
    soft404_len, soft404_body = 0, ""
    try:
        r404 = await client.get(f"{root}/sx-definitely-missing-987654321", headers=headers)
        if r404:
            soft404_len, soft404_body = len(r404.content), r404.text[:500]
    except Exception:
        pass

    sem = asyncio.Semaphore(20)

    async def probe(path: str):
        async with sem:
            full = root + "/" + path.lstrip("/")
            resp = await client.get(full, headers=headers)
            if not resp:
                return
            # interesting: 200 with non-trivial body, or revealing status
            if resp.status_code == 200 and len(resp.content) > 100:
                # soft-404 filter: skip if body matches the 404 baseline
                # (signal 1: status 200, signal 2: content differs from 404 page)
                if soft404_len and abs(len(resp.content) - soft404_len) < 200:
                    return
                if soft404_body and soft404_body in resp.text[:500]:
                    return
                ev = Evidence(
                    request_raw=raw_request("GET", full, headers, None),
                    response_raw=raw_response(resp.status_code, dict(resp.headers),
                                              resp.content[:2000]),
                    proof=f"HTTP 200, {len(resp.content)} bytes at /{path} (differs from 404 baseline)",
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
