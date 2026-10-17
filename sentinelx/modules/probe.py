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
                    proof=f"HTTP 200, {len(resp.content)} bytes at /{path} (differs from 404 baseline). "
                          f"NOTE: found via wordlist guessing, not linked from the site — verify manually.",
                )
                f = Finding(
                    type="Sensitive Path Exposure", subtype=f"wordlist:path:/{path}",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    confidence=0.7, url=full, method="GET", param="",
                    payload=f"/{path}", evidence=ev, cwe="CWE-538",
                    owasp="A05:2021 – Security Misconfiguration",
                    remediation="Remove or protect sensitive paths; block /.git, /.env, backups at the edge.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                )
                # Wordlist-based: lower confidence, clearly labeled. Dynamic
                # discovery (crawl/js/robots/sitemap) always outranks guessing.
                f.set_confidence("LOW")
                findings.append(f)

    await asyncio.gather(*[probe(p) for p in ADMIN_PATHS])
    return findings


# Sensitive file patterns — checked ONLY against URLs the crawler actually
# discovered (comment mining, JS, links). This is verification, not guessing:
# dirfuzz (wordlist) is the guessing path and is disabled by default.
SENSITIVE_FILE_RES = [
    (re.compile(r"\.git/HEAD$", re.I), "Git metadata exposed", "CWE-538"),
    (re.compile(r"\.env$", re.I), "Environment file exposed", "CWE-538"),
    (re.compile(r"backup\.(zip|sql|tar\.gz|bak)$", re.I), "Backup file exposed", "CWE-538"),
    (re.compile(r"\.sql$", re.I), "SQL dump exposed", "CWE-538"),
    (re.compile(r"\.svn/entries$", re.I), "SVN metadata exposed", "CWE-538"),
    (re.compile(r"server\.key$", re.I), "Private key exposed", "CWE-798"),
    (re.compile(r"\.DS_Store$", re.I), "DS_Store exposed", "CWE-538"),
    (re.compile(r"web\.config$", re.I), "Web config exposed", "CWE-538"),
]


async def scan_sensitive_file(client: ScanClient, config: ScanConfig,
                              method: str, url: str, params: dict) -> list[Finding]:
    """Verify dynamically-discovered sensitive files (not a wordlist)."""
    findings = []
    if method.upper() != "GET":
        return findings
    path = urlsplit(url).path
    matched = None
    for rx, label, cwe in SENSITIVE_FILE_RES:
        if rx.search(path):
            matched = (label, cwe)
            break
    if not matched:
        return findings
    label, cwe = matched
    try:
        resp = await client.get(url, headers={"User-Agent": config.user_agent})
    except Exception:
        return findings
    if not resp or resp.status_code != 200 or len(resp.content) < 10:
        return findings
    # content sanity: .git/HEAD should look like a git ref
    if path.endswith("/HEAD") and b"ref:" not in resp.content[:100]:
        return findings
    ev = Evidence(
        request_raw=raw_request("GET", url, {"User-Agent": config.user_agent}, None),
        response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content[:500]),
        proof=f"{label}: {path} returned HTTP 200 ({len(resp.content)} bytes). "
              f"Discovered dynamically from site content, not guessed.",
    )
    f = Finding(
        type="Sensitive Data Exposure", subtype=f"sensitive-file:{path}",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        confidence=0.9, url=url, method="GET", param="",
        evidence=ev, cwe=cwe,
        owasp="A05:2021 – Security Misconfiguration",
        remediation="Remove sensitive files from the web root; block them at the edge.",
        references=["https://owasp.org/www-project-web-security-testing-guide/"],
    )
    f.set_confidence("HIGH")
    findings.append(f)
    return findings


# Page-content module: verifies discovered files, needs no params.
scan_sensitive_file.NEEDS_PARAMS = False


# ---------------------------------------------------------------------------
# Exposed sensitive API: dynamically-discovered API endpoints whose path
# suggests internal use AND whose response contains sensitive data.
# Two signals required (path keyword + sensitive keys) to avoid FPs.
# ---------------------------------------------------------------------------
SENSITIVE_API_PATH_RES = [
    re.compile(r"/(internal|admin|private|debug|metrics|config|backup)(/|$)", re.I),
]
SENSITIVE_DATA_KEYS = [
    "password", "passwd", "secret", "api_key", "apikey", "db_host",
    "db_password", "revenue", "salary", "ssn", "credit_card", "internal_notes",
    "private_key", "auth_token",
]


async def scan_exposed_api(client: ScanClient, config: ScanConfig,
                           method: str, url: str, params: dict) -> list[Finding]:
    findings = []
    if method.upper() != "GET" or "/api/" not in url:
        return findings
    path = urlsplit(url).path
    if not any(rx.search(path) for rx in SENSITIVE_API_PATH_RES):
        return findings
    try:
        resp = await client.get(url, headers={"User-Agent": config.user_agent})
    except Exception:
        return findings
    if not resp or resp.status_code != 200:
        return findings
    ctype = resp.headers.get("content-type", "")
    if "json" not in ctype:
        return findings
    try:
        import json as _json
        data = _json.loads(resp.text)
    except Exception:
        return findings
    if not isinstance(data, dict):
        return findings
    hit_keys = [k for k in data.keys()
                if any(s in k.lower() for s in SENSITIVE_DATA_KEYS)]
    if not hit_keys:
        return findings
    ev = Evidence(
        request_raw=raw_request("GET", url, {"User-Agent": config.user_agent}, None),
        response_raw=raw_response(resp.status_code, dict(resp.headers),
                                  resp.content[:1000]),
        proof=f"Unauthenticated internal API exposes sensitive fields: "
              f"{', '.join(hit_keys)}. No Authorization required (HTTP 200).",
    )
    f = Finding(
        type="Sensitive Data Exposure", subtype="exposed-internal-api",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        confidence=0.85, url=url, method="GET", param="",
        evidence=ev, cwe="CWE-200",
        owasp="A01:2021 – Broken Access Control",
        remediation="Require authentication on internal APIs; never expose "
                    "infrastructure details (db hosts) or business data publicly.",
        references=["https://owasp.org/API-Security/editions/2023/en/0x11-t01/"],
    )
    f.set_confidence("HIGH")
    findings.append(f)
    return findings


scan_exposed_api.NEEDS_PARAMS = False
