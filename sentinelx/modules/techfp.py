"""SentinelX module: Wappalyzer-style technology fingerprinting.

Detects servers, frameworks, CMS, JS libs, CDNs and analytics from
headers + body markers. INFO findings only — reconnaissance evidence.
"""

from __future__ import annotations

import re

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


# (name, category, check) — check(headers_lower_dict, body) -> evidence snippet | None
TECH_CHECKS: list[tuple[str, str, object]] = []


def _hdr(name: str, needle: str):
    def check(h, b):
        v = h.get(name, "")
        return v if needle.lower() in v.lower() else None
    return check


def _hdr_re(name: str, pattern: str):
    rx = re.compile(pattern, re.I)
    def check(h, b):
        v = h.get(name, "")
        m = rx.search(v)
        return m.group(0) if m else None
    return check


def _body(pattern: str):
    rx = re.compile(pattern, re.I | re.S)
    def check(h, b):
        m = rx.search(b)
        return m.group(0)[:120] if m else None
    return check


def _either(*fns):
    def check(h, b):
        for fn in fns:
            r = fn(h, b)
            if r:
                return r
        return None
    return check


TECH_CHECKS = [
    ("Nginx", "Web server", _hdr_re("server", r"nginx/?[\d.]*")),
    ("Apache", "Web server", _hdr_re("server", r"apache/?[\d.]*")),
    ("Microsoft IIS", "Web server", _hdr_re("server", r"microsoft-iis/?[\d.]*")),
    ("LiteSpeed", "Web server", _hdr("server", "litespeed")),
    ("Caddy", "Web server", _hdr("server", "caddy")),
    ("PHP", "Language", _either(_hdr("x-powered-by", "php"), _body(r"\.php[\"'?]"))),
    ("Express", "Framework", _hdr("x-powered-by", "express")),
    ("ASP.NET", "Framework", _either(_hdr("x-powered-by", "asp.net"), _hdr("x-aspnet-version", ""))),
    ("Django", "Framework", _either(_body(r"csrftoken"), _hdr("server", "wsgiserver"))),
    ("Ruby on Rails", "Framework", _either(_hdr("x-powered-by", "phusion"), _body(r"_rails|rails-ujs"))),
    ("Flask", "Framework", _hdr("server", "werkzeug")),
    ("FastAPI", "Framework", _body(r"openapi|/docs|fastapi")),
    ("WordPress", "CMS", _body(r"wp-content|wp-includes|/wp-json/")),
    ("Drupal", "CMS", _body(r"drupal|sites/default/files")),
    ("Joomla", "CMS", _body(r"joomla|/media/jui/")),
    ("React", "JS library", _body(r"react-root|__NEXT_DATA__|data-reactroot|_react")),
    ("Next.js", "Framework", _either(_body(r"__NEXT_DATA__|_next/static"), _hdr("x-powered-by", "next.js"))),
    ("Vue.js", "JS library", _body(r"vue\.|data-v-[0-9a-f]{8}|__vue__")),
    ("Angular", "JS library", _body(r"ng-version|angular\.|ng-app")),
    ("jQuery", "JS library", _body(r"jquery[.-][\d.]+|jQuery\.fn")),
    ("Bootstrap", "CSS framework", _body(r"bootstrap[.-][\d.]+|bootstrap\.min\.css")),
    ("Laravel", "Framework", _body(r"laravel|csrf-token")),
    ("Cloudflare", "CDN", _either(_hdr("server", "cloudflare"), _hdr("cf-ray", ""))),
    ("Akamai", "CDN", _hdr("akamai", "")),
    ("CloudFront", "CDN", _either(_hdr("via", "cloudfront"), _hdr("x-amz-cf-id", ""))),
    ("Vercel", "PaaS", _hdr("x-vercel-id", "")),
    ("Google Analytics", "Analytics", _body(r"googletagmanager|google-analytics|gtag\(")),
    ("Sentry", "Error tracking", _body(r"sentry\.|sentry-cdn")),
    ("Stripe.js", "Payment", _body(r"js\.stripe\.com")),
]


def _ev(method, url, headers, resp) -> Evidence:
    body = resp.content if resp else b""
    return Evidence(
        request_raw=raw_request(method, url, headers, None),
        response_raw=raw_response(resp.status_code if resp else 0,
                                  dict(resp.headers) if resp else {}, body[:1500]),
        proof="",
    )


async def fingerprint(client: ScanClient, config: ScanConfig, url: str) -> list[Finding]:
    findings = []
    headers = {"User-Agent": config.user_agent}
    resp = await client.get(url, headers=headers)
    if not resp:
        return findings
    h = {k.lower(): v for k, v in resp.headers.items()}
    try:
        body = resp.text
    except Exception:
        body = ""
    if len(body) > 500_000:
        body = body[:500_000]
    for name, category, check in TECH_CHECKS:
        try:
            snippet = check(h, body)
        except Exception:
            continue
        if snippet:
            ev = _ev("GET", url, headers, resp)
            ev.proof = f"Technology detected: {name} ({category}) — matched: {snippet[:120]}"
            findings.append(Finding(
                type="Information Disclosure", subtype=f"tech:{name}",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                severity="info", confidence=0.95, url=url, method="GET",
                param="", payload=name, evidence=ev, cwe="CWE-200",
                owasp="A01:2021 – Broken Access Control",
                remediation=("Technology fingerprinting aids attackers in targeting known CVEs. "
                             "Remove or obfuscate revealing headers (Server, X-Powered-By) and "
                             "minimize client-side framework markers where feasible."),
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            ))
    return findings
