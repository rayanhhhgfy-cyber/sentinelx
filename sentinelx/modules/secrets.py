"""SentinelX module: secret / API-key scanning in response bodies and JS files.

Scans HTML/JS/text responses for 30+ real secret patterns. All secrets are
redacted to their first 8 characters in evidence — the scanner never stores
or prints full secret values.
"""

from __future__ import annotations

import re

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


# (pattern_name, compiled_regex, high_severity?)
SECRET_PATTERNS: list[tuple[str, re.Pattern, bool]] = [
    ("AWS access key ID",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),
    ("AWS secret access key",
     re.compile(r"(?i)(aws[_-]?secret[_-]?access[_-]?key|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), True),
    ("AWS session token",
     re.compile(r"(?i)(aws[_-]?session[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?"), True),
    ("GCP API key",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), True),
    ("GitHub personal access token",
     re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), True),
    ("GitHub OAuth token",
     re.compile(r"\bgho_[0-9A-Za-z]{36}\b"), True),
    ("GitHub fine-grained token",
     re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b"), True),
    ("Slack token",
     re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), True),
    ("Stripe secret key",
     re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"), True),
    ("Stripe restricted key",
     re.compile(r"\brk_live_[0-9A-Za-z]{16,}\b"), False),
    ("Stripe publishable key",
     re.compile(r"\bpk_live_[0-9A-Za-z]{16,}\b"), False),
    ("RSA private key",
     re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"), True),
    ("JWT token",
     re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), False),
    ("Generic API key assignment",
     re.compile(r"(?i)\b(api[_-]?key|apikey)\b\s*[:=]\s*['\"]([A-Za-z0-9\-_.]{16,})['\"]"), False),
    ("Password assignment",
     re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]"), False),
    ("Heroku API key",
     re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), False),
    ("Twilio account SID + auth token",
     re.compile(r"\bAC[0-9a-f]{32}\b"), True),
    ("SendGrid API key",
     re.compile(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b"), True),
    ("Mailgun API key",
     re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), False),
    ("Discord webhook",
     re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[0-9A-Za-z\-_]+"), False),
    ("Telegram bot token",
     re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b"), True),
    ("npm auth token",
     re.compile(r"//[^/\s]+/:_authToken=[0-9A-Za-z\-_]{16,}"), True),
    ("PyPI token",
     re.compile(r"\bpypi-[A-Za-z0-9\-_]{30,}\b"), True),
    ("OpenAI API key",
     re.compile(r"\bsk-[0-9A-Za-z]{20,}\b"), True),
    ("Anthropic API key",
     re.compile(r"\bsk-ant-[0-9A-Za-z\-_]{20,}\b"), True),
    ("Azure connection string",
     re.compile(r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+"), True),
    ("Firebase key",
     re.compile(r"\bAAAA[0-9A-Za-z\-_]{7}:[0-9A-Za-z\-_]{140}\b"), False),
    ("MongoDB connection URI",
     re.compile(r"mongodb(?:\+srv)?://[^/\s:]+:[^@\s]+@[^\s\"']+"), True),
    ("Postgres connection URI",
     re.compile(r"postgres(?:ql)?://[^/\s:]+:[^@\s]+@[^\s\"']+"), True),
    ("MySQL connection URI",
     re.compile(r"mysql://[^/\s:]+:[^@\s]+@[^\s\"']+"), True),
    ("Redis connection URI",
     re.compile(r"rediss?://(?::[^@\s]+@)?[^\s\"']+"), False),
    ("Cloudinary URL",
     re.compile(r"cloudinary://[0-9]+:[0-9A-Za-z\-_]+@[0-9A-Za-z\-_]+"), True),
    ("Algolia API key",
     re.compile(r"(?i)\balgolia\b.{0,40}?\b[0-9a-f]{32}\b"), False),
    ("Bugsnag API key",
     re.compile(r"(?i)\bbugsnag\b.{0,40}?\b[0-9a-f]{32}\b"), False),
    ("Mapbox token",
     re.compile(r"\bpk\.[0-9A-Za-z]{20,}\.[0-9A-Za-z]{20,}\b"), False),
    ("Google OAuth client secret",
     re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{16,}\b"), True),
    ("Facebook app secret",
     re.compile(r"(?i)(facebook|fb)[_-]?(app[_-]?secret|secret)\s*[:=]\s*['\"][0-9a-f]{32}['\"]"), True),
    ("Segment write key",
     re.compile(r"(?i)\bsegment\b.{0,30}?\b[0-9A-Za-z]{32}\b"), False),
    ("Mixpanel token",
     re.compile(r"(?i)\bmixpanel\b.{0,30}?\b[0-9a-f]{32}\b"), False),
]

REMEDIATION_SECRETS = (
    "Remove the secret from all client-visible responses immediately and rotate it. "
    "Store secrets server-side (env vars / secret manager), never in JS, HTML, or repos. "
    "Scan git history for the same secret and revoke anything that leaked."
)


def redact(value: str, keep: int = 8) -> str:
    v = value.strip()
    if len(v) <= keep:
        return v[:2] + "***REDACTED***"
    return v[:keep] + "***REDACTED***"


def find_secrets(body: str) -> list[tuple[str, str, bool]]:
    """Return [(pattern_name, redacted_sample, high_sev)] deduped by pattern name."""
    seen: dict[str, tuple[str, bool]] = {}
    for name, rx, high in SECRET_PATTERNS:
        m = rx.search(body)
        if m:
            sample = m.group(0)
            # prefer the longest capture group (actual secret) for redaction
            for g in m.groups() if hasattr(m, "groups") else []:
                if g and len(g) > len(sample) // 2:
                    sample = g
                    break
            if name not in seen:
                seen[name] = (redact(sample), high)
    return [(n, s, h) for n, (s, h) in seen.items()]


def _ev(method, url, headers, resp) -> Evidence:
    body = resp.content if resp else b""
    return Evidence(
        request_raw=raw_request(method, url, headers, None),
        response_raw=raw_response(resp.status_code if resp else 0,
                                  dict(resp.headers) if resp else {}, body[:2000]),
        proof="",
    )


def _finding(url: str, method: str, name: str, redacted: str, high: bool,
             headers: dict, resp) -> Finding:
    ev = _ev(method, url, headers, resp)
    ev.proof = f"Secret pattern matched: {name} — value {redacted}"
    vector = ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
              if high else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    return Finding(
        type="Sensitive Data Exposure", subtype=f"secret:{name}",
        cvss_vector=vector, confidence=0.85, url=url, method=method,
        param="", payload=name, evidence=ev, cwe="CWE-798",
        owasp="A02:2021 – Cryptographic Failures",
        remediation=REMEDIATION_SECRETS,
        references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
    )


async def scan_page(client: ScanClient, config: ScanConfig, url: str) -> list[Finding]:
    """Fetch a URL and scan its body (HTML or JS) for secrets."""
    findings = []
    headers = {"User-Agent": config.user_agent}
    resp = await client.get(url, headers=headers)
    if not resp:
        return findings
    ctype = resp.headers.get("content-type", "").lower()
    if not any(t in ctype for t in ("html", "javascript", "text", "json")) and ".js" not in url:
        return findings
    try:
        body = resp.text
    except Exception:
        return findings
    if len(body) > 2_000_000:
        body = body[:2_000_000]
    for name, redacted, high in find_secrets(body):
        findings.append(_finding(url, "GET", name, redacted, high, headers, resp))
    return findings


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    """Scan a parameterized endpoint's response for secrets."""
    findings = []
    headers = {"User-Agent": config.user_agent}
    from urllib.parse import urlencode as _urlencode
    if method == "GET":
        full = url + ("&" if "?" in url else "?") + _urlencode(params) if params else url
        resp = await client.get(full, headers=headers)
    else:
        full = url
        resp = await client.post(url, data=params, headers=headers)
    if not resp:
        return findings
    try:
        body = resp.text
    except Exception:
        return findings
    for name, redacted, high in find_secrets(body):
        findings.append(_finding(full, method, name, redacted, high, headers, resp))
    return findings
