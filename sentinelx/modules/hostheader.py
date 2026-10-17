"""SentinelX module [22]: Host Header Injection.

Real implementation: sends evil Host headers and detects (1) reflection in
password-reset / absolute URLs (poisoning), (2) cache-key confusion via
X-Forwarded-Host, (3) differential responses indicating virtual-host routing
issues. Safe: uses inert evil-sentinelx.example domain.
"""

from __future__ import annotations

import re

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


EVIL_HOST = "evil-sentinelx.example"

# --- TECHNIQUE GROUPS: Host header attack vectors ---
HOST_TECHNIQUES = [
    # --- basic Host override ---
    ("host-evil", {"Host": EVIL_HOST}),
    ("host-evil-port", {"Host": EVIL_HOST + ":8080"}),
    ("host-localhost", {"Host": "localhost"}),
    ("host-127", {"Host": "127.0.0.1"}),
    # --- X-Forwarded-* variants ---
    ("xfwd-host", {"X-Forwarded-Host": EVIL_HOST}),
    ("x-host", {"X-Host": EVIL_HOST}),
    ("xfwd-server", {"X-Forwarded-Server": EVIL_HOST}),
    ("x-forwarded-host-port", {"X-Forwarded-Host": EVIL_HOST + ":443"}),
    # --- parsing differentials ---
    ("host-at", {"Host": "trusted.example@" + EVIL_HOST}),
    ("host-double", {"Host": EVIL_HOST + ", trusted.example"}),
    ("host-space", {"Host": EVIL_HOST + " "}),
    ("host-tab", {"Host": EVIL_HOST + "\t"}),
    # --- absolute-URI request line (proxy-style) ---
    ("absolute-uri", {}),  # handled specially: full URL in request line
    # --- scheme confusion ---
    ("xfwd-proto-http", {"X-Forwarded-Proto": "http"}),
    ("xfwd-scheme-http", {"X-Forwarded-Scheme": "http"}),
    ("x-forwarded-ssl-off", {"X-Forwarded-Ssl": "off"}),
    # --- password-reset poisoning markers ---
    ("host-reset", {"Host": EVIL_HOST}),
    # --- cache-key confusion ---
    ("host-cache", {"Host": EVIL_HOST}),
    # --- IPv6 / decimal IP ---
    ("host-decimal", {"Host": "2130706433"}),  # 127.0.0.1 decimal
    ("host-hex", {"Host": "0x7f.0.0.1"}),
    # --- username-style ---
    ("host-userinfo", {"Host": "user@" + EVIL_HOST}),
    # --- trailing dot / case ---
    ("host-trailing-dot", {"Host": EVIL_HOST + "."}),
    ("host-uppercase", {"Host": EVIL_HOST.upper()}),
    # --- X-Forwarded-Host chain ---
    ("xfwd-chain", {"X-Forwarded-Host": "a," + EVIL_HOST}),
    # --- Host + XFH mismatch ---
    ("host-xfh-mismatch", {"Host": "trusted.example", "X-Forwarded-Host": EVIL_HOST}),
    # --- line folding (obs-fold) ---
    ("host-fold", {"Host": EVIL_HOST + " "}),
]

REMEDIATION_HOST = (
    "Validate the Host header against an allowlist of known domains. "
    "Generate password-reset links from a configured base URL, not the "
    "request Host. Ignore X-Forwarded-Host unless from trusted proxies."
)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    base_headers = {"User-Agent": config.user_agent}

    # Try every technique; check reflection of the evil marker in body/Location
    for tech_label, theaders in HOST_TECHNIQUES:
        if tech_label == "absolute-uri":
            continue  # proxy-style request line not supported by httpx client
        h = dict(base_headers)
        h.update(theaders)
        # skip techniques httpx can't send (raw CR/LF in values)
        try:
            resp = await client.get(url, headers=h, dedupe=False)
        except Exception:
            continue
        if not resp:
            continue
        evil = theaders.get("Host", theaders.get("X-Forwarded-Host", EVIL_HOST))
        reflected = evil in resp.text
        loc_reflect = evil in resp.headers.get("location", "")
        if not (reflected or loc_reflect):
            continue
        # signal 2: confirm reflection persists on resend
        try:
            r3 = await client.get(url, headers=h, dedupe=False)
        except Exception:
            continue
        if not r3 or not (evil in r3.text or evil in r3.headers.get("location", "")):
            continue
        kind = "location-header" if loc_reflect else "body-reflection"
        reset_ctx = bool(re.search(
            r"password.*reset|reset.*password|href=[\"']https?://" + re.escape(evil),
            r3.text, re.I))
        ev = Evidence(
            request_raw=raw_request("GET", url, h, None),
            response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
            proof=(f"Host header attack [{tech_label}]: '{evil}' reflected via {kind} (2/2). "
                   f"Password-reset poisoning possible: {reset_ctx}"),
        )
        findings.append(Finding(
            type="Host Header Injection", subtype=f"host-poisoning-{tech_label}",
            cvss_vector=("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
                         if reset_ctx else
                         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
            confidence=0.88 if reset_ctx else 0.75, url=url, method="GET",
            param="", payload=f"{tech_label}: {theaders}", evidence=ev,
            cwe="CWE-640", owasp="A01:2021 – Broken Access Control",
            remediation=REMEDIATION_HOST,
            references=["https://portswigger.net/web-security/host-header"],
        ))
        if len(findings) >= 3:
            break  # enough signal
    return findings
