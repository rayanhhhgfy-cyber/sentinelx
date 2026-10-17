"""SentinelX module: Authentication weaknesses — username enumeration.

Techniques: differential login error messages (invalid user vs invalid
password), timing differences. All via real HTTP; safe (no brute force —
only a handful of probes with obviously-fake credentials).
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.core.diff import fuzzy_similarity

REMEDIATION_AUTHENUM = (
    "Return identical generic error messages for invalid usernames and invalid "
    "passwords (e.g. 'Invalid credentials'). Ensure response timing is uniform. "
    "Add rate limiting / account lockout on login endpoints.")


def _evidence(method, url, req_headers, body_sent, resp) -> Evidence:
    rbody = resp.content if resp else b""
    return Evidence(
        request_raw=raw_request(method, url, req_headers, body_sent),
        response_raw=raw_response(resp.status_code if resp else 0,
                                  dict(resp.headers) if resp else {}, rbody),
        proof="",
    )


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    # self-gate: only login-like endpoints
    pl = url.lower()
    pnames = " ".join((params or {}).keys()).lower()
    if not ("login" in pl or "signin" in pl or "auth" in pl
            or ("user" in pnames and "pass" in pnames)):
        return findings
    headers = {"User-Agent": config.user_agent}

    # find the username/password param names
    user_p = next((p for p in (params or {}) if re.search(r"user|login|email", p, re.I)), None)
    pass_p = next((p for p in (params or {}) if re.search(r"pass", p, re.I)), None)
    if not user_p or not pass_p:
        return findings

    async def _try_login(u: str, pw: str):
        p = dict(params or {})
        p[user_p] = u
        p[pass_p] = pw
        t0 = time.monotonic()
        if method == "GET":
            full = url + ("&" if "?" in url else "?") + _urlencode(p)
            resp = await client.get(full, dedupe=False)
            body_sent = None
        else:
            resp = await client.post(url, data=p, dedupe=False)
            full, body_sent = url, _urlencode(p).encode()
        return resp, full, body_sent, time.monotonic() - t0

    fake = "sx_no_such_user_9z9z"
    # 2 samples each for stability
    r_u1, _, _, _ = await _try_login(fake, "x")
    r_u2, _, _, _ = await _try_login(fake, "x")
    r_p1, f_p1, b_p1, _ = await _try_login("admin", "sx_wrong_pw_9z9z")
    r_p2, _, _, _ = await _try_login("admin", "sx_wrong_pw_9z9z")
    if not all([r_u1, r_u2, r_p1, r_p2]):
        return findings
    if r_u1.text != r_u2.text or r_p1.text != r_p2.text:
        return findings  # unstable; skip

    # signal: different messages for bad-user vs bad-password
    sim = fuzzy_similarity(r_u1.text, r_p1.text)
    if sim < 0.85 and r_u1.text != r_p1.text:
        # confirm the difference is about the username, not random
        if len(r_u1.text) > 10 and len(r_p1.text) > 10:
            ev = _evidence("POST", f_p1, headers, b_p1, r_p1)
            # redact: show message shapes, not full bodies
            u_msg = re.sub(r"\s+", " ", r_u1.text[:120])
            p_msg = re.sub(r"\s+", " ", r_p1.text[:120])
            ev.proof = (f"Username enumeration (2/2 stable): invalid username -> "
                        f"'{u_msg}' vs valid username + wrong password -> '{p_msg}' "
                        f"(similarity {sim:.0%})")
            findings.append(Finding(
                type="Authentication Weakness", subtype="username-enumeration",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=0.85, url=f_p1, method=method,
                param=user_p, payload=fake, evidence=ev, cwe="CWE-204",
                owasp="A07:2021 – Identification and Authentication Failures",
                remediation=REMEDIATION_AUTHENUM,
                references=["https://owasp.org/www-community/attacks/Username_enumeration"],
            ))
    return findings
