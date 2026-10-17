"""SentinelX module [12]: Insecure Direct Object Reference (IDOR).

Techniques: numeric enumeration (original±1, ±10, 0, -1) on
id-like params, path-based ID enumeration, cross-session replay
when --auth-a/--auth-b supplied. All via real HTTP; detection uses
fuzzy content similarity + reflection of the mutated id.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode as _urlencode, urlsplit, urlunsplit

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.core.diff import fuzzy_similarity

# param names that typically reference a direct object
ID_PARAM_RE = re.compile(r"id|user|account|order|object|profile|customer|invoice|doc", re.I)

REMEDIATION_IDOR = (
    "Enforce server-side authorization on every object access: verify the "
    "authenticated user owns (or may access) the requested object id. Never "
    "trust client-supplied identifiers. Use indirect, unpredictable references "
    "(e.g. random UUIDs) where feasible, and return 403/404 for unauthorized ids."
)


async def _send(client: ScanClient, method: str, url: str, params: dict,
                param: str, value: str, extra_headers: dict | None = None):
    """Send request with one param replaced by value."""
    p = dict(params); p[param] = value
    headers = dict(extra_headers or {})
    if method == "GET":
        qs = _urlencode(p)
        full = url + ("&" if "?" in url else "?") + qs
        resp = await client.get(full, headers=headers or None)
        body = None
    else:
        resp = await client.post(url, data=p, headers=headers or None)
        full, body = url, _urlencode(p).encode()
    return resp, full, body, headers


async def _send_path(client: ScanClient, url: str, headers: dict | None = None):
    """GET a fully-formed URL (used for path-based id tests)."""
    resp = await client.get(url, headers=headers or None)
    return resp, url, None, dict(headers or {})


def _evidence(method, url, req_headers, body_sent, resp) -> Evidence:
    rbody = resp.content if resp else b""
    return Evidence(
        request_raw=raw_request(method, url, req_headers, body_sent),
        response_raw=raw_response(resp.status_code if resp else 0,
                                  dict(resp.headers) if resp else {}, rbody),
        proof="",
    )


def _numeric_variants(original: str) -> list[str]:
    """±1, ±10, 0, -1 variants of a numeric id."""
    try:
        n = int(original)
    except (ValueError, TypeError):
        return []
    variants = {str(n + 1), str(n - 1), str(n + 10), str(n - 10), "0", "-1"}
    variants.discard(original)
    return sorted(variants, key=lambda v: abs(int(v) - n))


def _uuid_variants(original: str) -> list[str]:
    """UUID-adjacent enumeration: flip last hex digit, try nil UUID."""
    import re as _re
    if not _re.match(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", original):
        return []
    last = original[-1]
    flipped = "0" if last.lower() != "0" else "1"
    variants = [original[:-1] + flipped,
                "00000000-0000-0000-0000-000000000000"]
    return [v for v in variants if v != original]


def _timestamp_variants(original: str) -> list[str]:
    """Timestamp-based IDs: ±1s, ±1h, ±1d for epoch-ish values."""
    try:
        n = int(original)
    except (ValueError, TypeError):
        return []
    # heuristic: 10-digit (seconds) or 13-digit (ms) epoch
    if not (9 <= len(original) <= 13):
        return []
    if len(original) == 13:
        deltas = [1000, -1000, 3600000, -3600000]
    else:
        deltas = [1, -1, 3600, -3600, 86400, -86400]
    return [str(n + d) for d in deltas]


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    headers = {"User-Agent": config.user_agent}

    # ---------- 1. param-based numeric enumeration ----------
    id_params = [p for p in (params or {}) if ID_PARAM_RE.search(p)]
    for param in id_params:
        variants = _numeric_variants(params[param])
        variant_kind = "numeric-enumeration"
        if not variants:
            # try UUID-adjacent, then timestamp-based IDs
            variants = _uuid_variants(params[param])
            variant_kind = "uuid-enumeration"
        if not variants:
            variants = _timestamp_variants(params[param])
            variant_kind = "timestamp-enumeration"
        if not variants:
            continue
        # baseline: 2 samples, must be stable and 200
        base_bodies = []
        for _ in range(2):
            resp, full, body_sent, _ = await _send(
                client, method, url, params, param, params[param])
            if not resp or resp.status_code != 200:
                base_bodies = []
                break
            base_bodies.append(resp.text)
        if len(base_bodies) != 2 or base_bodies[0] != base_bodies[1]:
            continue  # unstable or inaccessible baseline; skip
        base_body = base_bodies[0]

        for variant in variants:
            resp, full, body_sent, req_h = await _send(
                client, method, url, params, param, variant)
            if not resp or resp.status_code != 200:
                continue
            sim = fuzzy_similarity(base_body, resp.text)
            reflected = variant in resp.text
            # >30% different content AND mutated id reflected => other object
            if sim < 0.7 and reflected:
                ev = _evidence(method, full, {**headers, **req_h}, body_sent, resp)
                ev.proof = (f"Object id {variant} returned HTTP 200 with {1 - sim:.0%} "
                            f"content difference vs id {params[param]}; mutated id reflected")
                findings.append(Finding(
                    type="Insecure Direct Object Reference", subtype=variant_kind,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                    confidence=0.85, url=full, method=method, param=param,
                    payload=variant, evidence=ev, cwe="CWE-639",
                    owasp="A01:2021 – Broken Access Control",
                    remediation=REMEDIATION_IDOR,
                    references=["https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"],
                ))
                break  # one finding per param is enough

    # ---------- 2. path-based id enumeration (/users/123) ----------
    u = urlsplit(url)
    m = re.search(r"/(\d+)(/?)$", u.path)
    if m:
        orig_id = m.group(1)
        try:
            n = int(orig_id)
        except ValueError:
            n = None
        if n is not None:
            # baseline the original path
            base_bodies = []
            for _ in range(2):
                resp, full, body_sent, _ = await _send_path(client, url)
                if not resp or resp.status_code != 200:
                    base_bodies = []
                    break
                base_bodies.append(resp.text)
            if len(base_bodies) == 2 and base_bodies[0] == base_bodies[1]:
                base_body = base_bodies[0]
                for delta in (1, -1):
                    variant = str(n + delta)
                    new_path = u.path[:m.start(1)] + variant + m.group(2)
                    new_url = urlunsplit((u.scheme, u.netloc, new_path, u.query, u.fragment))
                    resp, full, body_sent, req_h = await _send_path(client, new_url)
                    if not resp or resp.status_code != 200:
                        continue
                    sim = fuzzy_similarity(base_body, resp.text)
                    if sim < 0.7 and variant in resp.text:
                        ev = _evidence("GET", full, headers, body_sent, resp)
                        ev.proof = (f"Path id {variant} returned HTTP 200 with "
                                    f"{1 - sim:.0%} content difference vs id {orig_id}")
                        findings.append(Finding(
                            type="Insecure Direct Object Reference",
                            subtype="path-id-enumeration",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                            confidence=0.85, url=full, method="GET", param="path-id",
                            payload=variant, evidence=ev, cwe="CWE-639",
                            owasp="A01:2021 – Broken Access Control",
                            remediation=REMEDIATION_IDOR,
                            references=["https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"],
                        ))
                        break

    # ---------- 3. cross-session replay (auth_a vs auth_b) ----------
    if config.auth_a and config.auth_b:
        # replay the IDENTICAL request with user B's token
        a_headers = {**headers, "Authorization": f"Bearer {config.auth_a}"}
        b_headers = {**headers, "Authorization": f"Bearer {config.auth_b}"}
        p = dict(params or {})
        if method == "GET":
            full_id = url + ("&" if "?" in url else "?") + _urlencode(p) if p else url
            resp_a = await client.get(full_id, headers=a_headers)
            resp_b = await client.get(full_id, headers=b_headers)
            body_sent = None
        else:
            resp_a = await client.post(url, data=p, headers=a_headers)
            resp_b = await client.post(url, data=p, headers=b_headers)
            full_id, body_sent = url, _urlencode(p).encode()

        if resp_a and resp_b and resp_a.status_code == 200 and resp_b.status_code == 200:
            sim = fuzzy_similarity(resp_a.text, resp_b.text)
            if sim > 0.8:
                ev = Evidence(
                    request_raw=raw_request(method, full_id, b_headers, body_sent),
                    response_raw=raw_response(resp_b.status_code, dict(resp_b.headers), resp_b.content),
                    proof=(f"User B's token received HTTP 200 with {sim:.0%} content "
                           f"similarity to user A's private object response"),
                )
                findings.append(Finding(
                    type="Insecure Direct Object Reference",
                    subtype="cross-session-replay",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    confidence=0.9, url=full_id, method=method,
                    param="Authorization", payload="[REDACTED bearer token B]",
                    evidence=ev, cwe="CWE-639",
                    owasp="A01:2021 – Broken Access Control",
                    remediation=REMEDIATION_IDOR,
                    references=["https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"],
                ))

    return findings
