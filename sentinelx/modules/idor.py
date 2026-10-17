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

# Public catalog params: enumerating these is NORMAL browsing, not IDOR.
# /product?productId=2 showing product 2 is just a catalog — flagging it
# as HIGH IDOR is a false positive. These are only tested when the endpoint
# requires auth or returns user-private data.
PUBLIC_CATALOG_PARAM_RE = re.compile(
    r"^(product|item|article|post|page|category|blog|news|image|img|"
    r"video|file|doc|document|listing)s?[-_]?ids?$", re.I)

# Markers of user-private data: if the response contains these, the endpoint
# returns user-specific data and ID enumeration is a real test.
# NOTE: bare "username"/"phone" are NOT markers — every login form has them.
# Only count them when paired with an actual value (e.g. "Username: carlos").
PRIVATE_DATA_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"  # email address
    r"|my account|my profile|my orders|order history|log\s?out|sign\s?out"
    r"|username\s*:\s*\S|phone\s*:\s*\S|date of birth|\bssn\b|credit card|my address",
    re.I)

# Path segments that indicate a public catalog (for path-based enumeration)
PUBLIC_CATALOG_PATH_RE = re.compile(
    r"/(products?|items?|articles?|posts?|pages?|categories|blog|news|"
    r"images?|videos?|files?|docs?|listings?)/\d+", re.I)


def _extract_emails(body: str) -> set[str]:
    return set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body))


def _is_public_catalog(param: str, baseline_body: str, config) -> bool:
    """True if this looks like public catalog browsing, not an IDOR vector."""
    if not PUBLIC_CATALOG_PARAM_RE.match(param or ""):
        return False
    if config.auth_a or config.auth_b:
        return False  # auth in play -> authorization matters -> test it
    if PRIVATE_DATA_RE.search(baseline_body):
        return False  # user-private data in response -> test it
    return True

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
    """±1, ±10, 0, -1, encoding and boundary variants of a numeric id."""
    try:
        n = int(original)
    except (ValueError, TypeError):
        return []
    variants = {str(n + 1), str(n - 1), str(n + 10), str(n - 10), "0", "-1",
                str(n + 2), str(n - 2), "1", "2"}
    variants.discard(original)
    out = sorted(variants, key=lambda v: abs(int(v) - n))
    # --- TECHNIQUE: encoded numeric forms ---
    out += [f"{n:05d}", f"+{n}", f"{n}.0", f"0x{n:x}"]
    # --- TECHNIQUE: boundary values ---
    out += ["2147483647", "999999999", "1000000"]
    # --- TECHNIQUE: negative / zero edge ---
    out += ["-0", "00", "01"]
    return out


def _string_id_variants(original: str) -> list[str]:
    """Techniques for opaque string IDs: case, truncation, suffix games."""
    o = original.strip()
    variants = []
    # --- TECHNIQUE: case flip ---
    variants.append(o.swapcase())
    variants.append(o.lower())
    variants.append(o.upper())
    # --- TECHNIQUE: truncation / extension ---
    if len(o) > 2:
        variants.append(o[:-1])
        variants.append(o + "1")
        variants.append(o + "0")
    # --- TECHNIQUE: common suffixes ---
    for suffix in ("-test", "_test", "-dev", "1", "2", "-backup"):
        variants.append(o + suffix)
    # --- TECHNIQUE: URL-encoding ---
    import urllib.parse as _up
    variants.append(_up.quote(o, safe=""))
    variants.append(_up.quote(_up.quote(o, safe=""), safe=""))
    # --- TECHNIQUE: null byte / truncation ---
    variants.append(o + "%00")
    # --- TECHNIQUE: whitespace ---
    variants.append(o + " ")
    variants.append(" " + o)
    return [v for v in variants if v != original]


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
            variants = _string_id_variants(params[param])
            variant_kind = "string-id-enumeration"
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

        # FALSE-POSITIVE GUARD: public catalog browsing (e.g. /product?productId=2
        # on an unauthenticated shop) is not IDOR. Skip unless the endpoint needs
        # auth or returns user-private data.
        if _is_public_catalog(param, base_body, config):
            continue
        base_emails = _extract_emails(base_body)
        base_has_private = bool(PRIVATE_DATA_RE.search(base_body))

        for variant in variants:
            resp, full, body_sent, req_h = await _send(
                client, method, url, params, param, variant)
            if not resp or resp.status_code != 200:
                continue
            sim = fuzzy_similarity(base_body, resp.text)
            reflected = variant in resp.text
            # >30% different content AND mutated id reflected => other object
            if sim < 0.7 and reflected:
                # REAL-IDOR CONFIRMATION: is this another USER's private data,
                # or just different public content? Compare user identifiers.
                var_emails = _extract_emails(resp.text)
                var_has_private = bool(PRIVATE_DATA_RE.search(resp.text))
                cross_user = bool(base_emails and var_emails and
                                  base_emails.isdisjoint(var_emails))
                # Skip: public content with no private data on either side and
                # no auth in play -> just different catalog items, not IDOR.
                if (not base_has_private and not var_has_private
                        and not cross_user
                        and not (config.auth_a or config.auth_b)):
                    continue
                confidence = 0.90 if (cross_user or base_has_private) else 0.75
                proof_extra = ""
                if cross_user:
                    proof_extra = (f" Cross-user confirmed: baseline exposed "
                                   f"{sorted(base_emails)[:2]}, variant exposed "
                                   f"{sorted(var_emails)[:2]}.")
                ev = _evidence(method, full, {**headers, **req_h}, body_sent, resp)
                ev.proof = (f"Object id {variant} returned HTTP 200 with {1 - sim:.0%} "
                            f"content difference vs id {params[param]}; mutated id reflected."
                            f"{proof_extra}")
                findings.append(Finding(
                    type="Insecure Direct Object Reference", subtype=variant_kind,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                    confidence=confidence, url=full, method=method, param=param,
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
                # FALSE-POSITIVE GUARD: /products/2 is catalog browsing, not IDOR.
                if (PUBLIC_CATALOG_PATH_RE.search(u.path)
                        and not (config.auth_a or config.auth_b)
                        and not PRIVATE_DATA_RE.search(base_body)):
                    pass  # public catalog path; skip enumeration
                else:
                    base_emails = _extract_emails(base_body)
                    base_has_private = bool(PRIVATE_DATA_RE.search(base_body))
                    for delta in (1, -1):
                        variant = str(n + delta)
                        new_path = u.path[:m.start(1)] + variant + m.group(2)
                        new_url = urlunsplit((u.scheme, u.netloc, new_path, u.query, u.fragment))
                        resp, full, body_sent, req_h = await _send_path(client, new_url)
                        if not resp or resp.status_code != 200:
                            continue
                        sim = fuzzy_similarity(base_body, resp.text)
                        if sim < 0.7 and variant in resp.text:
                            var_emails = _extract_emails(resp.text)
                            var_has_private = bool(PRIVATE_DATA_RE.search(resp.text))
                            cross_user = bool(base_emails and var_emails and
                                              base_emails.isdisjoint(var_emails))
                            if (not base_has_private and not var_has_private
                                    and not cross_user
                                    and not (config.auth_a or config.auth_b)):
                                continue
                            confidence = 0.90 if (cross_user or base_has_private) else 0.75
                            ev = _evidence("GET", full, headers, body_sent, resp)
                            ev.proof = (f"Path id {variant} returned HTTP 200 with "
                                        f"{1 - sim:.0%} content difference vs id {orig_id}")
                            findings.append(Finding(
                                type="Insecure Direct Object Reference",
                                subtype="path-id-enumeration",
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                                confidence=confidence, url=full, method="GET", param="path-id",
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


# Path-based ID enumeration (e.g. /api/clients/1 -> /api/clients/2) works
# without query params.
scan_endpoint.NEEDS_PARAMS = False
