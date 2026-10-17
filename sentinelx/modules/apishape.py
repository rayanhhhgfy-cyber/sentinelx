"""SentinelX module [35]: API request-shape testing.

Tests reconstructed API calls (from jsapi deep extraction) with their FULL
request shape: custom headers, JSON body fields, query params — replayed
verbatim, then attacked field-by-field.

Pipeline (accuracy-first):
1. VALIDATE: replay the exact reconstructed call once. No HTTP response
   (connection failure) -> endpoint is dead, skip everything. This prevents
   wasting hundreds of requests on hallucinated endpoints.
2. BASELINE: the validation replay doubles as the baseline (dedup-cached).
3. TEST (prioritized: ids -> auth headers -> body fields -> custom headers):
   - JSON body fields: SQLi error payloads + XSS reflection, field by field
   - Custom headers: reflection test (2-signal), auth-bypass when Authorization present
   - Tamper: role/admin-like fields tried with escalated values
4. Every finding requires 2-signal confirmation (baseline differential +
   independent re-request). No single-signal reports.

Only string/number/bool body fields that were actually sent in the
validated replay are tested — never hallucinated fields.
"""

from __future__ import annotations

import difflib
import re
import time

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.core.diff import is_significant_change
from sentinelx.modules.sqli import detect_db_error, REMEDIATION_SQLI

# standard headers that are never "interesting" for header testing
_STANDARD_HEADERS = {
    "user-agent", "accept", "accept-language", "accept-encoding",
    "content-type", "content-length", "host", "connection",
    "cache-control", "pragma", "referer", "origin",
}

# payloads kept small: the api-shape pass is surgical, not a fuzz cannon
_SQLI_PROBES = ["'", '"', "' OR '1'='1"]
_XSS_PROBE = "<sxq\"'>"
_TAMPER_FIELDS = re.compile(r"^(role|is_admin|isadmin|admin|privilege|user_type|account_type|group)$", re.I)
_TAMPER_VALUES = {"admin": "user", "true": "false", "1": "0"}
_ID_LIKE = re.compile(r"(id|uuid|guid|key)$", re.I)


def _custom_headers(headers: dict) -> dict:
    return {k: v for k, v in (headers or {}).items()
            if k.lower() not in _STANDARD_HEADERS}


def _replay_headers(config: ScanConfig, extra: dict | None,
                    drop: set | None = None) -> dict:
    h = {"User-Agent": config.user_agent}
    for k, v in (extra or {}).items():
        if drop and k in drop:
            continue
        kl = k.lower()
        if kl in ("host", "content-length"):
            continue
        if v == "<redacted>":
            # structure known, value unknown: send a placeholder so the
            # request shape stays faithful without leaking real secrets
            h[k] = "test"
        else:
            h[k] = str(v)
    return h


def _prioritize_fields(names: list[str]) -> list[str]:
    """ids -> query-like -> rest. High-value params tested first."""
    def _rank(n: str) -> int:
        nl = n.lower()
        if _ID_LIKE.search(nl):
            return 0
        if any(w in nl for w in ("q", "query", "search", "keyword", "name", "email", "code")):
            return 1
        return 2
    return sorted(names, key=lambda n: (_rank(n), n))


def _bodies_similar(a: str, b: str) -> bool:
    if a == b:
        return True
    if not a or not b:
        return False
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio() >= 0.9


async def _replay(client: ScanClient, config: ScanConfig, method: str, url: str,
                  query: dict, headers: dict, json_body: dict | None,
                  field: str | None = None, value=None,
                  header_override: dict | None = None,
                  drop_headers: set | None = None,
                  dedupe: bool = False):
    """Replay the reconstructed call, optionally with one field/header replaced."""
    body = None
    if json_body is not None:
        body = dict(json_body)
        if field is not None:
            body[field] = value
    h = _replay_headers(config, headers, drop=drop_headers)
    if header_override:
        for k, v in header_override.items():
            h[k] = v
    t0 = time.monotonic()
    resp = await client.request(
        method.upper(), url,
        params=query or None,
        json_data=body,
        headers=h,
        dedupe=dedupe,
    )
    elapsed = time.monotonic() - t0
    return resp, elapsed, h, body


def _evidence(method, url, headers, body_dict, resp, proof: str) -> Evidence:
    body_bytes = None
    if body_dict is not None:
        import json as _json
        try:
            body_bytes = _json.dumps(body_dict).encode()
        except Exception:
            body_bytes = str(body_dict).encode()
    ev = Evidence(
        request_raw=raw_request(method, url, headers, body_bytes),
        response_raw=raw_response(resp.status_code, dict(resp.headers),
                                  resp.content[:3000]) if resp else "",
        proof=proof,
    )
    return ev


async def scan_api_shape(client: ScanClient, config: ScanConfig,
                         ep: dict) -> list[Finding]:
    """Full-shape API testing for one enriched endpoint dict."""
    findings: list[Finding] = []
    method = ep.get("method", "GET") or "GET"
    url = ep.get("url", "")
    if not url:
        return findings
    query = dict(ep.get("params") or {})
    headers = dict(ep.get("headers") or {})
    json_body = dict(ep.get("json_body") or {}) or None
    custom = _custom_headers(headers)

    # ---- 1. VALIDATE: replay the exact reconstructed call ----
    resp, _, sent_headers, sent_body = await _replay(
        client, config, method, url, query, headers, json_body, dedupe=True)
    if resp is None:
        # dead endpoint (connection failure): skip, don't waste requests
        return findings
    base_status, base_text = resp.status_code, resp.text
    base_has_db_error = bool(detect_db_error(base_text))

    # ---- 2. JSON body field tests (only fields actually sent) ----
    if json_body:
        for fname in _prioritize_fields(list(json_body.keys()))[:10]:
            fval = json_body[fname]
            if not isinstance(fval, str):
                continue  # only string fields for injection probes
            # --- SQLi error-based: signal1 = DB error, signal2 = absent in baseline + re-confirm
            sqli_hit = False
            for payload in _SQLI_PROBES:
                r1, _, h1, b1 = await _replay(
                    client, config, method, url, query, headers, json_body,
                    field=fname, value=fval + payload)
                if not r1:
                    continue
                if detect_db_error(r1.text) and not base_has_db_error:
                    # signal 2: independent re-request with the SAME payload
                    # (baseline is clean, probe errors 2/2 -> confirmed)
                    r2, _, h2, b2 = await _replay(
                        client, config, method, url, query, headers, json_body,
                        field=fname, value=fval + payload)
                    if r2 and detect_db_error(r2.text):
                        findings.append(Finding(
                            type="SQL Injection", subtype="error-based (API body)",
                            severity="critical",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            url=url, method=method, param=f"body.{fname}",
                            payload=payload,
                            evidence=_evidence(
                                method, url, h1, b1, r1,
                                f"Database error signature appeared only with payload "
                                f"in JSON body field '{fname}' (2/2 confirmed); "
                                f"baseline response has no DB error."),
                            cwe="CWE-89", owasp="A03:2021 – Injection",
                            remediation=REMEDIATION_SQLI,
                            references=["https://owasp.org/API-Security/editions/2023/en/0x11-t03/"],
                        ).set_confidence("CONFIRMED"))
                        sqli_hit = True
                        break
            if sqli_hit:
                continue
            # --- XSS reflection in API responses: 2-signal (reflected + re-confirmed)
            # JSON responses escape quotes: check both raw and JSON-escaped forms
            _xss_variants = {_XSS_PROBE, _XSS_PROBE.replace('"', '\\"')}
            r1, _, h1, b1 = await _replay(
                client, config, method, url, query, headers, json_body,
                field=fname, value=fval + _XSS_PROBE)
            _reflected = (r1 and any(v in r1.text for v in _xss_variants)
                          and not any(v in base_text for v in _xss_variants))
            if _reflected:
                r2, _, _, _ = await _replay(
                    client, config, method, url, query, headers, json_body,
                    field=fname, value=fval + _XSS_PROBE)
                if r2 and any(v in r2.text for v in _xss_variants):
                    findings.append(Finding(
                        type="Cross-Site Scripting", subtype="reflected (API body)",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        url=url, method=method, param=f"body.{fname}",
                        payload=_XSS_PROBE,
                        evidence=_evidence(
                            method, url, h1, b1, r1,
                            f"Probe reflected verbatim in API response for JSON body "
                            f"field '{fname}' (2/2 confirmed). Exploitable if a "
                            f"client renders this value as HTML."),
                        cwe="CWE-79", owasp="A03:2021 – Injection",
                        remediation="Encode all API output on the client; validate "
                                    "and sanitize body fields server-side.",
                        references=["https://owasp.org/www-community/attacks/xss/"],
                    ).set_confidence("MEDIUM"))

        # --- parameter tampering: role/admin-like fields ---
        for fname in list(json_body.keys()):
            if not _TAMPER_FIELDS.match(fname):
                continue
            cur = str(json_body[fname]).lower()
            escalated = _TAMPER_VALUES.get(cur)
            if not escalated:
                continue
            r1, _, h1, b1 = await _replay(
                client, config, method, url, query, headers, json_body,
                field=fname, value=escalated)
            if not r1 or r1.status_code != 200:
                continue
            # signal 2: re-request; both must differ from baseline the same way
            r2, _, _, _ = await _replay(
                client, config, method, url, query, headers, json_body,
                field=fname, value=escalated)
            if (r2 and r2.status_code == 200
                    and is_significant_change(base_text, r1.text)
                    and _bodies_similar(r1.text, r2.text)):
                findings.append(Finding(
                    type="Broken Access Control", subtype="parameter tampering (API body)",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
                    url=url, method=method, param=f"body.{fname}",
                    payload=escalated,
                    evidence=_evidence(
                        method, url, h1, b1, r1,
                        f"Privilege field '{fname}' accepted escalated value "
                        f"'{escalated}' (2/2 confirmed, response differs from baseline)."),
                    cwe="CWE-639", owasp="A01:2021 – Broken Access Control",
                    remediation="Never trust client-supplied privilege fields; "
                                "enforce roles server-side from the session.",
                    references=["https://owasp.org/API-Security/editions/2023/en/0x11-t05/"],
                ).set_confidence("MEDIUM"))

    # ---- 3. custom header tests ----
    for hname in _prioritize_fields(list(custom.keys()))[:8]:
        # --- header reflection: 2-signal (canary reflected + re-confirmed)
        canary = "sxhdr7q2"
        r1, _, h1, _ = await _replay(
            client, config, method, url, query, headers, json_body,
            header_override={hname: canary})
        if r1 and canary in r1.text and canary not in base_text:
            r2, _, _, _ = await _replay(
                client, config, method, url, query, headers, json_body,
                header_override={hname: canary})
            if r2 and canary in r2.text:
                findings.append(Finding(
                    type="Security Misconfiguration",
                    subtype="unvalidated header reflection",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                    url=url, method=method, param=f"header.{hname}",
                    payload=canary,
                    evidence=_evidence(
                        method, url, h1, sent_body, r1,
                        f"Custom header '{hname}' value reflected verbatim in the "
                        f"response body (2/2 confirmed). Response-splitting / "
                        f"cache-poisoning vector if combined with CRLF."),
                    cwe="CWE-113", owasp="A05:2021 – Security Misconfiguration",
                    remediation="Never reflect raw header values into responses; "
                                "validate against an allowlist.",
                    references=["https://owasp.org/www-community/attacks/Cache_Poisoning"],
                ).set_confidence("MEDIUM"))

    # ---- 4. auth bypass: replay WITHOUT Authorization ----
    auth_names = [k for k in headers if k.lower() == "authorization"]
    if auth_names:
        aname = auth_names[0]
        r1, _, h1, _ = await _replay(
            client, config, method, url, query, headers, json_body,
            drop_headers={aname})
        if r1 and r1.status_code == 200:
            r2, _, _, _ = await _replay(
                client, config, method, url, query, headers, json_body,
                drop_headers={aname})
            if (r2 and r2.status_code == 200
                    and _bodies_similar(base_text, r1.text)
                    and _bodies_similar(r1.text, r2.text)):
                findings.append(Finding(
                    type="Broken Access Control", subtype="missing authentication (API)",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    url=url, method=method, param=f"header.{aname}",
                    evidence=_evidence(
                        method, url, h1, sent_body, r1,
                        f"API returns HTTP 200 with identical body WITHOUT the "
                        f"'{aname}' header the app's JS normally sends (2/2 "
                        f"confirmed). Authentication is not enforced."),
                    cwe="CWE-306", owasp="A01:2021 – Broken Access Control",
                    remediation="Enforce authentication on every API endpoint; "
                                "deny by default.",
                    references=["https://owasp.org/API-Security/editions/2023/en/0x11-t02/"],
                ).set_confidence("HIGH"))

    return findings


# standard module interface compliance: only run via engine's api-shape pass
scan_api_shape.NEEDS_PARAMS = False
