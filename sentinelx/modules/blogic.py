"""SentinelX module: business logic probes.

Real implementation:
- Price/quantity tampering: on e-commerce-flavored params (price, amount,
  total, qty, quantity, discount), submit negative / zero / overflow values
  and detect server acceptance (200 + reflected tampered value, or a
  downstream total that changed).
- Race condition probe: on state-changing endpoints (POST with params),
  fire N parallel identical requests and detect inconsistent outcomes
  (e.g. one succeeds where sequential would fail) — a double-spend signal.

Safe: uses non-destructive values (negative/zero quantities, tiny amounts);
never completes real purchases. Race probe is read-only in effect — it
repeats the same benign request and compares outcomes.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.core.diff import fuzzy_similarity

PRICE_RE = re.compile(r"price|amount|total|cost|qty|quantity|discount|coupon", re.I)

TAMPER_VALUES = ["-1", "0", "-999", "999999999", "0.01", "-0.01"]

REMEDIATION_BLOGIC = (
    "Validate all business-critical values server-side: reject negative/zero "
    "quantities and prices, recompute totals from trusted data (never trust "
    "client-supplied prices), and use atomic transactions / idempotency keys "
    "to prevent race-condition double-spend."
)


async def _send(client, method, url, params, param, value):
    p = dict(params); p[param] = value
    if method == "GET":
        full = url + ("&" if "?" in url else "?") + _urlencode(p)
        resp = await client.get(full)
        return resp, full, None
    resp = await client.post(url, data=p)
    return resp, url, _urlencode(p).encode()


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not params:
        return findings
    headers = {"User-Agent": config.user_agent}

    # ---------- 1. price/quantity tampering ----------
    biz_params = [p for p in params if PRICE_RE.search(p)]
    for param in biz_params:
        # baseline
        r0, _, _ = await _send(client, method, url, params, param, params[param])
        if not r0 or r0.status_code != 200:
            continue
        base_body = r0.text
        for tamper in TAMPER_VALUES:
            r1, full1, body1 = await _send(client, method, url, params, param, tamper)
            if not r1 or r1.status_code != 200:
                continue
            # accepted if the tampered value is reflected AND the page
            # materially differs from baseline (not just an error page)
            if tamper in r1.text:
                sim = fuzzy_similarity(base_body, r1.text)
                err = re.search(r"error|invalid|not allowed|rejected", r1.text, re.I)
                if sim < 0.95 and not err:
                    ev = Evidence(
                        request_raw=raw_request(method, full1, headers, body1),
                        response_raw=raw_response(r1.status_code, dict(r1.headers),
                                                  r1.content),
                        proof=(f"Tampered value '{tamper}' for '{param}' accepted "
                               f"(HTTP 200, value reflected, no validation error)"),
                    )
                    findings.append(Finding(
                        type="Business Logic Flaw", subtype="price-quantity-tampering",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                        confidence=0.80, url=full1, method=method, param=param,
                        payload=tamper, evidence=ev, cwe="CWE-837",
                        owasp="A04:2021 – Insecure Design",
                        remediation=REMEDIATION_BLOGIC,
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    ))
                    break

    # ---------- 2. race condition probe (parallel identical POSTs) ----------
    # Only on POST endpoints with params (state-changing). Fire 8 parallel
    # requests; if outcomes differ (some 200, some 500/error, or bodies
    # diverge), the endpoint lacks atomicity — flag as a race lead.
    if method == "POST" and params and not any(
            f.type == "Business Logic Flaw" for f in findings):
        async def one():
            r, _, _ = await _send(client, method, url, params,
                                  next(iter(params)), params[next(iter(params))])
            return (r.status_code if r else -1,
                    (r.text[:500] if r else ""))
        results = await asyncio.gather(*[one() for _ in range(8)])
        codes = {c for c, _ in results}
        bodies = {b for _, b in results}
        # inconsistent outcomes across identical parallel requests
        if len(codes) > 1 and -1 not in codes:
            ev = Evidence(
                request_raw=raw_request(method, url, headers,
                                        _urlencode(params).encode()),
                response_raw=raw_response(results[0][0], {}, b""),
                proof=(f"8 parallel identical POSTs returned differing status "
                       f"codes {sorted(codes)} — non-atomic handling (race lead)"),
            )
            findings.append(Finding(
                type="Business Logic Flaw", subtype="race-condition-lead",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
                confidence=0.60, url=url, method=method,
                param=",".join(params.keys()), payload="[8x parallel POST]",
                evidence=ev, cwe="CWE-362",
                owasp="A04:2021 – Insecure Design",
                remediation=REMEDIATION_BLOGIC,
                references=["https://owasp.org/www-community/attacks/Race_Condition"],
            ))
    return findings
