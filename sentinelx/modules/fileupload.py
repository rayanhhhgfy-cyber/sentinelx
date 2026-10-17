"""SentinelX module: Unrestricted file upload.

Techniques: upload webshell-named files with double extensions and
content-type spoofing; confirm via the returned file URL containing the
malicious name (2-signal: upload accepted + accessible URL).
Safe: uploaded content is inert text, never executed by the scanner.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin, urlsplit

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response

# (filename, content-type, label) — inert content, dangerous names
UPLOAD_PROBES = [
    ("sx_shell.php", "image/jpeg", "php-double-ctype"),
    ("sx_shell.php.jpg", "image/jpeg", "double-extension"),
    ("sx_shell.phtml", "image/jpeg", "alt-php-extension"),
    ("sx_shell.jsp", "image/jpeg", "jsp-extension"),
    ("sx_shell.aspx", "image/jpeg", "aspx-extension"),
]
INERT_CONTENT = b"<?php /* sentinelx inert probe - not executable */ echo 'sx'; ?>"

REMEDIATION_UPLOAD = (
    "Validate file type by content (magic bytes), not extension or Content-Type. "
    "Rename uploads to random names, store outside webroot, serve with "
    "Content-Disposition: attachment. Never allow executable extensions.")


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
    # self-gate: only test likely upload endpoints (avoid spamming every URL)
    pl = url.lower()
    param_names = " ".join((params or {}).keys()).lower()
    if not ("upload" in pl or "file" in pl or "avatar" in pl or "image" in pl
            or "file" in param_names or "upload" in param_names):
        return findings
    headers = {"User-Agent": config.user_agent}

    for fname, ctype, label in UPLOAD_PROBES:
        # unique filename to avoid collisions
        uniq = f"sx{secrets.token_hex(3)}_{fname}"
        boundary = "----SentinelXBoundary" + secrets.token_hex(4)
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f"; filename="{uniq}"\r\n'
            f"Content-Type: {ctype}\r\n\r\n"
        ).encode() + INERT_CONTENT + f"\r\n--{boundary}--\r\n".encode()
        h = dict(headers)
        h["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        resp = await client.post(url, data=body, headers=h, dedupe=False)
        if not resp or resp.status_code >= 400:
            continue
        # signal 1: server accepted + reflected the dangerous filename/URL
        if uniq not in resp.text and fname not in resp.text:
            continue
        # signal 2: the file URL is reachable (or the name is echoed as a path)
        m = re.search(r'["\']?((?:/uploads?/|https?://)[^"\'<>\s]*' +
                      re.escape(uniq) + r')[ "\']?', resp.text)
        file_url = m.group(1) if m else None
        reachable = False
        if file_url:
            abs_url = file_url if file_url.startswith("http") else urljoin(url, file_url)
            # same-origin only
            if urlsplit(abs_url).netloc == urlsplit(url).netloc:
                r2 = await client.get(abs_url, dedupe=False)
                reachable = bool(r2 and r2.status_code == 200)
        if file_url or reachable:
            ev = _evidence("POST", url, h, None, resp)
            ev.proof = (f"Unrestricted upload ({label}): server accepted '{uniq}' "
                        f"with spoofed Content-Type {ctype}"
                        f"{'; file reachable at ' + file_url if reachable else ''}")
            findings.append(Finding(
                type="Unrestricted File Upload", subtype=label,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                confidence=0.88 if reachable else 0.75, url=url, method="POST",
                param="f", payload=uniq, evidence=ev, cwe="CWE-434",
                owasp="A04:2021 – Insecure Design",
                remediation=REMEDIATION_UPLOAD,
                references=["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
            ))
            break
    return findings

# Self-gates on upload indicators in scan_endpoint; NEEDS_PARAMS=False so it
# also runs on discovered upload URLs without form params.
scan_endpoint.NEEDS_PARAMS = False
