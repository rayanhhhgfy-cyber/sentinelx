"""SentinelX core: shared baseline fetching.

One baseline per (method, url, param-set), fetched once and reused by all
modules. Eliminates duplicate baseline requests across sqli/rce/xss/etc.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlencode as _urlencode


@dataclass
class Baseline:
    """Baseline response characteristics for differential analysis."""
    status: int = 200
    body: str = ""
    length: int = 0
    avg_time: float = 0.0
    stable: bool = True


def _key(method: str, url: str, params: dict) -> tuple:
    return (method, url, ",".join(sorted(params)))


async def get_baseline(client, method: str, url: str, params: dict) -> Baseline | None:
    """Fetch (or reuse cached) baseline. Two samples; marks unstable if they differ."""
    if not hasattr(client, "baselines"):
        client.baselines = {}
    key = _key(method, url, params)
    if key in client.baselines:
        return client.baselines[key]

    bodies, times, status = [], [], 200
    ok = True
    for _ in range(2):
        t0 = time.monotonic()
        if method == "GET":
            full = url + ("&" if "?" in url else "?") + _urlencode(params) if params else url
            resp = await client.get(full, dedupe=False)
        else:
            resp = await client.post(url, data=params, dedupe=False)
        el = time.monotonic() - t0
        if not resp:
            ok = False
            break
        bodies.append(resp.text)
        times.append(el)
        status = resp.status_code
    if not ok:
        return None
    bl = Baseline(
        status=status,
        body=bodies[0],
        length=len(bodies[0]),
        avg_time=sum(times) / len(times),
        stable=len(bodies) == 2 and bodies[0] == bodies[1],
    )
    client.baselines[key] = bl
    return bl


def adaptive_delay(baseline_rtt: float) -> float:
    """Scale time-based payload delays to measured RTT.

    Enough to distinguish injection from jitter, without fixed 5s waits.
    delay = 50x RTT, clamped to [2.0, 5.0]s.
    """
    return max(2.0, min(5.0, baseline_rtt * 50.0))
