"""SentinelX: webhook notifications (Slack, Discord, generic)."""

from __future__ import annotations

import httpx

from sentinelx.core.models import Finding


async def notify(url: str, findings: list[Finding], target: str, kind: str = "generic"):
    """Send scan summary to a webhook. kind: slack | discord | generic."""
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    text = (f"SentinelX scan of {target}: {len(findings)} findings "
            f"({crit} critical, {high} high)")
    async with httpx.AsyncClient(timeout=10) as c:
        if kind == "slack":
            await c.post(url, json={"text": text})
        elif kind == "discord":
            await c.post(url, json={"content": text})
        else:
            await c.post(url, json={
                "tool": "sentinelx", "target": target,
                "findings": len(findings), "critical": crit, "high": high,
                "items": [f.to_dict() for f in findings[:20]],
            })
