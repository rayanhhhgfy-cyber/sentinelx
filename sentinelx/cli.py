#!/usr/bin/env python3
"""SentinelX CLI — real vulnerability scanner.

Usage:
    python -m sentinelx.cli --target http://localhost:5000 --confirm-own
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from urllib.parse import urlsplit

from rich.console import Console
from rich.table import Table

from sentinelx.core.http import ScanConfig
from sentinelx.engine import run_scan
from sentinelx.reports.reports import write_json, write_html

console = Console()

SEV_STYLE = {
    "critical": "bold red", "high": "red", "medium": "yellow",
    "low": "cyan", "info": "dim",
}


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="SentinelX — authorized web vulnerability scanner")
    p.add_argument("--target", required=True, help="Target URL (you must own it or have permission)")
    p.add_argument("--confirm-own", action="store_true",
                   help="Confirm you own the target or have written permission to test it")
    p.add_argument("--concurrency", type=int, default=30)
    p.add_argument("--rate", type=float, default=10.0, help="requests/sec per host")
    p.add_argument("--depth", type=int, default=2, help="crawl depth")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--json", default="sentinelx-report.json")
    p.add_argument("--html", default="sentinelx-report.html")
    p.add_argument("--sarif", default="", help="also write SARIF report to PATH")
    p.add_argument("--no-html", action="store_true")
    p.add_argument("--unsafe", action="store_true",
                   help="allow potentially destructive techniques")
    p.add_argument("--oob-domain", default="", help="out-of-band callback domain")
    p.add_argument("--lhost", default="", help="reverse-shell listener host")
    p.add_argument("--lport", type=int, default=0, help="reverse-shell listener port")
    p.add_argument("--auth-a", default="", help="bearer token for session A (IDOR)")
    p.add_argument("--auth-b", default="", help="bearer token for session B (IDOR)")
    p.add_argument("--webhook", default="", help="webhook URL for completion notification")
    p.add_argument("--webhook-kind", default="generic", choices=["slack", "discord", "generic"])
    p.add_argument("--max-pages", type=int, default=50, help="max pages to crawl")
    p.add_argument("--no-smart", action="store_true", help="disable smart mode (tech-tuned payloads, priority queue)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    u = urlsplit(args.target)
    if u.scheme not in ("http", "https") or not u.netloc:
        console.print("[red]Invalid target URL. Use http(s)://host[:port][/path][/red]")
        return 2
    if not args.confirm_own:
        console.print(
            "[bold red]Refusing to scan.[/bold red]\n"
            "You must only scan systems you own or have explicit written permission to test.\n"
            "Re-run with [bold]--confirm-own[/bold] to confirm authorization."
        )
        return 2

    config = ScanConfig(
        target=args.target, concurrency=args.concurrency,
        rate_per_sec=args.rate, crawl_depth=args.depth, timeout=args.timeout,
        oob_domain=args.oob_domain, auth_a=args.auth_a, auth_b=args.auth_b,
        max_pages=args.max_pages, smart=not args.no_smart,
    )
    unsafe = args.unsafe

    live = []

    def on_finding(f):
        live.append(f)
        console.print(
            f"[{SEV_STYLE.get(f.severity, 'dim')}]● {f.severity.upper():8}[/] "
            f"{f.type} [{f.subtype}] — {f.method} {f.url[:90]}"
        )

    def on_progress(msg):
        console.print(f"[dim]… {msg}[/dim]")

    console.print(f"[bold]SentinelX[/bold] → {args.target}  [dim](authorized scan)[/dim]")
    findings = asyncio.run(run_scan(config, on_finding=on_finding, on_progress=on_progress))

    # summary table
    table = Table(title="Findings by severity")
    table.add_column("Severity"); table.add_column("Count", justify="right")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in counts:
            table.add_row(sev.upper(), str(counts[sev]))
    console.print(table)

    write_json(findings, args.json, meta={"target": args.target})
    console.print(f"[green]JSON report:[/green] {args.json}")
    if not args.no_html:
        write_html(findings, args.html, args.target)
        console.print(f"[green]HTML report:[/green] {args.html}")
    if args.sarif:
        from sentinelx.reports.sarif import write_sarif
        write_sarif(findings, args.sarif, args.target)
        console.print(f"[green]SARIF report:[/green] {args.sarif}")
    if args.lhost and args.lport:
        from sentinelx.modules.rce import reverse_shells
        console.print("\n[bold]Reverse shells (listener: "
                      f"{args.lhost}:{args.lport}):[/bold]")
        for name, cmd in reverse_shells(args.lhost, args.lport).items():
            console.print(f"  [cyan]{name}:[/cyan] {cmd[:80]}…")
    if args.webhook:
        from sentinelx.notify import notify
        asyncio.run(notify(args.webhook, findings, args.target, args.webhook_kind))
        console.print(f"[green]Webhook notified.[/green]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
