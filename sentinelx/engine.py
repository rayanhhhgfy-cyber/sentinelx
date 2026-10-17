"""SentinelX orchestrator: runs discovery then modules, dedupes findings.

Refactored into resumable stages so serverless chunk-runners can execute
one stage (or a slice of the per-endpoint stage) per invocation and persist
a checkpoint between chunks. `run_scan()` keeps the original all-at-once
behavior for the CLI.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding
from sentinelx.discovery.crawler import Crawler, Endpoint
from sentinelx.modules import sqli, xss, audit, probe, lfi, ssrf, rce, idor, jwt, csrf, bac, smuggling
from sentinelx.modules import secrets as secrets_mod, techfp, graphql


STAGES = [
    "waf",            # WAF fingerprinting (fast, passive)
    "discovery",      # crawl -> endpoint list
    "audit",          # headers / cookies / CORS / methods on main URL
    "dirfuzz",        # directory bruteforce
    "jwt",            # JWT analysis on main URL
    "bac",            # broken access control
    "stg",            # secrets + tech fingerprinting + graphql
    "smuggling",      # HTTP request smuggling (raw sockets)
    "endpoints",      # per-endpoint active modules (cursor-based, chunkable)
    "finalize",       # AI brain chaining (no new findings)
]


@dataclass
class ScanCtx:
    client: ScanClient
    config: ScanConfig
    emit: object = None          # callable(Finding)
    progress: object = None      # callable(str)
    seen: set = field(default_factory=set)
    seq: int = 0
    endpoints: list = field(default_factory=list)   # list of dicts
    findings: list = field(default_factory=list)
    mod_stats: dict = field(default_factory=dict)
    active_module: str = "discovery"

    def _emit(self, f: Finding):
        key = f.dedup_key()
        if key in self.seen:
            return
        self.seen.add(key)
        self.seq += 1
        f.finalize(self.seq)
        self.findings.append(f)
        if self.emit:
            self.emit(f)

    def _progress(self, msg: str):
        if self.progress:
            self.progress(msg)

    def _use(self, name: str):
        self.active_module = name

    def _enabled(self, name: str) -> bool:
        mods = self.config.modules or []
        return not mods or name in mods

    def checkpoint(self) -> dict:
        return {
            "seen_keys": sorted(self.seen),
            "seq": self.seq,
            "endpoints": self.endpoints,
            "mod_stats": dict(self.mod_stats),
        }

    @classmethod
    def restore(cls, client, config, emit, progress, cp: dict) -> "ScanCtx":
        ctx = cls(client=client, config=config, emit=emit, progress=progress)
        ctx.seen = set(cp.get("seen_keys") or [])
        ctx.seq = int(cp.get("seq") or 0)
        ctx.endpoints = cp.get("endpoints") or []
        ctx.mod_stats = dict(cp.get("mod_stats") or {})
        return ctx


def _tracked_client(client: ScanClient, config: ScanConfig, ctx: ScanCtx) -> ScanClient:
    """Wrap client.request to attribute request counts to the active module."""
    orig = client.request

    async def _tracked(method, url, **kw):
        if config.stats is not None:
            m = ctx.active_module
            ctx.mod_stats[m] = ctx.mod_stats.get(m, 0) + 1
        return await orig(method, url, **kw)

    client.request = _tracked  # type: ignore[method-assign]
    return client


async def run_stage(ctx: ScanCtx, stage: str):
    """Run one named stage. The 'endpoints' stage runs ALL endpoints (use
    run_endpoints_slice for chunked execution)."""
    client, config = ctx.client, ctx.config
    target = config.target

    if stage == "waf":
        ctx._use("waf")
        ctx._progress("evasion: WAF fingerprinting")
        try:
            from sentinelx.evasion.fingerprint import fingerprint as waf_fp
            wafs = await waf_fp(client, target)
            if wafs:
                ctx._progress(f"evasion: WAF detected: {', '.join(wafs)}")
        except Exception:
            pass

    elif stage == "discovery":
        ctx._use("discovery")
        ctx._progress("discovery: crawling")
        crawler = Crawler(client, config)
        endpoints = await crawler.run()
        ctx._progress(f"discovery: {len(endpoints)} endpoints, {len(crawler.visited)} pages")
        ctx.endpoints = [
            {"url": ep.url, "method": ep.method, "params": ep.params}
            for ep in endpoints
        ]

    elif stage == "audit":
        ctx._use("audit")
        if ctx._enabled("audit"):
            for f in await audit.scan_headers(client, config, target):
                ctx._emit(f)
            for f in await audit.scan_cookies(client, config, target):
                ctx._emit(f)
            for f in await audit.scan_cors(client, config, target):
                ctx._emit(f)
            for f in await audit.scan_methods(client, config, target):
                ctx._emit(f)
        ctx._progress("audit: headers/cookies/cors/methods done")

    elif stage == "dirfuzz":
        ctx._use("dirfuzz")
        if ctx._enabled("dirfuzz"):
            for f in await probe.scan_dirfuzz(client, config, target):
                ctx._emit(f)
        ctx._progress("probe: directory bruteforce done")

    elif stage == "jwt":
        ctx._use("jwt")
        ctx._progress("modules: JWT analysis")
        try:
            if ctx._enabled("jwt"):
                for f in await jwt.scan_endpoint(client, config, "GET", target, {}):
                    ctx._emit(f)
        except Exception:
            pass

    elif stage == "bac":
        ctx._use("bac")
        ctx._progress("modules: broken access control")
        try:
            if ctx._enabled("bac"):
                for f in await bac.scan_target(client, config, target):
                    ctx._emit(f)
        except Exception:
            pass

    elif stage == "stg":
        ctx._progress("modules: secrets / tech / graphql")
        try:
            ctx._use("secrets")
            if ctx._enabled("secrets"):
                for f in await secrets_mod.scan_page(client, config, target):
                    ctx._emit(f)
            ctx._use("techfp")
            if ctx._enabled("techfp"):
                for f in await techfp.fingerprint(client, config, target):
                    ctx._emit(f)
            ctx._use("graphql")
            if ctx._enabled("graphql"):
                for f in await graphql.scan_endpoint(client, config, "GET", target, {}):
                    ctx._emit(f)
        except Exception:
            pass

    elif stage == "smuggling":
        ctx._use("smuggling")
        ctx._progress("modules: request smuggling")
        try:
            if ctx._enabled("smuggling"):
                for f in await smuggling.scan_target(client, config, target):
                    ctx._emit(f)
        except Exception:
            pass

    elif stage == "endpoints":
        _, done = await run_endpoints_slice(ctx, 0, None)
        assert done

    elif stage == "finalize":
        try:
            from sentinelx.ai.brain import AIBrain
            brain = AIBrain()
            chains = brain.chain_findings([f.to_dict() for f in ctx.findings])
            if chains:
                for c in chains:
                    ctx._progress(f"ai: chain: {c.get('name', c)}")
        except Exception:
            pass

    else:
        raise ValueError(f"unknown stage: {stage}")


async def run_endpoints_slice(ctx: ScanCtx, start_idx: int,
                              deadline: float | None,
                              batch_size: int = 4) -> tuple[int, bool]:
    """Scan endpoints[start_idx:] in small batches. Returns (next_idx, done).
    Stops early when deadline (monotonic seconds) is exceeded."""
    from sentinelx.discovery.crawler import split_params

    client, config = ctx.client, ctx.config
    target = config.target

    # seed target itself if it carries params (mirrors original behavior)
    eps = list(ctx.endpoints)
    clean, params = split_params(target)
    if params and not any(e["url"] == clean for e in eps):
        eps.append({"url": clean, "method": "GET", "params": params})

    sem = asyncio.Semaphore(10)

    async def scan_ep(ep: dict):
        async with sem:
            try:
                ctx._use("sqli")
                if ctx._enabled("sqli"):
                    for f in await sqli.scan_endpoint(
                            client, config, ep["method"], ep["url"], ep["params"]):
                        ctx._emit(f)
                ctx._use("xss")
                if ctx._enabled("xss"):
                    for f in await xss.scan_endpoint(
                            client, config, ep["method"], ep["url"], ep["params"]):
                        ctx._emit(f)
                ctx._use("openredirect")
                if ctx._enabled("openredirect"):
                    for f in await probe.scan_openredirect(
                            client, config, ep["method"], ep["url"], ep["params"]):
                        ctx._emit(f)
                ctx._use("lfi")
                if ctx._enabled("lfi"):
                    for f in await lfi.scan_endpoint(
                            client, config, ep["method"], ep["url"], ep["params"]):
                        ctx._emit(f)
                ctx._use("ssrf")
                if ctx._enabled("ssrf"):
                    for f in await ssrf.scan_endpoint(
                            client, config, ep["method"], ep["url"], ep["params"]):
                        ctx._emit(f)
                ctx._use("rce")
                if ctx._enabled("rce"):
                    for f in await rce.scan_endpoint(
                            client, config, ep["method"], ep["url"], ep["params"]):
                        ctx._emit(f)
                ctx._use("idor")
                if ctx._enabled("idor"):
                    for f in await idor.scan_endpoint(
                            client, config, ep["method"], ep["url"], ep["params"]):
                        ctx._emit(f)
                ctx._use("csrf")
                if ctx._enabled("csrf"):
                    for f in await csrf.scan_endpoint(
                            client, config, ep["method"], ep["url"], ep["params"]):
                        ctx._emit(f)
            except Exception:
                pass

    idx = start_idx
    total = len(eps)
    while idx < total:
        batch = eps[idx:idx + batch_size]
        await asyncio.gather(*[scan_ep(ep) for ep in batch])
        idx += len(batch)
        ctx._progress(f"modules: endpoints {idx}/{total}")
        if deadline is not None and time.monotonic() >= deadline:
            break
    return idx, idx >= total


async def run_scan(config: ScanConfig, on_finding=None, on_progress=None) -> list[Finding]:
    """Original all-at-once behavior (CLI)."""
    stats_bucket: dict = {}
    config.stats = stats_bucket
    async with ScanClient(config) as client:
        ctx = ScanCtx(client=client, config=config,
                      emit=on_finding, progress=on_progress)
        _tracked_client(client, config, ctx)
        for stage in STAGES:
            await run_stage(ctx, stage)
        ctx._progress(f"done: {len(ctx.findings)} findings, "
                      f"{client.requests_made} requests")
    if config.stats is not None:
        config.stats["modules"] = dict(ctx.mod_stats)
        config.stats["total_requests"] = client.requests_made
    return ctx.findings
