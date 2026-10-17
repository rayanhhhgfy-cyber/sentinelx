"""SentinelX orchestrator: runs discovery then modules, dedupes findings."""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding
from sentinelx.discovery.crawler import Crawler, Endpoint
from sentinelx.modules import sqli, xss, audit, probe, lfi, ssrf, rce, idor, jwt, csrf, bac, smuggling
from sentinelx.modules import secrets as secrets_mod, techfp, graphql


async def run_scan(config: ScanConfig, on_finding=None, on_progress=None) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    seq = 0

    def emit(f: Finding):
        nonlocal seq
        key = f.dedup_key()
        if key in seen:
            return
        seen.add(key)
        seq += 1
        f.finalize(seq)
        findings.append(f)
        if on_finding:
            on_finding(f)

    def progress(msg: str):
        if on_progress:
            on_progress(msg)

    async with ScanClient(config) as client:
        # ---- per-module request stats (optional; web UI reads config.stats) ----
        _mod_stats: dict[str, int] = {}
        _active = {"module": "discovery"}
        _orig_request = client.request

        async def _tracked_request(method, url, **kw):
            if config.stats is not None:
                m = _active["module"]
                _mod_stats[m] = _mod_stats.get(m, 0) + 1
            return await _orig_request(method, url, **kw)

        client.request = _tracked_request  # type: ignore[method-assign]

        def _enabled(name: str) -> bool:
            mods = config.modules or []
            return not mods or name in mods

        def _use_module(name: str):
            _active["module"] = name
        # ---- WAF fingerprinting ----
        _use_module("waf")
        progress("evasion: WAF fingerprinting")
        try:
            from sentinelx.evasion.fingerprint import fingerprint as waf_fp
            wafs = await waf_fp(client, target)
            if wafs:
                progress(f"evasion: WAF detected: {', '.join(wafs)}")
        except Exception:
            pass

        # ---- discovery ----
        _use_module("discovery")
        progress("discovery: crawling")
        crawler = Crawler(client, config)
        endpoints = await crawler.run()
        progress(f"discovery: {len(endpoints)} endpoints, {len(crawler.visited)} pages")

        target = config.target

        # ---- passive audits on the main URL ----
        _use_module("audit")
        if _enabled("audit"):
            for f in await audit.scan_headers(client, config, target): emit(f)
            for f in await audit.scan_cookies(client, config, target): emit(f)
            for f in await audit.scan_cors(client, config, target): emit(f)
            for f in await audit.scan_methods(client, config, target): emit(f)
        progress("audit: headers/cookies/cors/methods done")

        # ---- directory bruteforce ----
        _use_module("dirfuzz")
        if _enabled("dirfuzz"):
            for f in await probe.scan_dirfuzz(client, config, target): emit(f)
        progress("probe: directory bruteforce done")

        # ---- JWT tests (token extraction + attacks) ----
        progress("modules: JWT analysis")
        _use_module("jwt")
        try:
            if _enabled("jwt"):
                for f in await jwt.scan_endpoint(client, config, "GET", target, {}): emit(f)
        except Exception:
            pass

        # ---- broken access control (forced browsing) ----
        progress("modules: broken access control")
        _use_module("bac")
        try:
            if _enabled("bac"):
                for f in await bac.scan_target(client, config, target): emit(f)
        except Exception:
            pass

        # ---- secrets + tech fingerprinting + graphql ----
        progress("modules: secrets / tech / graphql")
        _use_module("secrets")
        try:
            if _enabled("secrets"):
                for f in await secrets_mod.scan_page(client, config, target): emit(f)
            _use_module("techfp")
            if _enabled("techfp"):
                for f in await techfp.fingerprint(client, config, target): emit(f)
            _use_module("graphql")
            if _enabled("graphql"):
                for f in await graphql.scan_endpoint(client, config, "GET", target, {}): emit(f)
        except Exception:
            pass

        # ---- HTTP request smuggling (raw socket, timing-safe) ----
        progress("modules: request smuggling")
        _use_module("smuggling")
        try:
            if _enabled("smuggling"):
                for f in await smuggling.scan_target(client, config, target): emit(f)
        except Exception:
            pass

        # ---- per-endpoint active modules ----
        sem = asyncio.Semaphore(10)

        async def scan_ep(ep: Endpoint):
            async with sem:
                try:
                    _use_module("sqli")
                    if _enabled("sqli"):
                        for f in await sqli.scan_endpoint(
                                client, config, ep.method, ep.url, ep.params): emit(f)
                    _use_module("xss")
                    if _enabled("xss"):
                        for f in await xss.scan_endpoint(
                                client, config, ep.method, ep.url, ep.params): emit(f)
                    _use_module("openredirect")
                    if _enabled("openredirect"):
                        for f in await probe.scan_openredirect(
                                client, config, ep.method, ep.url, ep.params): emit(f)
                    _use_module("lfi")
                    if _enabled("lfi"):
                        for f in await lfi.scan_endpoint(
                                client, config, ep.method, ep.url, ep.params): emit(f)
                    _use_module("ssrf")
                    if _enabled("ssrf"):
                        for f in await ssrf.scan_endpoint(
                                client, config, ep.method, ep.url, ep.params): emit(f)
                    _use_module("rce")
                    if _enabled("rce"):
                        for f in await rce.scan_endpoint(
                                client, config, ep.method, ep.url, ep.params): emit(f)
                    _use_module("idor")
                    if _enabled("idor"):
                        for f in await idor.scan_endpoint(
                                client, config, ep.method, ep.url, ep.params): emit(f)
                    _use_module("csrf")
                    if _enabled("csrf"):
                        for f in await csrf.scan_endpoint(
                                client, config, ep.method, ep.url, ep.params): emit(f)
                except Exception:
                    pass

        # seed with target itself if it has params
        from sentinelx.discovery.crawler import split_params
        clean, params = split_params(target)
        all_eps = list(endpoints)
        if params:
            all_eps.append(Endpoint(url=clean, params=params, source="seed"))

        progress(f"modules: scanning {len(all_eps)} endpoints")
        await asyncio.gather(*[scan_ep(ep) for ep in all_eps])
        progress(f"done: {len(findings)} findings, {client.requests_made} requests")

    if config.stats is not None:
        config.stats["modules"] = dict(_mod_stats)
        config.stats["total_requests"] = client.requests_made

    # ---- AI brain: chain findings (heuristic, works without API keys) ----
    try:
        from sentinelx.ai.brain import AIBrain
        brain = AIBrain()
        chains = brain.chain_findings([f.to_dict() for f in findings])
        if chains:
            for c in chains:
                progress(f"ai: chain: {c.get('name', c)}")
    except Exception:
        pass

    return findings
