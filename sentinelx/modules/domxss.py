"""SentinelX module [35]: DOM-based XSS via real JavaScript execution.

Powered by sentinelx.jsruntime (js2py — real ECMAScript 5.1 engine).
Page <script> blocks are EXECUTED inside the virtual browser.
location.hash / location.search are seeded with unique taint canaries;
the instrumented environment records every sink hit. When a canary
reaches a sink — innerHTML, outerHTML, document.write, eval, Function,
setTimeout(string) — that is a PROVEN source → sink dataflow observed
during real JS execution.

Confidence:
- CONFIRMED: canary from hash/search proven to reach a dangerous sink
- MEDIUM: sink executed at runtime but no canary flow proven
- LOW (static_only): dangerous sink pattern in JS, never observed at runtime

Static patterns alone NEVER produce findings above LOW.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.jsruntime import execute, instrument, taint as taint_mod
from sentinelx.jsenv.static import score_js_interest


# sinks that execute attacker-controlled data as code/markup
DANGEROUS_SINKS = {
    "sink:innerHTML", "sink:outerHTML", "sink:document.write",
    "sink:eval", "sink:Function",
    "sink:setTimeout-string", "sink:setInterval-string",
    "sink:js-url-attr",
}


class _ScriptExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts: list[str] = []
        self._buf: list[str] | None = None
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            a = dict(attrs)
            if a.get("src"):
                self._skip = True
                return
            t = (a.get("type") or "").lower()
            if t and t not in ("text/javascript", "application/javascript",
                               "module", ""):
                self._skip = True
                return
            self._buf = []

    def handle_endtag(self, tag):
        if tag == "script":
            if self._buf is not None:
                body = "".join(self._buf).strip()
                if body:
                    self.scripts.append(body)
            self._buf = None
            self._skip = False

    def handle_data(self, data):
        if self._buf is not None and not self._skip:
            self._buf.append(data)


def extract_scripts(html: str) -> list[str]:
    p = _ScriptExtractor()
    try:
        p.feed(html)
    except Exception:
        pass
    return p.scripts


REMEDIATION_DOMXSS = (
    "Never assign attacker-influenced data to innerHTML/outerHTML, "
    "document.write, or eval. Use textContent for text, and sanitize with "
    "a whitelist HTML sanitizer (e.g. DOMPurify) when markup is required. "
    "Treat location.hash/location.search as untrusted input."
)


def _sink_subtype(kind: str) -> str:
    return "dom-xss-" + kind.split(":", 1)[1].replace(".", "-")


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if method.upper() != "GET":
        return findings
    headers = {"User-Agent": config.user_agent}
    resp = await client.get(url, headers=headers)
    if not resp:
        return findings
    ctype = resp.headers.get("content-type", "")
    if "html" not in ctype and "<script" not in resp.text[:20000].lower():
        return findings

    try:
        html = resp.text
    except Exception:
        return findings

    scripts = extract_scripts(html)
    if not scripts:
        return findings

    # cheap static gate: only execute scripts that mention sinks/sources
    interesting = []
    for js in scripts:
        if len(js) > 60000:
            continue
        score, sinks, sources = score_js_interest(js)
        if score > 0:
            interesting.append((score, js, sinks))
    if not interesting:
        return findings
    interesting.sort(key=lambda x: -x[0])
    interesting = interesting[:6]

    # one taint tracker per page; hash canary is the primary source
    tracker = taint_mod.TaintTracker()
    hash_mark = tracker.new_mark(taint_mod.Source.FRAGMENT, "location.hash")
    search_mark = tracker.new_mark(taint_mod.Source.QUERY, "location.search")

    seen: set[tuple] = set()
    for score, js, static_sinks in interesting:
        result = execute(
            js, page_url=url,
            hash_canary=hash_mark.canary, search_canary=search_mark.canary,
            timeout=10,
        )
        if not result.executed:
            continue

        # correlate: static sinks + runtime taint flows → confidence
        cf = instrument.correlate_dom_xss(static_sinks, result, tracker)

        for flow in cf.flows:
            if flow.sink not in DANGEROUS_SINKS:
                continue
            key = (flow.sink, flow.source_id)
            if key in seen:
                continue
            seen.add(key)

            is_code_sink = flow.sink in (
                "sink:eval", "sink:Function",
                "sink:setTimeout-string", "sink:setInterval-string")
            ev = Evidence(
                request_raw=raw_request("GET", url, headers, None),
                response_raw=raw_response(resp.status_code, dict(resp.headers),
                                          resp.content[:1500]),
                proof=(
                    f"DOM XSS CONFIRMED by real JS execution (js2py): tainted "
                    f"data from {flow.source}({flow.source_id}) reached "
                    f"{flow.sink}. Sink received: {flow.evidence[:220]}"
                ),
            )
            f = Finding(
                type="Cross-Site Scripting",
                subtype=_sink_subtype(flow.sink),
                cvss_vector=("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
                             if is_code_sink else
                             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
                confidence=0.95, url=url, method="GET", param=flow.source_id,
                payload="#" + hash_mark.canary if flow.source_id == "location.hash"
                else "?" + search_mark.canary,
                evidence=ev, cwe="CWE-79",
                owasp="A03:2021 – Injection",
                remediation=REMEDIATION_DOMXSS,
                references=[
                    "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                    "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                ],
            )
            f.set_confidence("CONFIRMED")
            f.source = f"{flow.source}({flow.source_id})"
            f.sink = flow.sink
            f.execution_trace = [
                {"kind": e.get("kind"), "data": e.get("data")}
                for e in result.trace[:25]
            ]
            findings.append(f)

        # MEDIUM: dangerous sink executed at runtime, no canary flow proven.
        # Only report once per sink kind per page to avoid noise.
        if cf.confidence == "MEDIUM":
            for e in result.dom_writes + result.eval_calls:
                kind = str(e.get("kind", ""))
                if kind not in DANGEROUS_SINKS:
                    continue
                key = ("medium", kind)
                if key in seen:
                    continue
                seen.add(key)
                d = e.get("data") or {}
                ev = Evidence(
                    request_raw=raw_request("GET", url, headers, None),
                    response_raw=raw_response(resp.status_code, dict(resp.headers),
                                              resp.content[:1500]),
                    proof=(f"DOM sink {kind} executed during real JS "
                           f"execution, but no attacker-controlled data flow "
                           f"was proven. Sink received: "
                           f"{str(d.get('value', ''))[:220]}"),
                )
                f = Finding(
                    type="Cross-Site Scripting",
                    subtype=_sink_subtype(kind) + "-unproven",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
                    confidence=0.55, url=url, method="GET", param="",
                    evidence=ev, cwe="CWE-79",
                    owasp="A03:2021 – Injection",
                    remediation=REMEDIATION_DOMXSS,
                    references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
                )
                f.set_confidence("MEDIUM")
                f.sink = kind
                findings.append(f)

    return findings
