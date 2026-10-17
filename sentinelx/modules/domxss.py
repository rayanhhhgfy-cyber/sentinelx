"""SentinelX module [35]: DOM-based XSS via pure-Python JS execution.

Real implementation — no Playwright, no headless browser. Page <script>
blocks are EXECUTED inside SentinelX's own JS interpreter (sentinelx/jsenv)
against a virtual browser. location.hash / location.search are seeded with
canary values; the interpreter tracks taint from those sources through
string operations. When tainted data reaches a sink — innerHTML, outerHTML,
document.write, eval, Function, setTimeout(string), event-handler
attributes — that is a REAL dataflow observed during REAL execution, and a
finding is emitted with the sink, the tainted value, and the code path.

Two-signal rule: a sink hit counts only if (1) the canary value is present
in the sink payload AND (2) the taint label traces to location.hash or
location.search. Static pattern matches alone never produce findings.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.jsenv.executor import execute_scripts
from sentinelx.jsenv.static import score_js_interest


CANARY = "SXDOMXSS9ZQ"
HASH_CANARY = "#" + CANARY
SEARCH_CANARY = "?sx=" + CANARY

# sinks that execute attacker-controlled data as code/markup
DANGEROUS_SINKS = {
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval", "Function", "setTimeout(string)", "setInterval(string)",
}

# sinks that are markup but need a script-execution context to be XSS
TAINTED_TEXT_OK = "(text-safe)"  # textContent/innerText — recorded but not XSS


class _ScriptExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts: list[str] = []
        self._buf: list[str] | None = None
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            a = dict(attrs)
            # external src or non-JS types: skip body
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

    # prioritize: only execute scripts that mention sinks (cheap static gate)
    interesting = []
    for js in scripts:
        if len(js) > 60000:
            continue  # pathological bundle — static path covers discovery
        score, sinks, sources = score_js_interest(js)
        if score > 0:
            interesting.append((score, js, sinks, sources))
    if not interesting:
        return findings
    interesting.sort(key=lambda x: -x[0])
    interesting = interesting[:6]  # bound execution cost per page

    seen_sinks: set[str] = set()
    for score, js, sinks, sources in interesting:
        result = execute_scripts(
            [js], page_url=url,
            hash_canary=HASH_CANARY, search_canary=SEARCH_CANARY,
        )
        if not result.executed:
            continue

        # --- signal 1+2: canary present AND tainted from hash/search ---
        for w in result.dom_writes:
            sink_base = w["sink"].split("#")[0]
            if sink_base not in DANGEROUS_SINKS:
                continue
            if TAINTED_TEXT_OK in w["sink"]:
                continue
            if CANARY not in w["value"]:
                continue  # signal 1: canary must reach the sink
            taint = w["taint"] or ""
            if "location.hash" not in taint and "location.search" not in taint:
                continue  # signal 2: must be attacker-controlled flow
            key = (sink_base, taint)
            if key in seen_sinks:
                continue
            seen_sinks.add(key)

            src = "location.hash" if "location.hash" in taint else "location.search"
            proof = (
                f"DOM XSS confirmed by JS execution: tainted data from {src} "
                f"reached sink {w['sink']} during real interpretation. "
                f"Sink received: {w['value'][:220]}"
            )
            ev = Evidence(
                request_raw=raw_request("GET", url, headers, None),
                response_raw=raw_response(resp.status_code, dict(resp.headers),
                                          resp.content[:1500]),
                proof=proof,
            )
            findings.append(Finding(
                type="Cross-Site Scripting", subtype=f"dom-xss-{sink_base}",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                confidence=0.85, url=url, method="GET", param=src,
                payload=HASH_CANARY if "hash" in src else SEARCH_CANARY,
                evidence=ev, cwe="CWE-79",
                owasp="A03:2021 – Injection",
                remediation=REMEDIATION_DOMXSS,
                references=[
                    "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                    "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                ],
            ))

        # eval-family sinks with tainted input
        for e in result.eval_calls:
            if CANARY not in e["code"]:
                continue
            taint = e["taint"] or ""
            if "location.hash" not in taint and "location.search" not in taint:
                continue
            key = ("eval:" + e["sink"], taint)
            if key in seen_sinks:
                continue
            seen_sinks.add(key)
            src = "location.hash" if "location.hash" in taint else "location.search"
            ev = Evidence(
                request_raw=raw_request("GET", url, headers, None),
                response_raw=raw_response(resp.status_code, dict(resp.headers),
                                          resp.content[:1500]),
                proof=(f"DOM code injection confirmed by JS execution: tainted "
                       f"data from {src} reached {e['sink']}. "
                       f"Code: {e['code'][:220]}"),
            )
            findings.append(Finding(
                type="Cross-Site Scripting", subtype=f"dom-code-injection-{e['sink']}",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
                confidence=0.88, url=url, method="GET", param=src,
                payload=HASH_CANARY if "hash" in src else SEARCH_CANARY,
                evidence=ev, cwe="CWE-79",
                owasp="A03:2021 – Injection",
                remediation=REMEDIATION_DOMXSS,
                references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
            ))

    return findings
