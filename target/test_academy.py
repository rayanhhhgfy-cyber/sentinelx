"""Academy lab test harness: runs each module against planted vulns + safe variants.

Usage: .venv/bin/python target/test_academy.py
Lab must be running: .venv/bin/python target/academy_lab.py (port 5070)
"""
import asyncio
import sys

sys.path.insert(0, "/home/hatch/workspace/sentinelx")

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.modules import (
    sqli, xss, csrf, clickjack, xxe, ssrf, rce, ssti, lfi, idor,
    jwt, jwt_adv, cachepoison, deser, secrets, hostheader, ldap, xpath,
    nosqli, fileupload, authenum,
)
from sentinelx.modules import audit as audit_mod

BASE = "http://127.0.0.1:5070"

# (category, module_fn, method, url, params, expect_finding, extra_kwargs)
# extra_kwargs: "cors_url" for audit.scan_cors, "second" for stored xss
TESTS = [
    # SQLi
    ("sqli-error", sqli.scan_endpoint, "GET", f"{BASE}/lab/sqli_error", {"category": "x"}, True, {}),
    ("sqli-error-safe", sqli.scan_endpoint, "GET", f"{BASE}/lab/sqli_error_safe", {"category": "x"}, False, {}),
    ("sqli-union", sqli.scan_endpoint, "GET", f"{BASE}/lab/sqli_union", {"category": "x"}, True, {}),
    ("sqli-blind-bool", sqli.scan_endpoint, "GET", f"{BASE}/lab/sqli_blind", {"category": "gifts"}, True, {}),
    ("sqli-blind-time", sqli.scan_endpoint, "GET", f"{BASE}/lab/sqli_time", {"category": "x"}, True, {}),
    ("sqli-cookie", sqli.scan_endpoint, "GET", f"{BASE}/lab/sqli_cookie", {}, True, {"set_cookie_first": True}),
    # XSS
    ("xss-reflected", xss.scan_endpoint, "GET", f"{BASE}/lab/xss_ref", {"q": "x"}, True, {}),
    ("xss-reflected-safe", xss.scan_endpoint, "GET", f"{BASE}/lab/xss_ref_safe", {"q": "x"}, False, {}),
    # CSRF
    ("csrf", csrf.scan_endpoint, "POST", f"{BASE}/lab/csrf/email", {"email": "x"}, True, {}),
    # Clickjacking
    ("clickjack", clickjack.scan_endpoint, "GET", f"{BASE}/lab/clickjack", {}, True, {"own_target": True}),
    # CORS
    ("cors", audit_mod.scan_cors, "GET", f"{BASE}/lab/cors", {}, True, {"cors": True}),
    ("cors-safe", audit_mod.scan_cors, "GET", f"{BASE}/lab/cors_safe", {}, False, {"cors": True}),
    # XXE
    ("xxe", xxe.scan_endpoint, "POST", f"{BASE}/lab/xxe", {}, True, {}),
    # SSRF (regression)
    ("ssrf", ssrf.scan_endpoint, "GET", f"{BASE}/lab/ssrf", {"url": "http://example.com"}, True, {}),
    # RCE
    ("rce", rce.scan_endpoint, "GET", f"{BASE}/lab/rce", {"ip": "1.1.1.1"}, True, {}),
    # SSTI
    ("ssti", ssti.scan_endpoint, "GET", f"{BASE}/lab/ssti", {"name": "x"}, True, {}),
    # LFI
    ("lfi", lfi.scan_endpoint, "GET", f"{BASE}/lab/lfi", {"file": "x"}, True, {}),
    # IDOR real (user objects with emails)
    ("idor-real", idor.scan_endpoint, "GET", f"{BASE}/lab/api/users/2", {}, True, {}),
    # IDOR safe catalog (must NOT flag)
    ("idor-catalog-fp", idor.scan_endpoint, "GET", f"{BASE}/lab/product", {"productId": "1"}, False, {}),
    # JWT none
    ("jwt", jwt.scan_endpoint, "GET", f"{BASE}/lab/jwt", {"token": "x"}, True, {}),
    # Cache poisoning
    ("cachepoison", cachepoison.scan_endpoint, "GET", f"{BASE}/lab/cache", {}, True, {}),
    # Deserialization
    ("deser", deser.scan_endpoint, "POST", f"{BASE}/lab/deser", {"data": "x"}, True, {}),
    # Secrets / info disclosure
    ("secrets-debug", secrets.scan_endpoint, "GET", f"{BASE}/lab/debug", {}, True, {}),
    # Host header
    ("hostheader", hostheader.scan_endpoint, "POST", f"{BASE}/lab/reset", {}, True, {}),
    # LDAP
    ("ldap", ldap.scan_endpoint, "GET", f"{BASE}/lab/ldap", {"user": "x"}, True, {}),
    # XPath
    ("xpath", xpath.scan_endpoint, "GET", f"{BASE}/lab/xpath", {"q": "x"}, True, {}),
    # NoSQLi
    ("nosqli", nosqli.scan_endpoint, "POST", f"{BASE}/lab/nosql/login", {}, True, {}),
    # File upload
    ("fileupload", fileupload.scan_endpoint, "POST", f"{BASE}/lab/upload", {}, True, {}),
    # Auth enumeration
    ("authenum", authenum.scan_endpoint, "POST", f"{BASE}/lab/login", {"username": "x", "password": "x"}, True, {}),
    # Juice Shop: SQLi login bypass
    ("sqli-login-bypass", sqli.scan_endpoint, "POST", f"{BASE}/lab/login_sqli", {"username": "x", "password": "x"}, True, {}),
    # Juice Shop: basket IDOR (user data with emails)
    ("idor-basket", idor.scan_endpoint, "GET", f"{BASE}/lab/api/baskets/2", {}, True, {}),
    # Juice Shop: secrets in JS bundle
    ("secrets-js", secrets.scan_endpoint, "GET", f"{BASE}/lab/app.js", {}, True, {}),
    # Juice Shop: DOM XSS (static check via domxss module on the page)
]


async def run_one(client, config, name, fn, method, url, params, expect, extra):
    try:
        if extra.get("cors"):
            findings = await fn(client, config, url)
        elif extra.get("set_cookie_first"):
            # hit once to get the TrackingId cookie into the jar
            await client.get(url, dedupe=False)
            findings = await fn(client, config, method, url, params)
        elif extra.get("own_target"):
            # modules that only run on config.target (e.g. clickjack)
            cfg2 = ScanConfig(target=url)
            findings = await fn(client, cfg2, method, url, params)
        else:
            findings = await fn(client, config, method, url, params)
    except Exception as e:
        return name, expect, f"ERROR", f"{type(e).__name__}: {e}", False
    got = len(findings) > 0
    ok = got == expect
    detail = ""
    if findings:
        f = findings[0]
        detail = f"[{getattr(f, 'confidence_level', getattr(f, 'confidence', '?'))}] {f.subtype}"
    status = "PASS" if ok else "FAIL"
    return name, expect, status, detail, got


async def main():
    config = ScanConfig(target=BASE)
    async with ScanClient(config) as client:
        results = []
        for t in TESTS:
            r = await run_one(client, config, *t)
            results.append(r)
            name, expect, status, detail, got = r
            want = "FIND" if expect else "CLEAN"
            print(f"{status:4} {name:22} want={want:5} got={'FIND' if got else 'CLEAN':5} {detail}")

    npass = sum(1 for r in results if r[2] == "PASS")
    print(f"\n{npass}/{len(results)} passed")
    fails = [r[0] for r in results if r[2] != "PASS"]
    if fails:
        print("FAILURES:", ", ".join(fails))


if __name__ == "__main__":
    asyncio.run(main())
