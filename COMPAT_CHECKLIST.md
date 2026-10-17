# SentinelX Compatibility Checklist

Every existing vulnerability module MUST keep working after the jsruntime
upgrade. No module may be removed, weakened, renamed, or silently disabled.

Legend: [ ] = not yet verified · [✓] = verified working after changes

## Modules (32 files, ~40 vulnerability types)

| # | Module | Entry point(s) | Vulnerability types covered | Status |
|---|--------|----------------|-----------------------------|--------|
| 1 | `audit.py` | `scan_headers`, `scan_cookies`, `scan_cors`, `scan_methods` | Missing security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy, COEP/COOP/CORP), insecure cookie flags, permissive CORS, dangerous HTTP methods | [✓] |
| 2 | `bac.py` | `scan_target` | Broken access control, forced browsing, HTTP method override bypass | [~] |
| 3 | `blogic.py` | `scan_endpoint` | Business logic: price/quantity tampering, race conditions | [~] |
| 4 | `cachepoison.py` | `scan_endpoint` | Web cache poisoning | [~] |
| 5 | `clickjack.py` | `scan_endpoint` | Clickjacking (X-Frame-Options / frame-ancestors) | [~] |
| 6 | `crlf.py` | `scan_endpoint` | CRLF injection / HTTP response splitting | [~] |
| 7 | `csrf.py` | `scan_endpoint` | Cross-site request forgery (missing/invalid tokens) | [~] |
| 8 | `deser.py` | `scan_endpoint` | Insecure deserialization | [~] |
| 9 | `domxss.py` | `scan_endpoint` | DOM-based XSS (now js2py-powered) | [✓] |
| 10 | `graphql.py` | `scan_endpoint` | GraphQL introspection, query abuse | [~] |
| 11 | `header_rce.py` | `scan_endpoint` | Command injection via HTTP headers (User-Agent, Referer, X-Forwarded-For) | [~] |
| 12 | `hostheader.py` | `scan_endpoint` | Host header injection (password-reset poisoning, cache poisoning) | [~] |
| 13 | `idor.py` | `scan_endpoint` | Insecure direct object references (numeric, UUID, timestamp IDs) | [~] |
| 14 | `idor_api.py` | `scan_endpoint` | REST API IDOR / auth-bypass enumeration | [~] |
| 15 | `jsredirect.py` | `scan_endpoint` | JavaScript-based open redirect (javascript:/data: URLs) | [~] |
| 16 | `jwt.py` | `scan_endpoint` | JWT: alg=none, weak secrets, claim tampering | [~] |
| 17 | `jwt_adv.py` | `scan_endpoint` | JWT advanced: jwk confusion, kid path traversal | [~] |
| 18 | `ldap.py` | `scan_endpoint` | LDAP injection (error-based, boolean-blind) | [~] |
| 19 | `lfi.py` | `scan_endpoint` | Local file inclusion / path traversal | [~] |
| 20 | `probe.py` | `scan_openredirect`, `scan_dirfuzz` | Open redirect, directory bruteforce | [✓] |
| 21 | `proto_pollute.py` | `scan_endpoint` | JavaScript prototype pollution | [~] |
| 22 | `rce.py` | `scan_endpoint` | Remote code execution (error/time-based) | [~] |
| 23 | `secrets.py` | `scan_page`, `scan_endpoint` | Exposed secrets / API keys (30+ patterns) | [~] |
| 24 | `smuggling.py` | `scan_target` | HTTP request smuggling (CL.TE / TE.CL / TE.TE) | [~] |
| 25 | `sqli.py` | `scan_endpoint` | SQL injection (error, boolean-blind, time-blind, UNION, DNS OOB) | [✓] |
| 26 | `ssrf.py` | `scan_endpoint` | Server-side request forgery | [✓] |
| 27 | `ssti.py` | `scan_endpoint` | Server-side template injection | [~] |
| 28 | `takeover.py` | `scan_endpoint` | Subdomain takeover fingerprints | [~] |
| 29 | `techfp.py` | `fingerprint` | Technology fingerprinting (feeds smart payload tuning) | [~] |
| 30 | `xpath.py` | `scan_endpoint` | XPath injection (error-based, boolean-blind) | [~] |
| 31 | `xss.py` | `scan_endpoint`, `scan_second_order` | Reflected XSS, stored/second-order XSS | [✓] |
| 32 | `xxe.py` | `scan_endpoint` | XML external entity injection | [~] |

## Verification log

| Date | Module | Test | Result |
|------|--------|------|--------|
| 2026-10-17 | all 32 | import check | 32/32 import cleanly |
| 2026-10-17 | domxss | vuln page → CONFIRMED finding; safe page → 0 confirmed | PASS |
| 2026-10-17 | domxss | target/app.py (no DOM sinks) → 0 findings, no FP | PASS |
| 2026-10-17 | probe (openredirect) | vuln redirect → detected | PASS |
| 2026-10-17 | sqli, xss, audit, ssrf | targeted scan vs target/app.py → 36 findings | PASS |
| 2026-10-17 | models.Finding | backward compat (legacy confidence float) + new levels | PASS |
| 2026-10-17 | jsruntime | 22/22 unit tests (mock, executor, taint, instrument) | PASS |
| 2026-10-17 | cli | clean error when js2py hidden; normal start when present | PASS |

## Status key
- [✓] = verified working (import + functional test)
- [~] = import OK, logic untouched by this upgrade (no functional change)
