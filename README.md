# 🛡 SentinelX — Web Vulnerability Scanner

A real, working web vulnerability scanner. Every module fires real HTTP requests.
Every finding carries raw request/response evidence, a confidence score, CVSS 3.1
vector, CWE/OWASP mapping, remediation steps, and a copy-paste curl reproducer.

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m sentinelx.cli --target http://localhost:5055 --confirm-own
```

Reports: `sentinelx-report.json` + `sentinelx-report.html`.

## Safety

- You must pass `--confirm-own` to confirm you own the target or have
  **explicit written permission** to test it. Without it, the scanner refuses.
- Safe mode is ON by default (no destructive payloads).
- Per-host rate limiting (default 10 req/s) avoids accidental DoS.
- Scope is enforced to the target domain unless `--allow-external`.

## Modules

| # | Module | Techniques |
|---|--------|-----------|
| 01 | SQLi | error-based (40+ DB signatures), boolean-blind (3-sample stats), time-blind (baseline-subtracted), UNION-based (column discovery + data extraction) |
| 02 | XSS | reflected with canary + HTML context detection (body/attr/script/URL) |
| 03 | Security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| 04 | Cookies | Secure, HttpOnly, SameSite flags |
| 05 | CORS | wildcard+credentials, origin reflection |
| 06 | HTTP methods | dangerous methods via OPTIONS |
| 07 | Open redirect | Location header, meta refresh, JS redirect |
| 08 | Dir bruteforce | 20+ sensitive paths |
| 09 | LFI / Path traversal | 250+ payloads, Linux/Windows/PHP wrappers, base64 detection |
| 10 | SSRF | internal IPs (decimal/hex/octal), cloud metadata, protocol smuggling |
| 11 | RCE / Command injection | output-based + time-blind with baseline subtraction |
| 12 | IDOR | numeric enumeration, path IDs, cross-session replay |
| 13 | JWT | alg:none, claim tampering, expired token |
| 14 | CSRF | token detection, entropy, Origin validation |
| 15 | Broken access control | forced browsing, method tampering, header bypasses |
| 16 | Secrets | 30+ patterns (AWS, GitHub, Stripe, private keys…) |
| 17 | Tech fingerprinting | Wappalyzer-style header/body detection |
| 18 | GraphQL | introspection, playground detection |
| 19 | HTTP Request Smuggling | CL.TE/TE.CL/TE.TE via raw sockets, timing-based detection |

Plus: 31 encoding transforms, WAF fingerprinting (25+), AI brain (optional),
SARIF export, webhook notifications.

Plus: async crawler (links, forms, JS endpoints, robots.txt), param extraction.

## Options

```
--target URL        target (required)
--confirm-own       authorization confirmation (required)
--concurrency N     default 30
--rate R            req/sec per host (default 10)
--depth D           crawl depth (default 2)
--timeout S         request timeout (default 15)
--json PATH         JSON report path
--html PATH         HTML report path
--sarif PATH        SARIF 2.1.0 report path (GitHub code scanning)
--unsafe            allow potentially destructive techniques
--oob-domain D      out-of-band callback domain
--lhost H --lport P  reverse-shell listener (prints one-liners)
--auth-a T --auth-b T  bearer tokens for cross-session IDOR tests
--webhook URL       notify webhook on completion
--webhook-kind K    slack | discord | generic
```

## Web UI

```bash
# install everything (scanner + web backend)
.venv/bin/pip install -r requirements.txt

# build the frontend (backend serves web/frontend/dist directly)
cd web/frontend && npm install && npm run build && cd ../..

# start the backend
.venv/bin/python -m sentinelx.web.run
# open http://127.0.0.1:8000
```

Full-stack web app: FastAPI backend (REST + WebSocket + SQLite + auth)
with a responsive SPA frontend — start scans, watch live findings stream,
browse reports, manage history. Register an account in the UI first.

## Test target

A deliberately vulnerable demo app lives in `target/app.py` (Flask).
Run it, then scan it to see real findings:

```bash
.venv/bin/python target/app.py &
.venv/bin/python -m sentinelx.cli --target http://127.0.0.1:5055 --confirm-own
```

Expected: 2 critical SQLi, 3 XSS, 1 open redirect, 5 header misconfigurations.

## Docker

```bash
docker build -t sentinelx .
docker run --rm sentinelx --target http://host.docker.internal:5055 --confirm-own
```
