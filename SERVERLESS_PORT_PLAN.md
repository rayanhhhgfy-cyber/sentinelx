# SentinelX → Vercel Serverless Port Plan

Prepared 2026-10-17 by research (stage 1). rayan asked for a fully serverless
version of SentinelX so he can host it on Vercel (chat 2026-10-17 ~09:35 UTC).
The main agent promised the port after the 30+30 feature build lands.
This document is the blueprint the port build should follow — limits verified
against Vercel's current docs on 2026-10-17, not training data.

## 1. The real Vercel limits (verified 2026-10-17)

**The "10-second free tier" claim is outdated.** With Fluid Compute (on by
default since 2025), the limits are:

| Plan | Default | Maximum per invocation |
|------|---------|------------------------|
| Hobby (free) | 300s | **300s (5 minutes)** |
| Pro | 300s | **800s (~13 minutes)** |

Sources: https://vercel.com/changelog/higher-defaults-and-limits-for-vercel-functions-running-fluid-compute?ref=dailydev
(verified 2026-10-17); https://vercel.com/docs/limits/overview?query=reserve
(legacy 10s/60s table only applies to pre-April-2025 projects not on Fluid).

**Why this matters:** a 2–10 minute scan is NOT "hundreds of tiny chunks"
anymore. On Hobby, a full scan is **1 chunk for small targets, 2–4 chunks
for large ones**. The port is much more viable than the earlier 10s
assumption implied. Real remaining hard limits:

- **No WebSockets** on serverless functions — the live terminal at
  `/ws/scans/{id}` must become polling (endpoints already exist) or SSE.
- **No persistent disk** — SQLite gets wiped between invocations. Must
  move to an external DB.
- Python runtime IS supported (Fluid optimized concurrency covers
  Node.js + Python). FastAPI can be exported directly from `api/index.py`
  — Vercel's Python runtime serves ASGI apps.

## 2. Target architecture

- **Frontend** → Vercel static (Vite `dist/`). Perfect fit, no changes
  except API base URL / polling instead of WebSocket.
- **API** → single Python serverless function, `api/index.py` exporting
  the FastAPI `app` from `sentinelx/web/server.py`. `maxDuration: 300`
  on Hobby. All ~70 REST routes work unchanged (auth, scans CRUD,
  dashboard, findings, templates, targets, schedules, reports, exports,
  diff, comments, tags, SLA, accept-risk).
- **DB** → replace the `db()` sqlite3 helper with Postgres
  (Vercel Postgres via Neon, free tier) or Turso. ~15 tables, simple
  schema — mechanical port. Must be env-config driven, not file path.
- **Scan execution** → chunked step function:
  - `_run_scan_job` is refactored so one invocation runs one module-batch
    inside a ~240s budget, then writes a checkpoint
    (module index + per-module cursor + partial findings) to a job table.
  - Frontend polls `GET /api/scans/{scan_id}`; when status is
    `chunk_done`, it (or a cron tick) triggers the next chunk.
  - Pause/resume/cancel endpoints already exist — they map 1:1.
  - Timing-based modules (time-blind SQLi, request-smuggling timing
    probes) still work: their timing is relative within a chunk.
- **In-process scheduler** (`_scheduler_loop`, `_run_due_schedules`,
  `_expire_risk_acceptances`) → Vercel Cron hitting a `/api/cron/*`
  function. Scheduled scans and risk-acceptance expiry keep working.
- **Secrets** → `SENTINELX_FERNET_KEY` MUST be set in Vercel env vars.
  Today the code warns and generates an ephemeral key — on serverless
  that means stored auth-profile passwords silently break on every cold
  start. Make the port fail fast if the key is missing.

## 3. What stays identical (no changes needed)

- All 19 scanner modules (pure httpx/asyncio — runs fine serverless),
  31 encoding transforms, 25 WAF fingerprints, evidence/curl reproducers,
  CVSS/CWE/OWASP, JSON + HTML + SARIF reports (generated on demand via
  existing GET endpoints).

## 4. Verify-during-port (unknowns, do not assume)

1. The request-smuggling module opens raw asyncio TCP sockets. Outbound
   TCP generally works from serverless functions, but this must be proven
   with a real test, not assumed.
2. Hobby Vercel Cron allowance for the scheduler replacement.
3. SSE-vs-polling: test whether response streaming stays alive long
   enough to be worth it, or just poll every 2s.

## 5. Honest risks to tell rayan (say once, plainly)

1. **Scanning other people's sites from Vercel IPs** can trip Vercel's
   abuse detection and gets WAF-blocked more often (datacenter IPs).
   Gate web scans to his saved targets (`/api/targets` allowlist) —
   the same "only your own property" rule the CLI's `--confirm-own`
   enforces. Keep the CLI for anything else.
2. Hobby's 300s cap means very large scans take 2–4 chained chunks with
   checkpoint overhead — slower than the always-on backend, but real.
3. Hobby includes 1M function invocations/month — personal use is fine.
   Pro ($20/seat) buys 800s invocations for the biggest scans.

## 6. Proof plan (the assistant already promised this)

After the port: run a real scan against the local deliberately-vulnerable
target and compare findings parity with the local baseline (22 findings,
0 false positives on the hardened target). No green light until the
numbers match.
