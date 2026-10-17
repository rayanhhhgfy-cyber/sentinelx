"""SentinelX web backend — FastAPI REST API + WebSocket + background scan jobs.

Run:  python -m sentinelx.web.run   (or uvicorn sentinelx.web.server:app)
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from sentinelx.core.http import ScanConfig, DEFAULT_UA
from sentinelx.core.models import Finding, Evidence
from sentinelx.engine import run_scan

# ---------------------------------------------------------------- logging

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
)
log = logging.getLogger("sentinelx.web")

# ---------------------------------------------------------------- paths / db

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "sentinelx.db"

_db_lock = threading.Lock()
_db: Optional[sqlite3.Connection] = None


def db() -> sqlite3.Connection:
    global _db
    if _db is None:
        _db = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _db.row_factory = sqlite3.Row
    return _db


def init_db():
    with _db_lock:
        c = db()
        c.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
            pw_hash TEXT NOT NULL, created_at REAL NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS scans(
            id TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
            target TEXT NOT NULL, status TEXT NOT NULL,
            config_json TEXT NOT NULL, created_at REAL NOT NULL,
            finished_at REAL, stats_json TEXT DEFAULT '{}')""")
        c.execute("""CREATE TABLE IF NOT EXISTS findings(
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
            finding_json TEXT NOT NULL)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")
        # role column (migration for existing DBs)
        try:
            c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'member'")
        except sqlite3.OperationalError:
            pass
        # ---- extended feature tables ----
        c.execute("""CREATE TABLE IF NOT EXISTS templates(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            name TEXT NOT NULL, description TEXT DEFAULT '',
            modules_json TEXT DEFAULT '[]', rate_limit REAL DEFAULT 10.0,
            created_at REAL NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS targets(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            url TEXT NOT NULL, name TEXT DEFAULT '', tags_json TEXT DEFAULT '[]',
            notes TEXT DEFAULT '', last_scan_at REAL, created_at REAL NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS schedules(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            target_id INTEGER, template_id INTEGER, cron_expr TEXT NOT NULL,
            enabled INTEGER DEFAULT 1, next_run_at REAL NOT NULL,
            created_at REAL NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS auth_profiles(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            name TEXT NOT NULL, login_url TEXT NOT NULL,
            username_field TEXT DEFAULT 'username', password_field TEXT DEFAULT 'password',
            username TEXT NOT NULL, password_enc TEXT NOT NULL,
            created_at REAL NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS finding_notes(
            id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL, note TEXT NOT NULL, created_at REAL NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS tags(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            name TEXT NOT NULL, color TEXT DEFAULT '#4ade80',
            created_at REAL NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS finding_tags(
            finding_id INTEGER NOT NULL, tag_id INTEGER NOT NULL,
            PRIMARY KEY (finding_id, tag_id))""")
        c.execute("""CREATE TABLE IF NOT EXISTS risk_acceptances(
            id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL, reason TEXT NOT NULL,
            expires_at REAL, created_at REAL NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS notification_channels(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            name TEXT NOT NULL, type TEXT NOT NULL,
            config_json TEXT DEFAULT '{}', events_json TEXT DEFAULT '[]',
            enabled INTEGER DEFAULT 1, created_at REAL NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS api_keys(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            name TEXT NOT NULL, prefix TEXT NOT NULL, key_hash TEXT NOT NULL,
            created_at REAL NOT NULL, last_used_at REAL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS audit_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
            action TEXT NOT NULL, entity TEXT DEFAULT '', entity_id TEXT DEFAULT '',
            detail TEXT DEFAULT '', at REAL NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS scan_comments(
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
            user_id INTEGER NOT NULL, comment TEXT NOT NULL,
            created_at REAL NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS scan_shares(
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
            user_id INTEGER NOT NULL, created_at REAL NOT NULL,
            UNIQUE(scan_id, user_id))""")
        c.execute("""CREATE TABLE IF NOT EXISTS engine_stats(
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
            module TEXT NOT NULL, requests INTEGER NOT NULL)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_templates_user ON templates(user_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_targets_user ON targets(user_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_notes_finding ON finding_notes(finding_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_comments_scan ON scan_comments(scan_id)")
        c.commit()
    log.info("database ready at %s", DB_PATH)


# ---------------------------------------------------------------- auth

TOKENS: dict[str, int] = {}  # token -> user_id


def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 200_000)
    return salt.hex() + "$" + h.hex()


def verify_pw(pw: str, stored: str) -> bool:
    try:
        salt_hex, h_hex = stored.split("$", 1)
        h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt_hex), 200_000)
        return hmac.compare_digest(h.hex(), h_hex)
    except Exception:
        return False


def db_create_user(email: str, name: str, pw: str, role: str = "member") -> dict:
    with _db_lock:
        c = db()
        try:
            # first registered user becomes admin (bootstrap)
            n = c.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
            use_role = "admin" if n == 0 else role
            cur = c.execute(
                "INSERT INTO users(email,name,pw_hash,created_at,role) VALUES(?,?,?,?,?)",
                (email.lower().strip(), name.strip(), hash_pw(pw), time.time(), use_role))
            c.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(400, "email already registered")
        uid = cur.lastrowid
        row = c.execute("SELECT id,email,name,created_at,role FROM users WHERE id=?", (uid,)).fetchone()
        return dict(row)


def db_get_user(uid: int) -> Optional[dict]:
    with _db_lock:
        row = db().execute(
            "SELECT id,email,name,created_at,role FROM users WHERE id=?", (uid,)).fetchone()
        return dict(row) if row else None


def db_get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with _db_lock:
        return db().execute(
            "SELECT * FROM users WHERE email=?", (email.lower().strip(),)).fetchone()


def new_token(uid: int) -> str:
    tok = secrets.token_urlsafe(32)
    TOKENS[tok] = uid
    return tok


async def current_user(request: Request) -> dict:
    # API-key auth takes precedence when the header is present
    api_key = request.headers.get("x-api-key", "").strip()
    if api_key:
        user = db_user_by_api_key(api_key)
        if not user:
            raise HTTPException(401, "invalid API key")
        return user
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    uid = TOKENS.get(auth[7:].strip())
    if not uid:
        raise HTTPException(401, "invalid or expired token")
    user = db_get_user(uid)
    if not user:
        raise HTTPException(401, "user not found")
    return user


def db_user_by_api_key(raw_key: str) -> Optional[dict]:
    import hashlib as _h
    digest = _h.sha256(raw_key.encode()).hexdigest()
    with _db_lock:
        c = db()
        row = c.execute("SELECT user_id, id FROM api_keys WHERE key_hash=?", (digest,)).fetchone()
        if not row:
            return None
        c.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (time.time(), row["id"]))
        c.commit()
        u = c.execute("SELECT id,email,name,created_at,role FROM users WHERE id=?",
                      (row["user_id"],)).fetchone()
        return dict(u) if u else None


def _user_role(user: dict) -> str:
    return user.get("role") or "member"


def _require_scan_write(user: dict):
    if _user_role(user) not in ("admin", "member"):
        raise HTTPException(403, "viewers cannot modify scans")


def _require_admin(user: dict):
    if _user_role(user) != "admin":
        raise HTTPException(403, "admin only")


def ws_token(ws: WebSocket) -> int:
    tok = ws.query_params.get("token", "")
    uid = TOKENS.get(tok)
    if not uid:
        raise HTTPException(401, "invalid token")
    return uid


# ---------------------------------------------------------------- scan store

def db_create_scan(scan_id: str, user_id: int, target: str, config: dict) -> None:
    with _db_lock:
        db().execute(
            "INSERT INTO scans(id,user_id,target,status,config_json,created_at) VALUES(?,?,?,?,?,?)",
            (scan_id, user_id, target, "queued", json.dumps(config), time.time()))
        db().commit()


def db_set_scan_status(scan_id: str, status: str, stats: Optional[dict] = None) -> None:
    with _db_lock:
        c = db()
        if stats is not None:
            c.execute("UPDATE scans SET status=?, finished_at=?, stats_json=? WHERE id=?",
                      (status, time.time(), json.dumps(stats), scan_id))
        else:
            c.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))
        c.commit()


def db_get_scan(scan_id: str) -> Optional[dict]:
    with _db_lock:
        row = db().execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None


def db_list_scans(user_id: int) -> list[dict]:
    with _db_lock:
        rows = db().execute(
            """SELECT * FROM scans WHERE user_id=?
               UNION
               SELECT s.* FROM scans s JOIN scan_shares sh ON sh.scan_id=s.id
               WHERE sh.user_id=?
               ORDER BY created_at DESC""", (user_id, user_id)).fetchall()
        return [dict(r) for r in rows]


def db_delete_scan(scan_id: str) -> None:
    with _db_lock:
        c = db()
        c.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        c.commit()


def db_add_finding(scan_id: str, finding_dict: dict) -> int:
    with _db_lock:
        c = db()
        fd = dict(finding_dict)
        fd.setdefault("status", "open")
        cur = c.execute("INSERT INTO findings(scan_id,finding_json) VALUES(?,?)",
                        (scan_id, json.dumps(fd)))
        c.commit()
        return cur.lastrowid


def db_list_findings(scan_id: str) -> list[dict]:
    with _db_lock:
        rows = db().execute(
            "SELECT id, finding_json FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        out = []
        for r in rows:
            d = json.loads(r["finding_json"])
            d["_db_id"] = r["id"]
            out.append(d)
        return out


def db_patch_finding(db_id: int, false_positive: bool) -> Optional[dict]:
    with _db_lock:
        c = db()
        row = c.execute("SELECT finding_json FROM findings WHERE id=?", (db_id,)).fetchone()
        if not row:
            return None
        d = json.loads(row["finding_json"])
        d["false_positive"] = bool(false_positive)
        # keep the status workflow consistent with the legacy flag
        if false_positive:
            d["status"] = "false_positive"
        elif d.get("status") == "false_positive":
            d["status"] = "open"
        if "status" not in d:
            d["status"] = "open"
        c.execute("UPDATE findings SET finding_json=? WHERE id=?", (json.dumps(d), db_id))
        c.commit()
        d["_db_id"] = db_id
        return d


def db_update_finding_json(db_id: int, d: dict) -> None:
    with _db_lock:
        db().execute("UPDATE findings SET finding_json=? WHERE id=?",
                     (json.dumps(d), db_id))
        db().commit()


def db_get_finding(db_id: int) -> Optional[dict]:
    with _db_lock:
        row = db().execute("SELECT id, finding_json FROM findings WHERE id=?", (db_id,)).fetchone()
        if not row:
            return None
        d = json.loads(row["finding_json"])
        d["_db_id"] = row["id"]
        return d


def _finding_scan_owner(db_id: int) -> Optional[str]:
    with _db_lock:
        row = db().execute("SELECT scan_id FROM findings WHERE id=?", (db_id,)).fetchone()
        return row["scan_id"] if row else None


def _require_finding(db_id: int, user_id: int) -> dict:
    scan_id = _finding_scan_owner(db_id)
    if not scan_id:
        raise HTTPException(404, "finding not found")
    _require_scan(scan_id, user_id)
    d = db_get_finding(db_id)
    if not d:
        raise HTTPException(404, "finding not found")
    return d


def _finding_from_dict(d: dict) -> Finding:
    ev = d.get("evidence") or {}
    return Finding(
        id=d.get("id", ""), type=d.get("type", ""), subtype=d.get("subtype", ""),
        severity=d.get("severity", "info"), cvss_vector=d.get("cvss_vector", ""),
        cvss_score=d.get("cvss_score", 0.0), confidence=d.get("confidence", 0.0),
        url=d.get("url", ""), method=d.get("method", "GET"), param=d.get("param", ""),
        payload=d.get("payload", ""),
        evidence=Evidence(request_raw=ev.get("request_raw", ""),
                          response_raw=ev.get("response_raw", ""),
                          proof=ev.get("proof", "")),
        cwe=d.get("cwe", ""), owasp=d.get("owasp", ""), remediation=d.get("remediation", ""),
        references=d.get("references", []), curl_command=d.get("curl_command", ""),
        timestamp=d.get("timestamp", 0.0),
    )


def _dedup_key_of(d: dict) -> str:
    import hashlib as _h
    return _h.sha256(
        f"{d.get('type','')}|{d.get('subtype','')}|{d.get('method','')}|"
        f"{d.get('url','')}|{d.get('param','')}".encode()).hexdigest()[:16]


def _is_excluded(f: dict) -> bool:
    """A finding is excluded from counts/reports when marked false positive
    (flag or status) or when a risk acceptance is currently valid."""
    if f.get("false_positive"):
        return True
    if (f.get("status") or "open") == "false_positive":
        return True
    ra = f.get("risk_accepted")
    if isinstance(ra, dict):
        exp = ra.get("expires_at")
        if exp is None or exp > time.time():
            return True
    return False


def _severity_counts(findings: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if _is_excluded(f):
            continue
        s = f.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1
    return counts


def _scan_summary(row: dict) -> dict:
    findings = db_list_findings(row["id"])
    stats = json.loads(row.get("stats_json") or "{}")
    return {
        "id": row["id"], "target": row["target"], "status": row["status"],
        "created_at": row["created_at"], "finished_at": row.get("finished_at"),
        "counts": _severity_counts(findings),
        "total_findings": len(findings),
        "requests": stats.get("requests", 0),
    }


# ---------------------------------------------------------------- background scans

SCANS: dict[str, dict] = {}  # scan_id -> {task, queue, events, status, ...}


SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}


async def _run_scan_job(scan_id: str, user_id: int, target: str, cfg: dict):
    state = SCANS.get(scan_id)
    if not state:
        return
    queue: asyncio.Queue = state["queue"]
    stats_bucket: dict = {}
    config = ScanConfig(
        target=target,
        concurrency=cfg.get("concurrency", 30),
        rate_per_sec=cfg.get("rate", 10.0),
        crawl_depth=cfg.get("depth", 2),
        timeout=cfg.get("timeout", 15.0),
        safe_mode=cfg.get("safe_mode", True),
        user_agent=cfg.get("user_agent") or DEFAULT_UA,
        modules=cfg.get("modules") or [],
        custom_headers=cfg.get("custom_headers") or {},
        custom_cookies=cfg.get("custom_cookies") or {},
        exclude_paths=cfg.get("exclude_paths") or [],
        pause_event=state.get("pause_event"),
        stats=stats_bucket,
    )

    def emit_event(ev: dict):
        state["events"].append(ev)
        if len(state["events"]) > 500:
            state["events"] = state["events"][-500:]
        queue.put_nowait(ev)

    def on_finding(f: Finding):
        fd = f.to_dict()
        db_id = db_add_finding(scan_id, fd)
        fd["_db_id"] = db_id
        state["findings"].append(fd)
        emit_event({"type": "finding", "data": {
            "id": f.id, "db_id": db_id, "type": f.type, "subtype": f.subtype,
            "severity": f.severity, "cvss_score": f.cvss_score,
            "confidence": f.confidence, "url": f.url, "method": f.method,
            "param": f.param,
        }})

    def on_progress(msg: str):
        emit_event({"type": "progress", "data": msg})
        if msg.startswith("done:"):
            try:
                parts = msg.split(",")
                req = int(parts[1].strip().split()[0])
                state["stats"]["requests"] = req
            except Exception:
                pass

    # authenticated scans: perform the profile login first, reuse its cookies
    if cfg.get("auth_profile_id"):
        try:
            prof_cookies = await _profile_login(user_id, int(cfg["auth_profile_id"]))
            if prof_cookies:
                merged = dict(config.custom_cookies or {})
                merged.update(prof_cookies)
                config.custom_cookies = merged
                emit_event({"type": "progress",
                            "data": "auth profile login ok, session cookies captured"})
        except Exception as e:  # noqa: BLE001
            emit_event({"type": "progress",
                        "data": f"auth profile login failed: {str(e)[:200]}"})
            log.warning("scan %s auth profile login failed: %s", scan_id, e)

    db_set_scan_status(scan_id, "running")
    state["status"] = "running"
    emit_event({"type": "progress", "data": f"scan started: {target}"})
    try:
        findings = await run_scan(config, on_finding=on_finding, on_progress=on_progress)
        finished = time.time()
        stats = {"requests": state["stats"].get("requests", 0),
                 "counts": _severity_counts(state["findings"])}
        db_set_scan_status(scan_id, "completed", stats)
        state["status"] = "completed"
        state["stats"].update(stats)
        # SLA due dates + engine stats, persisted for the API
        _apply_sla_and_stats(scan_id, state["findings"], finished, stats_bucket)
        emit_event({"type": "done", "data": {"status": "completed",
                                             "findings": len(findings)}})
        log.info("scan %s completed: %d findings", scan_id, len(findings))
        await _fire_notifications(user_id, "scan_completed", {
            "scan_id": scan_id, "target": target,
            "findings": len(findings), "counts": stats["counts"],
        })
    except asyncio.CancelledError:
        db_set_scan_status(scan_id, "cancelled")
        state["status"] = "cancelled"
        emit_event({"type": "done", "data": {"status": "cancelled"}})
        log.info("scan %s cancelled", scan_id)
        raise
    except Exception as e:  # noqa: BLE001
        db_set_scan_status(scan_id, "failed", {"error": str(e)[:500]})
        state["status"] = "failed"
        emit_event({"type": "done", "data": {"status": "failed", "error": str(e)[:500]}})
        log.error("scan %s failed: %s", scan_id, e)
        await _fire_notifications(user_id, "scan_failed", {
            "scan_id": scan_id, "target": target, "error": str(e)[:500],
        })


def _apply_sla_and_stats(scan_id: str, findings: list[dict], finished_at: float,
                         stats_bucket: dict):
    """Stamp SLA due dates on fresh findings; persist per-module request stats."""
    for fd in findings:
        db_id = fd.get("_db_id")
        if not db_id:
            continue
        days = SLA_DAYS.get((fd.get("severity") or "info").lower())
        if days:
            fd["sla_due_at"] = finished_at + days * 86400
        if "status" not in fd:
            fd["status"] = "open"
        db_update_finding_json(db_id, fd)
    modules = (stats_bucket or {}).get("modules") or {}
    if modules:
        with _db_lock:
            c = db()
            c.execute("DELETE FROM engine_stats WHERE scan_id=?", (scan_id,))
            for mod, req in modules.items():
                c.execute("INSERT INTO engine_stats(scan_id,module,requests) VALUES(?,?,?)",
                          (scan_id, mod, int(req)))
            c.commit()


# ---------------------------------------------------------------- auth profiles (Fernet)

_FERNET = None


def _fernet():
    global _FERNET
    if _FERNET is not None:
        return _FERNET
    from cryptography.fernet import Fernet
    key = os.environ.get("SENTINELX_FERNET_KEY", "")
    if not key:
        key = Fernet.generate_key().decode()
        log.warning("SENTINELX_FERNET_KEY not set — generated ephemeral key; "
                    "stored auth-profile passwords will not survive restarts")
    _FERNET = Fernet(key.encode() if isinstance(key, str) else key)
    return _FERNET


async def _profile_login(user_id: int, profile_id: int) -> dict:
    """POST the profile credentials to its login_url; return session cookies."""
    import httpx
    with _db_lock:
        row = db().execute(
            "SELECT * FROM auth_profiles WHERE id=? AND user_id=?",
            (profile_id, user_id)).fetchone()
    if not row:
        raise ValueError("auth profile not found")
    password = _fernet().decrypt(row["password_enc"].encode()).decode()
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True,
                                  trust_env=False) as cli:
        r = await cli.post(row["login_url"], data={
            row["username_field"]: row["username"],
            row["password_field"]: password,
        })
        log.info("auth profile '%s' login -> %s", row["name"], r.status_code)
        return dict(r.cookies)


# ---------------------------------------------------------------- notifications

async def _fire_notifications(user_id: int, event: str, payload: dict):
    with _db_lock:
        rows = db().execute(
            "SELECT * FROM notification_channels WHERE user_id=? AND enabled=1",
            (user_id,)).fetchall()
    for row in rows:
        try:
            events = json.loads(row["events_json"] or "[]")
        except Exception:
            events = []
        if events and event not in events:
            continue
        try:
            cfg = json.loads(row["config_json"] or "{}")
            await _send_notification(row["type"], cfg, event, payload)
        except Exception as e:  # noqa: BLE001
            log.warning("notification %s failed: %s", row["name"], e)


async def _send_notification(kind: str, cfg: dict, event: str, payload: dict):
    import httpx
    text = f"SentinelX: {event} — target {payload.get('target')} " \
           f"({payload.get('findings', '?')} findings)"
    if kind == "email":
        import smtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = f"[SentinelX] {event}"
        msg["From"] = cfg["from_addr"]
        msg["To"] = ", ".join(cfg["to_addrs"])
        msg.set_content(text + "\n\n" + json.dumps(payload, indent=2))
        with smtplib.SMTP(cfg.get("smtp_host", "localhost"),
                          int(cfg.get("smtp_port", 587)), timeout=15) as s:
            if cfg.get("use_tls", True):
                s.starttls()
            if cfg.get("username"):
                s.login(cfg["username"], cfg.get("password", ""))
            s.send_message(msg)
    elif kind == "slack":
        async with httpx.AsyncClient(timeout=15, trust_env=False) as cli:
            r = await cli.post(cfg["webhook_url"], json={"text": text})
            r.raise_for_status()
    elif kind == "discord":
        async with httpx.AsyncClient(timeout=15, trust_env=False) as cli:
            r = await cli.post(cfg["webhook_url"], json={"content": text})
            r.raise_for_status()
    elif kind == "webhook":
        async with httpx.AsyncClient(timeout=15, trust_env=False) as cli:
            r = await cli.post(cfg["url"], json={"event": event, "payload": payload},
                               headers=cfg.get("headers") or {})
            r.raise_for_status()
    else:
        raise ValueError(f"unknown channel type: {kind}")


# ---------------------------------------------------------------- cron

def _cron_next(expr: str, after_ts: float) -> float:
    """Next run timestamp for a 5-field cron expr after `after_ts`."""
    import datetime as _dt
    fields = expr.strip().split()
    if len(fields) != 5:
        raise ValueError("cron expression needs 5 fields (min hour dom month dow)")

    def parse_field(f: str, lo: int, hi: int) -> set[int]:
        vals: set[int] = set()
        for part in f.split(","):
            if part == "*":
                vals.update(range(lo, hi + 1))
            elif "/" in part:
                base, step = part.split("/", 1)
                step = int(step)
                r = range(lo, hi + 1) if base == "*" else range(int(base), hi + 1)
                vals.update(x for x in r if (x - lo) % step == 0)
            elif "-" in part:
                a, b = part.split("-", 1)
                vals.update(range(int(a), int(b) + 1))
            else:
                vals.add(int(part))
        return {v for v in vals if lo <= v <= hi}

    mins = parse_field(fields[0], 0, 59)
    hours = parse_field(fields[1], 0, 23)
    doms = parse_field(fields[2], 1, 31)
    months = parse_field(fields[3], 1, 12)
    dows = parse_field(fields[4], 0, 6)  # 0=Sunday
    if not all([mins, hours, doms, months, dows]):
        raise ValueError("cron expression matches nothing")
    dt = _dt.datetime.fromtimestamp(after_ts).replace(second=0, microsecond=0)
    for _ in range(525600):  # up to ~1 year of minutes
        dt += _dt.timedelta(minutes=1)
        dow = (dt.isoweekday() % 7)  # Monday=1..Sunday=0
        if (dt.minute in mins and dt.hour in hours and dt.day in doms
                and dt.month in months and dow in dows):
            return dt.timestamp()
    raise ValueError("no cron run found within a year")


async def _run_due_schedules():
    """Launch scans for enabled schedules whose next_run_at has passed."""
    now = time.time()
    with _db_lock:
        rows = db().execute(
            "SELECT * FROM schedules WHERE enabled=1 AND next_run_at<=?",
            (now,)).fetchall()
    for row in rows:
        try:
            with _db_lock:
                tgt = db().execute("SELECT url FROM targets WHERE id=?",
                                   (row["target_id"],)).fetchone() if row["target_id"] else None
            if not tgt:
                continue
            cfg: dict = {"concurrency": 30, "rate": 10.0, "depth": 2,
                         "timeout": 15.0, "safe_mode": True}
            if row["template_id"]:
                with _db_lock:
                    t = db().execute("SELECT * FROM templates WHERE id=?",
                                     (row["template_id"],)).fetchone()
                if t:
                    cfg["modules"] = json.loads(t["modules_json"] or "[]")
                    cfg["rate"] = t["rate_limit"] or 10.0
            _launch_scan(row["user_id"], tgt["url"], cfg)
            nxt = _cron_next(row["cron_expr"], now)
            with _db_lock:
                db().execute("UPDATE schedules SET next_run_at=? WHERE id=?", (nxt, row["id"]))
                db().commit()
            _audit(row["user_id"], "schedule_run", "schedule", str(row["id"]),
                   f"target={tgt['url']}")
            log.info("scheduled scan launched for %s", tgt["url"])
        except Exception as e:  # noqa: BLE001
            log.warning("schedule %s failed: %s", row["id"], e)


def _expire_risk_acceptances():
    now = time.time()
    with _db_lock:
        c = db()
        rows = c.execute(
            "SELECT id, finding_id FROM risk_acceptances WHERE expires_at IS NOT NULL"
            " AND expires_at<=?", (now,)).fetchall()
        for r in rows:
            c.execute("DELETE FROM risk_acceptances WHERE id=?", (r["id"],))
            fr = c.execute("SELECT finding_json FROM findings WHERE id=?",
                           (r["finding_id"],)).fetchone()
            if fr:
                d = json.loads(fr["finding_json"])
                d.pop("risk_accepted", None)
                c.execute("UPDATE findings SET finding_json=? WHERE id=?",
                          (json.dumps(d), r["finding_id"]))
        if rows:
            c.commit()
            log.info("expired %d risk acceptances", len(rows))


async def _scheduler_loop():
    while True:
        try:
            await _run_due_schedules()
            _expire_risk_acceptances()
        except Exception as e:  # noqa: BLE001
            log.warning("scheduler tick failed: %s", e)
        await asyncio.sleep(60)


def _launch_scan(user_id: int, target: str, cfg: dict) -> str:
    scan_id = secrets.token_hex(8)
    db_create_scan(scan_id, user_id, target, cfg)
    pause_event = asyncio.Event()
    pause_event.set()
    SCANS[scan_id] = {
        "task": None, "queue": asyncio.Queue(), "events": [],
        "status": "queued", "findings": [], "stats": {},
        "target": target, "config": cfg, "user_id": user_id,
        "pause_event": pause_event,
    }
    SCANS[scan_id]["task"] = asyncio.create_task(_run_scan_job(scan_id, user_id, target, cfg))
    log.info("scan %s queued for %s", scan_id, target)
    # keep saved-target bookkeeping fresh
    with _db_lock:
        db().execute("UPDATE targets SET last_scan_at=? WHERE user_id=? AND url=?",
                     (time.time(), user_id, target))
        db().commit()
    return scan_id


def _require_scan(scan_id: str, user_id: int) -> dict:
    row = db_get_scan(scan_id)
    if not row:
        raise HTTPException(404, "scan not found")
    if row["user_id"] == user_id:
        return row
    with _db_lock:
        sh = db().execute("SELECT id FROM scan_shares WHERE scan_id=? AND user_id=?",
                          (scan_id, user_id)).fetchone()
    if not sh:
        raise HTTPException(404, "scan not found")
    return row


def _audit(user_id: Optional[int], action: str, entity: str = "",
           entity_id: str = "", detail: str = ""):
    try:
        with _db_lock:
            db().execute(
                "INSERT INTO audit_log(user_id,action,entity,entity_id,detail,at)"
                " VALUES(?,?,?,?,?,?)",
                (user_id, action, entity, entity_id, detail[:1000], time.time()))
            db().commit()
    except Exception as e:  # noqa: BLE001
        log.warning("audit log failed: %s", e)


# ---------------------------------------------------------------- app

app = FastAPI(title="SentinelX API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)


@app.on_event("startup")
async def _startup():
    init_db()
    app.state.scheduler_task = asyncio.create_task(_scheduler_loop())
    log.info("scheduler loop started")


@app.on_event("shutdown")
async def _shutdown():
    task = getattr(app.state, "scheduler_task", None)
    if task:
        task.cancel()


_START_TIME = time.time()


# ---------------------------------------------------------------- pydantic in/out

class RegisterIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=8, max_length=256)


class LoginIn(BaseModel):
    email: str
    password: str


RATE_PROFILES = {"polite": 2.0, "normal": 10.0, "aggressive": 50.0}


class ScanStartIn(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    confirm_own: bool = False
    concurrency: int = Field(default=30, ge=1, le=100)
    rate: float = Field(default=10.0, ge=0.5, le=200.0)
    depth: int = Field(default=2, ge=0, le=5)
    timeout: float = Field(default=15.0, ge=5.0, le=120.0)
    safe_mode: bool = True
    # extended config
    template_id: Optional[int] = None
    rate_limit_profile: Optional[str] = None
    modules: Optional[list[str]] = None
    custom_headers: Optional[dict[str, str]] = None
    custom_cookies: Optional[dict[str, str]] = None
    user_agent: Optional[str] = None
    exclude_paths: Optional[list[str]] = None
    auth_profile_id: Optional[int] = None


class FindingPatchIn(BaseModel):
    false_positive: bool


def _validate_target(target: str) -> str:
    t = target.strip()
    u = urlsplit(t)
    if u.scheme not in ("http", "https") or not u.netloc:
        raise HTTPException(400, "target must be an http(s) URL")
    return t


# ---------------------------------------------------------------- misc

@app.get("/api/health")
async def health():
    try:
        db_bytes = DB_PATH.stat().st_size
    except OSError:
        db_bytes = 0
    return {"status": "ok", "version": "1.0.0",
            "uptime_sec": round(time.time() - _START_TIME, 1),
            "db_bytes": db_bytes}


@app.get("/api/version")
async def version():
    return {"version": "1.0.0", "name": "SentinelX"}


# ---------------------------------------------------------------- auth routes

@app.post("/api/auth/register")
async def register(body: RegisterIn):
    if "@" not in body.email or "." not in body.email.split("@")[-1]:
        raise HTTPException(400, "invalid email address")
    user = db_create_user(body.email, body.name, body.password)
    token = new_token(user["id"])
    _audit(user["id"], "register", "user", str(user["id"]), f"email={user['email']}")
    log.info("user registered: %s", user["email"])
    return {"token": token, "user": user}


@app.post("/api/auth/login")
async def login(body: LoginIn):
    row = db_get_user_by_email(body.email)
    if not row or not verify_pw(body.password, row["pw_hash"]):
        raise HTTPException(401, "invalid email or password")
    user = db_get_user(row["id"])
    token = new_token(user["id"])
    _audit(user["id"], "login", "user", str(user["id"]), "")
    log.info("user login: %s", user["email"])
    return {"token": token, "user": user}


@app.post("/api/auth/logout")
async def logout(request: Request):
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        TOKENS.pop(auth[7:].strip(), None)
    return {}


@app.get("/api/auth/me")
async def me(request: Request):
    return await current_user(request)


# ---------------------------------------------------------------- scans

@app.post("/api/scans", status_code=201)
async def start_scan(body: ScanStartIn, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    if not body.confirm_own:
        raise HTTPException(400, "confirm_own must be true: only scan targets you own or have written permission to test")
    target = _validate_target(body.target)
    cfg = {"concurrency": body.concurrency, "rate": body.rate, "depth": body.depth,
           "timeout": body.timeout, "safe_mode": body.safe_mode}
    # template presets
    if body.template_id:
        with _db_lock:
            t = db().execute("SELECT * FROM templates WHERE id=? AND user_id=?",
                             (body.template_id, user["id"])).fetchone()
        if not t:
            raise HTTPException(404, "template not found")
        cfg["modules"] = json.loads(t["modules_json"] or "[]")
        cfg["rate"] = t["rate_limit"] or cfg["rate"]
        cfg["template_id"] = body.template_id
    # rate-limit presets (explicit profile wins)
    if body.rate_limit_profile:
        if body.rate_limit_profile not in RATE_PROFILES:
            raise HTTPException(400, f"unknown rate_limit_profile, choose from {sorted(RATE_PROFILES)}")
        cfg["rate"] = RATE_PROFILES[body.rate_limit_profile]
        cfg["rate_limit_profile"] = body.rate_limit_profile
    if body.modules is not None:
        cfg["modules"] = body.modules
    if body.custom_headers:
        cfg["custom_headers"] = dict(body.custom_headers)
    if body.custom_cookies:
        cfg["custom_cookies"] = dict(body.custom_cookies)
    if body.user_agent:
        cfg["user_agent"] = body.user_agent[:500]
    if body.exclude_paths:
        cfg["exclude_paths"] = [p for p in body.exclude_paths if p.startswith("/")]
    if body.auth_profile_id:
        with _db_lock:
            ap = db().execute("SELECT id FROM auth_profiles WHERE id=? AND user_id=?",
                              (body.auth_profile_id, user["id"])).fetchone()
        if not ap:
            raise HTTPException(404, "auth profile not found")
        cfg["auth_profile_id"] = body.auth_profile_id
    scan_id = _launch_scan(user["id"], target, cfg)
    _audit(user["id"], "scan_create", "scan", scan_id, f"target={target}")
    return {"scan_id": scan_id, "status": "queued"}


@app.get("/api/scans")
async def list_scans(request: Request):
    user = await current_user(request)
    return [_scan_summary(r) for r in db_list_scans(user["id"])]


@app.get("/api/dashboard/stats")
async def dashboard_stats(request: Request):
    """Real aggregated stats from the database — no mock data."""
    import json as _json
    user = await current_user(request)
    uid = user["id"]
    scans = db_list_scans(uid)
    total_scans = len(scans)
    active = sum(1 for s in scans if s["status"] in ("running", "queued"))
    completed = sum(1 for s in scans if s["status"] == "done")
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    open_findings = 0
    recent_findings = []
    for s in scans:
        for fr in db_list_findings(s["id"]):
            try:
                f = _json.loads(fr["finding_json"])
            except Exception:
                continue
            sev = (f.get("severity") or "info").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
            if not f.get("false_positive"):
                open_findings += 1
            recent_findings.append({
                "id": f.get("id"), "type": f.get("type"), "severity": sev,
                "url": f.get("url"), "scan_id": s["id"], "target": s["target"],
                "timestamp": f.get("timestamp", 0),
            })
    recent_findings.sort(key=lambda x: x["timestamp"] or 0, reverse=True)
    # security posture score: weighted by severity
    weights = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
    deduction = sum(sev_counts[k] * weights[k] for k in weights)
    score = max(0, 100 - deduction)
    recent_scans = [_scan_summary(s) for s in scans[:5]]
    return {
        "total_scans": total_scans,
        "active_scans": active,
        "completed_scans": completed,
        "open_findings": open_findings,
        "severity_counts": sev_counts,
        "security_score": score,
        "recent_scans": recent_scans,
        "recent_findings": recent_findings[:8],
    }


@app.get("/api/scans/compare")
async def compare_scans(request: Request, ids: str = Query(min_length=1)):
    user = await current_user(request)
    scan_ids = [s.strip() for s in ids.split(",") if s.strip()][:10]
    if len(scan_ids) < 2:
        raise HTTPException(400, "provide at least 2 scan ids")
    rows = []
    for sid in scan_ids:
        rows.append(_require_scan(sid, user["id"]))
    rows.sort(key=lambda r: r["created_at"])
    keysets = []
    for r in rows:
        ks = {_dedup_key_of(f): f for f in db_list_findings(r["id"])
              if not _is_excluded(f)}
        keysets.append(ks)
    all_keys = set().union(*[set(k) for k in keysets]) if keysets else set()
    persisting = [keysets[-1][k] for k in all_keys
                  if all(k in ks for ks in keysets)]
    first, last = keysets[0], keysets[-1]
    fixed = [first[k] for k in first if k not in last]
    new_by_scan: dict[str, list] = {}
    seen: set[str] = set()
    for r, ks in zip(rows, keysets):
        new_by_scan[r["id"]] = [ks[k] for k in ks if k not in seen]
        seen.update(ks.keys())
    return {"scans": [{"id": r["id"], "target": r["target"],
                       "created_at": r["created_at"]} for r in rows],
            "new_by_scan": new_by_scan, "fixed": fixed,
            "persisting": persisting}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, request: Request):
    user = await current_user(request)
    row = _require_scan(scan_id, user["id"])
    summary = _scan_summary(row)
    summary["findings"] = db_list_findings(scan_id)
    summary["config"] = json.loads(row["config_json"])
    return summary


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    _require_scan(scan_id, user["id"])
    state = SCANS.pop(scan_id, None)
    if state and state.get("task") and not state["task"].done():
        state["task"].cancel()
    db_delete_scan(scan_id)
    _audit(user["id"], "scan_delete", "scan", scan_id, "")
    log.info("scan %s deleted", scan_id)
    return {"deleted": True}


@app.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    _require_scan(scan_id, user["id"])
    state = SCANS.get(scan_id)
    if not state or not state.get("task") or state["task"].done():
        raise HTTPException(400, "scan is not running")
    state["task"].cancel()
    _audit(user["id"], "scan_cancel", "scan", scan_id, "")
    return {"cancelled": True}


@app.post("/api/scans/{scan_id}/pause")
async def pause_scan(scan_id: str, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    _require_scan(scan_id, user["id"])
    state = SCANS.get(scan_id)
    if not state or state.get("status") != "running":
        raise HTTPException(400, "scan is not running")
    ev: asyncio.Event = state.get("pause_event")
    if ev is None or not ev.is_set():
        raise HTTPException(400, "scan is not running")
    ev.clear()
    db_set_scan_status(scan_id, "paused")
    state["status"] = "paused"
    _audit(user["id"], "scan_pause", "scan", scan_id, "")
    return {"paused": True}


@app.post("/api/scans/{scan_id}/resume")
async def resume_scan(scan_id: str, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    _require_scan(scan_id, user["id"])
    state = SCANS.get(scan_id)
    if not state or state.get("status") != "paused":
        raise HTTPException(400, "scan is not paused")
    ev: asyncio.Event = state.get("pause_event")
    if ev is None:
        raise HTTPException(400, "scan is not paused")
    ev.set()
    db_set_scan_status(scan_id, "running")
    state["status"] = "running"
    _audit(user["id"], "scan_resume", "scan", scan_id, "")
    return {"resumed": True}


@app.post("/api/scans/{scan_id}/rerun", status_code=201)
async def rerun_scan(scan_id: str, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    row = _require_scan(scan_id, user["id"])
    cfg = json.loads(row["config_json"])
    new_id = _launch_scan(user["id"], row["target"], cfg)
    return {"scan_id": new_id, "status": "queued"}


@app.get("/api/scans/{scan_id}/diff/{other_id}")
async def diff_scans(scan_id: str, other_id: str, request: Request):
    user = await current_user(request)
    _require_scan(scan_id, user["id"])
    _require_scan(other_id, user["id"])
    a = { _dedup_key_of(f): f for f in db_list_findings(scan_id) if not _is_excluded(f) }
    b = { _dedup_key_of(f): f for f in db_list_findings(other_id) if not _is_excluded(f) }
    return {
        "scan_a": scan_id, "scan_b": other_id,
        "new": [b[k] for k in b if k not in a],          # in b, not in a
        "fixed": [a[k] for k in a if k not in b],       # in a, not in b
        "persisting": [b[k] for k in b if k in a],      # in both
    }


def _report_findings(scan_id: str, user_id: int) -> tuple[list[Finding], str]:
    row = _require_scan(scan_id, user_id)
    findings = [_finding_from_dict(d) for d in db_list_findings(scan_id)
                if not _is_excluded(d)]
    return findings, row["target"]


@app.get("/api/scans/{scan_id}/report.json")
async def report_json(scan_id: str, request: Request):
    from sentinelx.reports.reports import write_json
    user = await current_user(request)
    findings, target = _report_findings(scan_id, user["id"])
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        path = tf.name
    write_json(findings, path, meta={"target": target, "scan_id": scan_id})
    return FileResponse(path, media_type="application/json",
                        filename=f"sentinelx-{scan_id}.json")


@app.get("/api/scans/{scan_id}/report.html")
async def report_html(scan_id: str, request: Request):
    from sentinelx.reports.reports import write_html
    user = await current_user(request)
    findings, target = _report_findings(scan_id, user["id"])
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as tf:
        path = tf.name
    write_html(findings, path, target)
    return FileResponse(path, media_type="text/html",
                        filename=f"sentinelx-{scan_id}.html")


@app.get("/api/scans/{scan_id}/report.sarif")
async def report_sarif(scan_id: str, request: Request):
    from sentinelx.reports.sarif import write_sarif
    user = await current_user(request)
    findings, target = _report_findings(scan_id, user["id"])
    with tempfile.NamedTemporaryFile("w", suffix=".sarif", delete=False) as tf:
        path = tf.name
    write_sarif(findings, path, target)
    return FileResponse(path, media_type="application/sarif+json",
                        filename=f"sentinelx-{scan_id}.sarif")


@app.get("/api/scans/{scan_id}/export/csv")
async def export_csv(scan_id: str, request: Request):
    import csv
    import io
    user = await current_user(request)
    row = _require_scan(scan_id, user["id"])
    findings = [d for d in db_list_findings(scan_id) if not _is_excluded(d)]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "type", "subtype", "severity", "cvss_score", "confidence",
                "url", "method", "param", "payload", "cwe", "owasp",
                "status", "assignee", "sla_due_at", "remediation"])
    for f in findings:
        w.writerow([f.get("id"), f.get("type"), f.get("subtype"),
                    f.get("severity"), f.get("cvss_score"), f.get("confidence"),
                    f.get("url"), f.get("method"), f.get("param"),
                    (f.get("payload") or "")[:500], f.get("cwe"), f.get("owasp"),
                    f.get("status", "open"), f.get("assignee") or "",
                    f.get("sla_due_at") or "",
                    (f.get("remediation") or "")[:500]])
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False,
                                     newline="") as tf:
        tf.write(buf.getvalue())
        path = tf.name
    return FileResponse(path, media_type="text/csv",
                        filename=f"sentinelx-{scan_id}.csv")


@app.get("/api/scans/{scan_id}/export/pdf")
async def export_pdf(scan_id: str, request: Request):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    user = await current_user(request)
    row = _require_scan(scan_id, user["id"])
    findings = [d for d in db_list_findings(scan_id) if not _is_excluded(d)]
    counts = _severity_counts(findings)
    with tempfile.NamedTemporaryFile("wb", suffix=".pdf", delete=False) as tf:
        path = tf.name
    c = canvas.Canvas(path, pagesize=A4)
    W, H = A4
    y = H - 20 * mm
    c.setFont("Helvetica-Bold", 18)
    c.drawString(20 * mm, y, "SentinelX Scan Report")
    y -= 10 * mm
    c.setFont("Helvetica", 11)
    for line in (f"Target: {row['target']}",
                 f"Scan ID: {scan_id}",
                 f"Status: {row['status']}",
                 "Findings: " + ", ".join(f"{k}={v}" for k, v in counts.items())):
        c.drawString(20 * mm, y, line[:110])
        y -= 6 * mm
    y -= 4 * mm
    c.setFont("Helvetica-Bold", 13)
    c.drawString(20 * mm, y, "Findings")
    y -= 8 * mm
    c.setFont("Helvetica", 9)
    for f in findings:
        if y < 25 * mm:
            c.showPage()
            y = H - 20 * mm
            c.setFont("Helvetica", 9)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(20 * mm, y,
                     f"[{f.get('severity', '?').upper()}] {f.get('type', '')}"
                     f" — {f.get('subtype', '')}"[:100])
        y -= 5 * mm
        c.setFont("Helvetica", 9)
        for line in (f"URL: {f.get('url', '')}",
                     f"Param: {f.get('param', '')} | CWE: {f.get('cwe', '')}"
                     f" | CVSS: {f.get('cvss_score', '')}"):
            c.drawString(22 * mm, y, line[:110])
            y -= 5 * mm
        y -= 3 * mm
    c.save()
    return FileResponse(path, media_type="application/pdf",
                        filename=f"sentinelx-{scan_id}.pdf")


class ShareIn(BaseModel):
    email: str


class ScanCommentIn(BaseModel):
    comment: str = Field(min_length=1, max_length=5000)


@app.get("/api/scans/{scan_id}/config-export")
async def config_export(scan_id: str, request: Request):
    user = await current_user(request)
    row = _require_scan(scan_id, user["id"])
    return {"target": row["target"], "config": json.loads(row["config_json"])}


@app.post("/api/scans/import-config", status_code=201)
async def config_import(body: dict, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    target = (body.get("target") or "").strip()
    cfg = body.get("config") or {}
    if not target or not isinstance(cfg, dict):
        raise HTTPException(400, "body must contain target and config")
    if not body.get("confirm_own"):
        raise HTTPException(400, "confirm_own must be true")
    _validate_target(target)
    clean = {k: cfg[k] for k in ("concurrency", "rate", "depth", "timeout",
                                 "safe_mode", "modules", "custom_headers",
                                 "custom_cookies", "user_agent",
                                 "exclude_paths") if k in cfg}
    scan_id = _launch_scan(user["id"], target, clean)
    _audit(user["id"], "scan_create", "scan", scan_id,
           f"target={target} via=config-import")
    return {"scan_id": scan_id, "status": "queued"}


@app.post("/api/scans/{scan_id}/share", status_code=201)
async def share_scan(scan_id: str, body: ShareIn, request: Request):
    user = await current_user(request)
    row = _require_scan(scan_id, user["id"])
    if row["user_id"] != user["id"]:
        raise HTTPException(403, "only the scan owner can share it")
    other = db_get_user_by_email(body.email)
    if not other:
        raise HTTPException(404, "user not found")
    if other["id"] == user["id"]:
        raise HTTPException(400, "cannot share with yourself")
    with _db_lock:
        db().execute("INSERT OR IGNORE INTO scan_shares(scan_id,user_id,created_at)"
                     " VALUES(?,?,?)", (scan_id, other["id"], time.time()))
        db().commit()
    _audit(user["id"], "scan_share", "scan", scan_id, f"shared_with={body.email}")
    return {"shared": True, "with": other["email"]}


@app.delete("/api/scans/{scan_id}/share/{email}")
async def unshare_scan(scan_id: str, email: str, request: Request):
    user = await current_user(request)
    row = _require_scan(scan_id, user["id"])
    if row["user_id"] != user["id"]:
        raise HTTPException(403, "only the scan owner can unshare it")
    other = db_get_user_by_email(email)
    if other:
        with _db_lock:
            db().execute("DELETE FROM scan_shares WHERE scan_id=? AND user_id=?",
                         (scan_id, other["id"]))
            db().commit()
    return {"unshared": True}


@app.post("/api/scans/{scan_id}/comments", status_code=201)
async def add_scan_comment(scan_id: str, body: ScanCommentIn, request: Request):
    user = await current_user(request)
    _require_scan(scan_id, user["id"])
    with _db_lock:
        c = db()
        cur = c.execute(
            "INSERT INTO scan_comments(scan_id,user_id,comment,created_at)"
            " VALUES(?,?,?,?)",
            (scan_id, user["id"], body.comment.strip(), time.time()))
        c.commit()
        cid = cur.lastrowid
    return {"id": cid, "comment": body.comment.strip()}


@app.get("/api/scans/{scan_id}/comments")
async def list_scan_comments(scan_id: str, request: Request):
    user = await current_user(request)
    _require_scan(scan_id, user["id"])
    with _db_lock:
        rows = db().execute(
            """SELECT sc.id, sc.comment, sc.created_at, u.email AS author
               FROM scan_comments sc JOIN users u ON u.id=sc.user_id
               WHERE sc.scan_id=? ORDER BY sc.created_at""", (scan_id,)).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------- findings

@app.get("/api/findings/search")
async def search_findings(request: Request, q: str = Query(min_length=1, max_length=200)):
    user = await current_user(request)
    ql = q.lower()
    out = []
    for r in db_list_scans(user["id"]):
        for f in db_list_findings(r["id"]):
            hay = " ".join(str(f.get(k, "")) for k in
                           ("type", "subtype", "url", "param", "payload", "title")).lower()
            if ql in hay:
                f = dict(f)
                f["scan_id"] = r["id"]
                out.append(f)
    return out


@app.get("/api/findings/sla-overdue")
async def sla_overdue(request: Request):
    user = await current_user(request)
    now = time.time()
    out = []
    for r in db_list_scans(user["id"]):
        for f in db_list_findings(r["id"]):
            due = f.get("sla_due_at")
            if not due or due >= now or _is_excluded(f):
                continue
            if (f.get("status") or "open") in ("resolved", "verified"):
                continue
            f = dict(f)
            f["scan_id"] = r["id"]
            f["sla_overdue_by_days"] = round((now - due) / 86400, 1)
            out.append(f)
    out.sort(key=lambda x: x["sla_due_at"])
    return out


@app.get("/api/findings")
async def list_findings(request: Request,
                        scan_id: Optional[str] = None,
                        severity: Optional[str] = None,
                        tag: Optional[str] = None,
                        type: Optional[str] = Query(default=None, alias="type")):
    user = await current_user(request)
    if scan_id:
        _require_scan(scan_id, user["id"])
        items = db_list_findings(scan_id)
    else:
        items = []
        for r in db_list_scans(user["id"]):
            items.extend(db_list_findings(r["id"]))
    if severity:
        items = [f for f in items if f.get("severity") == severity]
    if type:
        items = [f for f in items if f.get("type") == type]
    if tag:
        with _db_lock:
            trow = db().execute("SELECT id FROM tags WHERE user_id=? AND name=?",
                                (user["id"], tag)).fetchone()
            if trow:
                tagged = {r["finding_id"] for r in db().execute(
                    "SELECT finding_id FROM finding_tags WHERE tag_id=?",
                    (trow["id"],)).fetchall()}
                items = [f for f in items if f.get("_db_id") in tagged]
            else:
                items = []
    return items


@app.patch("/api/findings/{db_id}")
async def patch_finding(db_id: int, body: FindingPatchIn, request: Request):
    user = await current_user(request)
    # verify ownership via parent scan
    with _db_lock:
        row = db().execute("SELECT scan_id FROM findings WHERE id=?", (db_id,)).fetchone()
    if not row:
        raise HTTPException(404, "finding not found")
    _require_scan(row["scan_id"], user["id"])
    updated = db_patch_finding(db_id, body.false_positive)
    if not updated:
        raise HTTPException(404, "finding not found")
    _audit(user["id"], "finding_fp", "finding", str(db_id),
           f"false_positive={body.false_positive}")
    return updated


FINDING_STATUSES = ("open", "in_progress", "resolved", "verified", "false_positive")


class FindingStatusIn(BaseModel):
    status: str


class FindingAssigneeIn(BaseModel):
    assignee: Optional[str] = Field(default=None, max_length=254)


class FindingNoteIn(BaseModel):
    note: str = Field(min_length=1, max_length=5000)


class FindingTagsIn(BaseModel):
    tag_ids: list[int]


class AcceptRiskIn(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)
    expires_at: Optional[float] = None


@app.patch("/api/findings/{db_id}/status")
async def set_finding_status(db_id: int, body: FindingStatusIn, request: Request):
    user = await current_user(request)
    d = _require_finding(db_id, user["id"])
    if body.status not in FINDING_STATUSES:
        raise HTTPException(400, f"status must be one of {FINDING_STATUSES}")
    d["status"] = body.status
    if body.status == "false_positive":
        d["false_positive"] = True
    elif body.status == "open" and d.get("false_positive"):
        d["false_positive"] = False
    db_update_finding_json(db_id, d)
    _audit(user["id"], "finding_status", "finding", str(db_id),
           f"status={body.status}")
    return d


@app.patch("/api/findings/{db_id}/assignee")
async def set_finding_assignee(db_id: int, body: FindingAssigneeIn, request: Request):
    user = await current_user(request)
    d = _require_finding(db_id, user["id"])
    email = (body.assignee or "").strip().lower() or None
    if email and ("@" not in email or "." not in email.split("@")[-1]):
        raise HTTPException(400, "invalid assignee email")
    d["assignee"] = email
    db_update_finding_json(db_id, d)
    _audit(user["id"], "finding_assignee", "finding", str(db_id),
           f"assignee={email}")
    return d


@app.post("/api/findings/{db_id}/notes", status_code=201)
async def add_finding_note(db_id: int, body: FindingNoteIn, request: Request):
    user = await current_user(request)
    _require_finding(db_id, user["id"])
    with _db_lock:
        c = db()
        cur = c.execute(
            "INSERT INTO finding_notes(finding_id,user_id,note,created_at)"
            " VALUES(?,?,?,?)", (db_id, user["id"], body.note.strip(), time.time()))
        c.commit()
        nid = cur.lastrowid
    return {"id": nid, "finding_id": db_id, "note": body.note.strip()}


@app.get("/api/findings/{db_id}/notes")
async def list_finding_notes(db_id: int, request: Request):
    user = await current_user(request)
    _require_finding(db_id, user["id"])
    with _db_lock:
        rows = db().execute(
            """SELECT n.id, n.note, n.created_at, u.email AS author
               FROM finding_notes n JOIN users u ON u.id=n.user_id
               WHERE n.finding_id=? ORDER BY n.created_at""", (db_id,)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/findings/{db_id}/tags")
async def tag_finding(db_id: int, body: FindingTagsIn, request: Request):
    user = await current_user(request)
    _require_finding(db_id, user["id"])
    with _db_lock:
        c = db()
        for tid in body.tag_ids:
            trow = c.execute("SELECT id FROM tags WHERE id=? AND user_id=?",
                             (tid, user["id"])).fetchone()
            if not trow:
                raise HTTPException(404, f"tag {tid} not found")
            c.execute("INSERT OR IGNORE INTO finding_tags(finding_id,tag_id) VALUES(?,?)",
                      (db_id, tid))
        c.commit()
    return {"tagged": True}


@app.delete("/api/findings/{db_id}/tags/{tag_id}")
async def untag_finding(db_id: int, tag_id: int, request: Request):
    user = await current_user(request)
    _require_finding(db_id, user["id"])
    with _db_lock:
        db().execute("DELETE FROM finding_tags WHERE finding_id=? AND tag_id=?",
                     (db_id, tag_id))
        db().commit()
    return {"untagged": True}


@app.get("/api/findings/{db_id}/tags")
async def finding_tags(db_id: int, request: Request):
    user = await current_user(request)
    _require_finding(db_id, user["id"])
    with _db_lock:
        rows = db().execute(
            """SELECT t.id, t.name, t.color FROM tags t
               JOIN finding_tags ft ON ft.tag_id=t.id
               WHERE ft.finding_id=? AND t.user_id=?""", (db_id, user["id"])).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/findings/{db_id}/accept-risk", status_code=201)
async def accept_risk(db_id: int, body: AcceptRiskIn, request: Request):
    user = await current_user(request)
    d = _require_finding(db_id, user["id"])
    if body.expires_at is not None and body.expires_at <= time.time():
        raise HTTPException(400, "expires_at must be in the future")
    with _db_lock:
        c = db()
        c.execute("DELETE FROM risk_acceptances WHERE finding_id=?", (db_id,))
        cur = c.execute(
            "INSERT INTO risk_acceptances(finding_id,user_id,reason,expires_at,created_at)"
            " VALUES(?,?,?,?,?)",
            (db_id, user["id"], body.reason.strip(), body.expires_at, time.time()))
        c.commit()
        rid = cur.lastrowid
    d["risk_accepted"] = {"reason": body.reason.strip(),
                          "expires_at": body.expires_at,
                          "acceptance_id": rid}
    db_update_finding_json(db_id, d)
    _audit(user["id"], "finding_accept_risk", "finding", str(db_id),
           f"reason={body.reason.strip()[:100]}")
    return {"id": rid, "finding_id": db_id}


@app.delete("/api/findings/{db_id}/accept-risk")
async def revoke_risk(db_id: int, request: Request):
    user = await current_user(request)
    d = _require_finding(db_id, user["id"])
    with _db_lock:
        db().execute("DELETE FROM risk_acceptances WHERE finding_id=?", (db_id,))
        db().commit()
    d.pop("risk_accepted", None)
    db_update_finding_json(db_id, d)
    _audit(user["id"], "finding_revoke_risk", "finding", str(db_id), "")
    return {"revoked": True}


CWE_REFERENCES = {
    "CWE-79": ["https://owasp.org/www-community/attacks/xss/",
               "https://cwe.mitre.org/data/definitions/79.html",
               "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
    "CWE-89": ["https://owasp.org/www-community/attacks/SQL_Injection",
               "https://cwe.mitre.org/data/definitions/89.html",
               "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    "CWE-78": ["https://owasp.org/www-community/attacks/Command_Injection",
               "https://cwe.mitre.org/data/definitions/78.html"],
    "CWE-22": ["https://owasp.org/www-community/attacks/Path_Traversal",
               "https://cwe.mitre.org/data/definitions/22.html"],
    "CWE-918": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cwe.mitre.org/data/definitions/918.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
    "CWE-601": ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/601.html"],
    "CWE-352": ["https://owasp.org/www-community/attacks/csrf",
                "https://cwe.mitre.org/data/definitions/352.html"],
    "CWE-639": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema",
                "https://cwe.mitre.org/data/definitions/639.html"],
    "CWE-862": ["https://cwe.mitre.org/data/definitions/862.html",
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
    "CWE-863": ["https://cwe.mitre.org/data/definitions/863.html",
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
    "CWE-287": ["https://cwe.mitre.org/data/definitions/287.html",
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
    "CWE-798": ["https://cwe.mitre.org/data/definitions/798.html",
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
    "CWE-312": ["https://cwe.mitre.org/data/definitions/312.html"],
    "CWE-532": ["https://cwe.mitre.org/data/definitions/532.html"],
    "CWE-200": ["https://cwe.mitre.org/data/definitions/200.html",
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
    "CWE-327": ["https://cwe.mitre.org/data/definitions/327.html"],
    "CWE-328": ["https://cwe.mitre.org/data/definitions/328.html"],
    "CWE-330": ["https://cwe.mitre.org/data/definitions/330.html"],
    "CWE-613": ["https://cwe.mitre.org/data/definitions/613.html"],
    "CWE-614": ["https://cwe.mitre.org/data/definitions/614.html"],
    "CWE-1004": ["https://cwe.mitre.org/data/definitions/1004.html"],
    "CWE-1275": ["https://cwe.mitre.org/data/definitions/1275.html"],
    "CWE-693": ["https://cwe.mitre.org/data/definitions/693.html"],
    "CWE-16": ["https://cwe.mitre.org/data/definitions/16.html"],
    "CWE-311": ["https://cwe.mitre.org/data/definitions/311.html"],
    "CWE-319": ["https://cwe.mitre.org/data/definitions/319.html"],
    "CWE-20": ["https://cwe.mitre.org/data/definitions/20.html"],
    "CWE-400": ["https://cwe.mitre.org/data/definitions/400.html"],
    "CWE-444": ["https://cwe.mitre.org/data/definitions/444.html"],
    "CWE-113": ["https://cwe.mitre.org/data/definitions/113.html"],
}


@app.get("/api/findings/{db_id}/references")
async def finding_references(db_id: int, request: Request):
    user = await current_user(request)
    d = _require_finding(db_id, user["id"])
    cwe = (d.get("cwe") or "").upper().strip()
    refs = list(d.get("references") or [])
    curated = CWE_REFERENCES.get(cwe, [])
    return {"cwe": cwe or None, "finding_references": refs,
            "curated": curated}
# ---------------------------------------------------------------- templates

class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    modules: list[str] = Field(default_factory=list)
    rate_limit: float = Field(default=10.0, ge=0.5, le=200.0)


def _row_to_template(r) -> dict:
    d = dict(r)
    d["modules"] = json.loads(d.pop("modules_json") or "[]")
    return d


@app.get("/api/templates")
async def list_templates(request: Request):
    user = await current_user(request)
    with _db_lock:
        rows = db().execute("SELECT * FROM templates WHERE user_id=? ORDER BY id",
                            (user["id"],)).fetchall()
    return [_row_to_template(r) for r in rows]


@app.post("/api/templates", status_code=201)
async def create_template(body: TemplateIn, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    with _db_lock:
        c = db()
        cur = c.execute(
            "INSERT INTO templates(user_id,name,description,modules_json,rate_limit,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (user["id"], body.name.strip(), body.description.strip(),
             json.dumps(body.modules), body.rate_limit, time.time()))
        c.commit()
        tid = cur.lastrowid
        row = c.execute("SELECT * FROM templates WHERE id=?", (tid,)).fetchone()
    return _row_to_template(row)


@app.get("/api/templates/{tid}")
async def get_template(tid: int, request: Request):
    user = await current_user(request)
    with _db_lock:
        row = db().execute("SELECT * FROM templates WHERE id=? AND user_id=?",
                           (tid, user["id"])).fetchone()
    if not row:
        raise HTTPException(404, "template not found")
    return _row_to_template(row)


@app.put("/api/templates/{tid}")
async def update_template(tid: int, body: TemplateIn, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    with _db_lock:
        c = db()
        row = c.execute("SELECT id FROM templates WHERE id=? AND user_id=?",
                        (tid, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "template not found")
        c.execute("UPDATE templates SET name=?,description=?,modules_json=?,rate_limit=?"
                  " WHERE id=?",
                  (body.name.strip(), body.description.strip(),
                   json.dumps(body.modules), body.rate_limit, tid))
        c.commit()
        row = c.execute("SELECT * FROM templates WHERE id=?", (tid,)).fetchone()
    return _row_to_template(row)


@app.delete("/api/templates/{tid}")
async def delete_template(tid: int, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    with _db_lock:
        c = db()
        row = c.execute("SELECT id FROM templates WHERE id=? AND user_id=?",
                        (tid, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "template not found")
        c.execute("DELETE FROM templates WHERE id=?", (tid,))
        c.commit()
    return {"deleted": True}


# ---------------------------------------------------------------- targets

class TargetIn(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    name: str = Field(default="", max_length=120)
    tags: list[str] = Field(default_factory=list)
    notes: str = Field(default="", max_length=5000)


def _row_to_target(r) -> dict:
    d = dict(r)
    d["tags"] = json.loads(d.pop("tags_json") or "[]")
    return d


@app.get("/api/targets")
async def list_targets(request: Request):
    user = await current_user(request)
    with _db_lock:
        rows = db().execute("SELECT * FROM targets WHERE user_id=? ORDER BY id",
                            (user["id"],)).fetchall()
    return [_row_to_target(r) for r in rows]


@app.post("/api/targets", status_code=201)
async def create_target(body: TargetIn, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    url = _validate_target(body.url)
    with _db_lock:
        c = db()
        cur = c.execute(
            "INSERT INTO targets(user_id,url,name,tags_json,notes,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (user["id"], url, body.name.strip(), json.dumps(body.tags),
             body.notes.strip(), time.time()))
        c.commit()
        tid = cur.lastrowid
        row = c.execute("SELECT * FROM targets WHERE id=?", (tid,)).fetchone()
    return _row_to_target(row)


@app.get("/api/targets/{tid}")
async def get_target(tid: int, request: Request):
    user = await current_user(request)
    with _db_lock:
        row = db().execute("SELECT * FROM targets WHERE id=? AND user_id=?",
                           (tid, user["id"])).fetchone()
    if not row:
        raise HTTPException(404, "target not found")
    return _row_to_target(row)


@app.put("/api/targets/{tid}")
async def update_target(tid: int, body: TargetIn, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    url = _validate_target(body.url)
    with _db_lock:
        c = db()
        row = c.execute("SELECT id FROM targets WHERE id=? AND user_id=?",
                        (tid, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "target not found")
        c.execute("UPDATE targets SET url=?,name=?,tags_json=?,notes=? WHERE id=?",
                  (url, body.name.strip(), json.dumps(body.tags),
                   body.notes.strip(), tid))
        c.commit()
        row = c.execute("SELECT * FROM targets WHERE id=?", (tid,)).fetchone()
    return _row_to_target(row)


@app.delete("/api/targets/{tid}")
async def delete_target(tid: int, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    with _db_lock:
        c = db()
        row = c.execute("SELECT id FROM targets WHERE id=? AND user_id=?",
                        (tid, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "target not found")
        c.execute("DELETE FROM targets WHERE id=?", (tid,))
        c.commit()
    return {"deleted": True}


class TargetImportIn(BaseModel):
    csv: str = Field(min_length=1, max_length=200000)


@app.post("/api/targets/import", status_code=201)
async def import_targets(body: TargetImportIn, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    created = 0
    errors: list[str] = []
    for i, line in enumerate(body.csv.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",", 1)]
        url, name = parts[0], (parts[1] if len(parts) > 1 else "")
        try:
            url = _validate_target(url)
        except HTTPException:
            errors.append(f"line {i}: invalid URL")
            continue
        with _db_lock:
            c = db()
            c.execute("INSERT INTO targets(user_id,url,name,tags_json,notes,created_at)"
                      " VALUES(?,?,?,?,?,?)",
                      (user["id"], url, name[:120], "[]", "", time.time()))
            c.commit()
        created += 1
    _audit(user["id"], "targets_import", "target", "", f"created={created}")
    return {"created": created, "errors": errors}


# ---------------------------------------------------------------- schedules

class ScheduleIn(BaseModel):
    target_id: Optional[int] = None
    template_id: Optional[int] = None
    cron_expr: str = Field(min_length=1, max_length=120)
    enabled: bool = True


def _row_to_schedule(r) -> dict:
    d = dict(r)
    d["enabled"] = bool(d["enabled"])
    return d


@app.get("/api/schedules")
async def list_schedules(request: Request):
    user = await current_user(request)
    with _db_lock:
        rows = db().execute("SELECT * FROM schedules WHERE user_id=? ORDER BY id",
                            (user["id"],)).fetchall()
    return [_row_to_schedule(r) for r in rows]


@app.post("/api/schedules", status_code=201)
async def create_schedule(body: ScheduleIn, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    if not body.target_id:
        raise HTTPException(400, "target_id is required")
    with _db_lock:
        t = db().execute("SELECT id FROM targets WHERE id=? AND user_id=?",
                         (body.target_id, user["id"])).fetchone()
    if not t:
        raise HTTPException(404, "target not found")
    if body.template_id:
        with _db_lock:
            tp = db().execute("SELECT id FROM templates WHERE id=? AND user_id=?",
                              (body.template_id, user["id"])).fetchone()
        if not tp:
            raise HTTPException(404, "template not found")
    try:
        nxt = _cron_next(body.cron_expr, time.time())
    except ValueError as e:
        raise HTTPException(400, f"invalid cron expression: {e}")
    with _db_lock:
        c = db()
        cur = c.execute(
            "INSERT INTO schedules(user_id,target_id,template_id,cron_expr,enabled,"
            "next_run_at,created_at) VALUES(?,?,?,?,?,?,?)",
            (user["id"], body.target_id, body.template_id, body.cron_expr.strip(),
             1 if body.enabled else 0, nxt, time.time()))
        c.commit()
        sid = cur.lastrowid
        row = c.execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
    return _row_to_schedule(row)


@app.get("/api/schedules/{sid}")
async def get_schedule(sid: int, request: Request):
    user = await current_user(request)
    with _db_lock:
        row = db().execute("SELECT * FROM schedules WHERE id=? AND user_id=?",
                           (sid, user["id"])).fetchone()
    if not row:
        raise HTTPException(404, "schedule not found")
    return _row_to_schedule(row)


@app.put("/api/schedules/{sid}")
async def update_schedule(sid: int, body: ScheduleIn, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    with _db_lock:
        row = db().execute("SELECT * FROM schedules WHERE id=? AND user_id=?",
                           (sid, user["id"])).fetchone()
    if not row:
        raise HTTPException(404, "schedule not found")
    try:
        nxt = _cron_next(body.cron_expr, time.time())
    except ValueError as e:
        raise HTTPException(400, f"invalid cron expression: {e}")
    with _db_lock:
        c = db()
        c.execute("UPDATE schedules SET target_id=?,template_id=?,cron_expr=?,"
                  "enabled=?,next_run_at=? WHERE id=?",
                  (body.target_id, body.template_id, body.cron_expr.strip(),
                   1 if body.enabled else 0, nxt, sid))
        c.commit()
        row = c.execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
    return _row_to_schedule(row)


@app.delete("/api/schedules/{sid}")
async def delete_schedule(sid: int, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    with _db_lock:
        c = db()
        row = c.execute("SELECT id FROM schedules WHERE id=? AND user_id=?",
                        (sid, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "schedule not found")
        c.execute("DELETE FROM schedules WHERE id=?", (sid,))
        c.commit()
    return {"deleted": True}


# ---------------------------------------------------------------- auth profiles

class AuthProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    login_url: str = Field(min_length=1, max_length=2048)
    username_field: str = Field(default="username", max_length=120)
    password_field: str = Field(default="password", max_length=120)
    username: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


def _row_to_auth_profile(r) -> dict:
    d = dict(r)
    d.pop("password_enc", None)
    return d


@app.get("/api/auth-profiles")
async def list_auth_profiles(request: Request):
    user = await current_user(request)
    with _db_lock:
        rows = db().execute(
            "SELECT id,user_id,name,login_url,username_field,password_field,"
            "username,created_at FROM auth_profiles WHERE user_id=? ORDER BY id",
            (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/auth-profiles", status_code=201)
async def create_auth_profile(body: AuthProfileIn, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    _validate_target(body.login_url)
    enc = _fernet().encrypt(body.password.encode()).decode()
    with _db_lock:
        c = db()
        cur = c.execute(
            "INSERT INTO auth_profiles(user_id,name,login_url,username_field,"
            "password_field,username,password_enc,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (user["id"], body.name.strip(), body.login_url.strip(),
             body.username_field.strip(), body.password_field.strip(),
             body.username.strip(), enc, time.time()))
        c.commit()
        pid = cur.lastrowid
        row = c.execute("SELECT * FROM auth_profiles WHERE id=?", (pid,)).fetchone()
    return _row_to_auth_profile(row)


@app.get("/api/auth-profiles/{pid}")
async def get_auth_profile(pid: int, request: Request):
    user = await current_user(request)
    with _db_lock:
        row = db().execute("SELECT * FROM auth_profiles WHERE id=? AND user_id=?",
                           (pid, user["id"])).fetchone()
    if not row:
        raise HTTPException(404, "auth profile not found")
    return _row_to_auth_profile(row)


@app.put("/api/auth-profiles/{pid}")
async def update_auth_profile(pid: int, body: AuthProfileIn, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    with _db_lock:
        row = db().execute("SELECT id FROM auth_profiles WHERE id=? AND user_id=?",
                           (pid, user["id"])).fetchone()
    if not row:
        raise HTTPException(404, "auth profile not found")
    _validate_target(body.login_url)
    enc = _fernet().encrypt(body.password.encode()).decode()
    with _db_lock:
        c = db()
        c.execute("UPDATE auth_profiles SET name=?,login_url=?,username_field=?,"
                  "password_field=?,username=?,password_enc=? WHERE id=?",
                  (body.name.strip(), body.login_url.strip(),
                   body.username_field.strip(), body.password_field.strip(),
                   body.username.strip(), enc, pid))
        c.commit()
        row = c.execute("SELECT * FROM auth_profiles WHERE id=?", (pid,)).fetchone()
    return _row_to_auth_profile(row)


@app.delete("/api/auth-profiles/{pid}")
async def delete_auth_profile(pid: int, request: Request):
    user = await current_user(request)
    _require_scan_write(user)
    with _db_lock:
        c = db()
        row = c.execute("SELECT id FROM auth_profiles WHERE id=? AND user_id=?",
                        (pid, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "auth profile not found")
        c.execute("DELETE FROM auth_profiles WHERE id=?", (pid,))
        c.commit()
    return {"deleted": True}


# ---------------------------------------------------------------- tags

class TagIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    color: str = Field(default="#4ade80", max_length=20)


@app.get("/api/tags")
async def list_tags(request: Request):
    user = await current_user(request)
    with _db_lock:
        rows = db().execute("SELECT * FROM tags WHERE user_id=? ORDER BY name",
                            (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/tags", status_code=201)
async def create_tag(body: TagIn, request: Request):
    user = await current_user(request)
    with _db_lock:
        c = db()
        cur = c.execute("INSERT INTO tags(user_id,name,color,created_at) VALUES(?,?,?,?)",
                        (user["id"], body.name.strip(), body.color.strip(), time.time()))
        c.commit()
        tid = cur.lastrowid
        row = c.execute("SELECT * FROM tags WHERE id=?", (tid,)).fetchone()
    return dict(row)


@app.delete("/api/tags/{tid}")
async def delete_tag(tid: int, request: Request):
    user = await current_user(request)
    with _db_lock:
        c = db()
        row = c.execute("SELECT id FROM tags WHERE id=? AND user_id=?",
                        (tid, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "tag not found")
        c.execute("DELETE FROM finding_tags WHERE tag_id=?", (tid,))
        c.execute("DELETE FROM tags WHERE id=?", (tid,))
        c.commit()
    return {"deleted": True}


# ---------------------------------------------------------------- notification channels

class ChannelIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    type: str = Field(min_length=1, max_length=20)
    config: dict = Field(default_factory=dict)
    events: list[str] = Field(default_factory=list)
    enabled: bool = True


CHANNEL_TYPES = ("email", "slack", "discord", "webhook")


@app.get("/api/notification-channels")
async def list_channels(request: Request):
    user = await current_user(request)
    with _db_lock:
        rows = db().execute("SELECT * FROM notification_channels WHERE user_id=? ORDER BY id",
                            (user["id"],)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["config"] = json.loads(d.pop("config_json") or "{}")
        d["events"] = json.loads(d.pop("events_json") or "[]")
        d["enabled"] = bool(d["enabled"])
        out.append(d)
    return out


@app.post("/api/notification-channels", status_code=201)
async def create_channel(body: ChannelIn, request: Request):
    user = await current_user(request)
    if body.type not in CHANNEL_TYPES:
        raise HTTPException(400, f"type must be one of {CHANNEL_TYPES}")
    with _db_lock:
        c = db()
        cur = c.execute(
            "INSERT INTO notification_channels(user_id,name,type,config_json,"
            "events_json,enabled,created_at) VALUES(?,?,?,?,?,?,?)",
            (user["id"], body.name.strip(), body.type, json.dumps(body.config),
             json.dumps(body.events), 1 if body.enabled else 0, time.time()))
        c.commit()
        cid = cur.lastrowid
    return {"id": cid, "name": body.name.strip(), "type": body.type}


@app.delete("/api/notification-channels/{cid}")
async def delete_channel(cid: int, request: Request):
    user = await current_user(request)
    with _db_lock:
        c = db()
        row = c.execute("SELECT id FROM notification_channels WHERE id=? AND user_id=?",
                        (cid, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "channel not found")
        c.execute("DELETE FROM notification_channels WHERE id=?", (cid,))
        c.commit()
    return {"deleted": True}


@app.post("/api/notification-channels/{cid}/test")
async def test_channel(cid: int, request: Request):
    user = await current_user(request)
    with _db_lock:
        row = db().execute("SELECT * FROM notification_channels WHERE id=? AND user_id=?",
                           (cid, user["id"])).fetchone()
    if not row:
        raise HTTPException(404, "channel not found")
    try:
        await _send_notification(row["type"], json.loads(row["config_json"] or "{}"),
                                 "test", {"scan_id": "test", "target": "test"})
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:500]}


# ---------------------------------------------------------------- API keys

class ApiKeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)


@app.get("/api/api-keys")
async def list_api_keys(request: Request):
    user = await current_user(request)
    with _db_lock:
        rows = db().execute(
            "SELECT id,name,prefix,created_at,last_used_at FROM api_keys"
            " WHERE user_id=? ORDER BY id", (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/api-keys", status_code=201)
async def create_api_key(body: ApiKeyIn, request: Request):
    import hashlib as _h
    user = await current_user(request)
    raw = "sx_" + secrets.token_urlsafe(32)
    digest = _h.sha256(raw.encode()).hexdigest()
    with _db_lock:
        c = db()
        cur = c.execute(
            "INSERT INTO api_keys(user_id,name,prefix,key_hash,created_at)"
            " VALUES(?,?,?,?,?)",
            (user["id"], body.name.strip(), raw[:10],
             digest, time.time()))
        c.commit()
        kid = cur.lastrowid
    _audit(user["id"], "api_key_create", "api_key", str(kid), f"name={body.name}")
    # the raw key is shown exactly once
    return {"id": kid, "name": body.name.strip(), "key": raw,
            "prefix": raw[:10]}


@app.delete("/api/api-keys/{kid}")
async def delete_api_key(kid: int, request: Request):
    user = await current_user(request)
    with _db_lock:
        c = db()
        row = c.execute("SELECT id FROM api_keys WHERE id=? AND user_id=?",
                        (kid, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "api key not found")
        c.execute("DELETE FROM api_keys WHERE id=?", (kid,))
        c.commit()
    _audit(user["id"], "api_key_delete", "api_key", str(kid), "")
    return {"deleted": True}


# ---------------------------------------------------------------- audit log

@app.get("/api/audit-log")
async def get_audit_log(request: Request, action: Optional[str] = None,
                        entity: Optional[str] = None, limit: int = 100):
    user = await current_user(request)
    q = "SELECT * FROM audit_log WHERE user_id=?"
    args: list = [user["id"]]
    if action:
        q += " AND action=?"
        args.append(action)
    if entity:
        q += " AND entity=?"
        args.append(entity)
    q += " ORDER BY at DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    with _db_lock:
        rows = db().execute(q, args).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------- admin

class AdminUserIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="member", max_length=20)


@app.get("/api/admin/users")
async def admin_list_users(request: Request):
    user = await current_user(request)
    _require_admin(user)
    with _db_lock:
        rows = db().execute(
            "SELECT id,email,name,role,created_at FROM users ORDER BY id").fetchall()
    return [dict(r) for r in rows]


@app.post("/api/admin/users", status_code=201)
async def admin_create_user(body: AdminUserIn, request: Request):
    user = await current_user(request)
    _require_admin(user)
    if body.role not in ("admin", "member", "viewer"):
        raise HTTPException(400, "role must be admin, member or viewer")
    if "@" not in body.email or "." not in body.email.split("@")[-1]:
        raise HTTPException(400, "invalid email address")
    created = db_create_user(body.email, body.name, body.password, role=body.role)
    # db_create_user only auto-admins the very first user; force requested role
    with _db_lock:
        db().execute("UPDATE users SET role=? WHERE id=?", (body.role, created["id"]))
        db().commit()
        created["role"] = body.role
    _audit(user["id"], "admin_create_user", "user", str(created["id"]),
           f"email={created['email']} role={body.role}")
    return created


# ---------------------------------------------------------------- dashboard trends

@app.get("/api/dashboard/trends")
async def dashboard_trends(request: Request, days: int = 30):
    import datetime as _dt
    user = await current_user(request)
    days = max(1, min(days, 365))
    now = time.time()
    start = now - days * 86400
    per_day: dict[str, dict] = {}
    for i in range(days):
        key = _dt.datetime.fromtimestamp(now - i * 86400).strftime("%Y-%m-%d")
        per_day[key] = {"critical": 0, "high": 0, "medium": 0,
                        "low": 0, "info": 0}
    for r in db_list_scans(user["id"]):
        for f in db_list_findings(r["id"]):
            if _is_excluded(f):
                continue
            ts = f.get("timestamp") or 0
            if ts < start:
                continue
            key = _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
            if key in per_day:
                sev = (f.get("severity") or "info").lower()
                if sev in per_day[key]:
                    per_day[key][sev] += 1
    return [{"date": k, **v} for k, v in sorted(per_day.items())]


# ---------------------------------------------------------------- engine stats

@app.get("/api/engine/stats")
async def engine_stats(request: Request, scan_id: Optional[str] = None):
    user = await current_user(request)
    if scan_id:
        _require_scan(scan_id, user["id"])
    else:
        scans = [s for s in db_list_scans(user["id"]) if s["status"] == "completed"]
        if not scans:
            return {"scan_id": None, "modules": []}
        scan_id = scans[0]["id"]
    with _db_lock:
        rows = db().execute(
            "SELECT module, requests FROM engine_stats WHERE scan_id=?"
            " ORDER BY requests DESC", (scan_id,)).fetchall()
    return {"scan_id": scan_id, "modules": [dict(r) for r in rows]}


# ---------------------------------------------------------------- websocket

@app.websocket("/ws/scans/{scan_id}")
async def ws_scan(ws: WebSocket, scan_id: str):
    try:
        uid = ws_token(ws)
    except HTTPException:
        await ws.close(code=4401)
        return
    row = db_get_scan(scan_id)
    if not row or row["user_id"] != uid:
        await ws.close(code=4404)
        return
    await ws.accept()
    state = SCANS.get(scan_id)
    findings = db_list_findings(scan_id)
    await ws.send_json({"type": "state", "data": {
        "scan_id": scan_id, "target": row["target"], "status": row["status"],
        "counts": _severity_counts(findings), "total_findings": len(findings),
    }})
    if state:
        for ev in state["events"]:
            await ws.send_json(ev)
        if state["status"] not in ("completed", "failed", "cancelled"):
            queue: asyncio.Queue = state["queue"]
            try:
                while True:
                    ev = await queue.get()
                    await ws.send_json(ev)
                    if ev.get("type") == "done":
                        break
            except WebSocketDisconnect:
                return
    await ws.send_json({"type": "done", "data": {"status": row["status"]}})
    await ws.close()


# ---------------------------------------------------------------- frontend static (mounted last)

_static_dir = ROOT / "web" / "frontend" / "dist"
if not _static_dir.is_dir():
    _static_dir = ROOT / "web" / "react" / "dist"
if not _static_dir.is_dir():
    _static_dir = ROOT / "web" / "static"
if _static_dir.is_dir():
    from fastapi.responses import FileResponse

    # serve built assets directly
    app.mount("/assets", StaticFiles(directory=str(_static_dir / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        # do not shadow API/WS routes (they're registered earlier and match first)
        fp = _static_dir / full_path
        if full_path and fp.is_file() and fp.suffix in (".js", ".css", ".svg", ".png", ".ico", ".map"):
            return FileResponse(str(fp))
        return FileResponse(str(_static_dir / "index.html"))

    log.info("serving frontend static from %s", _static_dir)
