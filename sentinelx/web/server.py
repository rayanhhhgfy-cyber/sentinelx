"""SentinelX web backend — FastAPI REST API + WebSocket + background scan jobs.

Run:  python -m sentinelx.web.run   (or uvicorn sentinelx.web.server:app)
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
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

from sentinelx.core.http import ScanConfig
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


def db_create_user(email: str, name: str, pw: str) -> dict:
    with _db_lock:
        c = db()
        try:
            cur = c.execute(
                "INSERT INTO users(email,name,pw_hash,created_at) VALUES(?,?,?,?)",
                (email.lower().strip(), name.strip(), hash_pw(pw), time.time()))
            c.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(400, "email already registered")
        uid = cur.lastrowid
        row = c.execute("SELECT id,email,name,created_at FROM users WHERE id=?", (uid,)).fetchone()
        return dict(row)


def db_get_user(uid: int) -> Optional[dict]:
    with _db_lock:
        row = db().execute(
            "SELECT id,email,name,created_at FROM users WHERE id=?", (uid,)).fetchone()
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
            "SELECT * FROM scans WHERE user_id=? ORDER BY created_at DESC", (user_id,)).fetchall()
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
        cur = c.execute("INSERT INTO findings(scan_id,finding_json) VALUES(?,?)",
                        (scan_id, json.dumps(finding_dict)))
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
        c.execute("UPDATE findings SET finding_json=? WHERE id=?", (json.dumps(d), db_id))
        c.commit()
        d["_db_id"] = db_id
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


def _severity_counts(findings: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.get("false_positive"):
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


async def _run_scan_job(scan_id: str, user_id: int, target: str, cfg: dict):
    state = SCANS.get(scan_id)
    if not state:
        return
    queue: asyncio.Queue = state["queue"]
    config = ScanConfig(
        target=target,
        concurrency=cfg.get("concurrency", 30),
        rate_per_sec=cfg.get("rate", 10.0),
        crawl_depth=cfg.get("depth", 2),
        timeout=cfg.get("timeout", 15.0),
        safe_mode=cfg.get("safe_mode", True),
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

    db_set_scan_status(scan_id, "running")
    state["status"] = "running"
    emit_event({"type": "progress", "data": f"scan started: {target}"})
    try:
        findings = await run_scan(config, on_finding=on_finding, on_progress=on_progress)
        stats = {"requests": state["stats"].get("requests", 0),
                 "counts": _severity_counts(state["findings"])}
        db_set_scan_status(scan_id, "completed", stats)
        state["status"] = "completed"
        state["stats"].update(stats)
        emit_event({"type": "done", "data": {"status": "completed",
                                             "findings": len(findings)}})
        log.info("scan %s completed: %d findings", scan_id, len(findings))
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


def _launch_scan(user_id: int, target: str, cfg: dict) -> str:
    scan_id = secrets.token_hex(8)
    db_create_scan(scan_id, user_id, target, cfg)
    SCANS[scan_id] = {
        "task": None, "queue": asyncio.Queue(), "events": [],
        "status": "queued", "findings": [], "stats": {},
        "target": target, "config": cfg, "user_id": user_id,
    }
    SCANS[scan_id]["task"] = asyncio.create_task(_run_scan_job(scan_id, user_id, target, cfg))
    log.info("scan %s queued for %s", scan_id, target)
    return scan_id


def _require_scan(scan_id: str, user_id: int) -> dict:
    row = db_get_scan(scan_id)
    if not row or row["user_id"] != user_id:
        raise HTTPException(404, "scan not found")
    return row


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


# ---------------------------------------------------------------- pydantic in/out

class RegisterIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=8, max_length=256)


class LoginIn(BaseModel):
    email: str
    password: str


class ScanStartIn(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    confirm_own: bool = False
    concurrency: int = Field(default=30, ge=1, le=100)
    rate: float = Field(default=10.0, ge=0.5, le=200.0)
    depth: int = Field(default=2, ge=0, le=5)
    timeout: float = Field(default=15.0, ge=5.0, le=120.0)
    safe_mode: bool = True


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
    return {"status": "ok"}


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
    log.info("user registered: %s", user["email"])
    return {"token": token, "user": user}


@app.post("/api/auth/login")
async def login(body: LoginIn):
    row = db_get_user_by_email(body.email)
    if not row or not verify_pw(body.password, row["pw_hash"]):
        raise HTTPException(401, "invalid email or password")
    user = db_get_user(row["id"])
    token = new_token(user["id"])
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
    if not body.confirm_own:
        raise HTTPException(400, "confirm_own must be true: only scan targets you own or have written permission to test")
    target = _validate_target(body.target)
    cfg = {"concurrency": body.concurrency, "rate": body.rate, "depth": body.depth,
           "timeout": body.timeout, "safe_mode": body.safe_mode}
    scan_id = _launch_scan(user["id"], target, cfg)
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
    _require_scan(scan_id, user["id"])
    state = SCANS.pop(scan_id, None)
    if state and state.get("task") and not state["task"].done():
        state["task"].cancel()
    db_delete_scan(scan_id)
    log.info("scan %s deleted", scan_id)
    return {"deleted": True}


@app.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str, request: Request):
    user = await current_user(request)
    _require_scan(scan_id, user["id"])
    state = SCANS.get(scan_id)
    if not state or not state.get("task") or state["task"].done():
        raise HTTPException(400, "scan is not running")
    state["task"].cancel()
    return {"cancelled": True}


@app.post("/api/scans/{scan_id}/rerun", status_code=201)
async def rerun_scan(scan_id: str, request: Request):
    user = await current_user(request)
    row = _require_scan(scan_id, user["id"])
    cfg = json.loads(row["config_json"])
    new_id = _launch_scan(user["id"], row["target"], cfg)
    return {"scan_id": new_id, "status": "queued"}


@app.get("/api/scans/{scan_id}/diff/{other_id}")
async def diff_scans(scan_id: str, other_id: str, request: Request):
    user = await current_user(request)
    _require_scan(scan_id, user["id"])
    _require_scan(other_id, user["id"])
    a = { _dedup_key_of(f): f for f in db_list_findings(scan_id) if not f.get("false_positive") }
    b = { _dedup_key_of(f): f for f in db_list_findings(other_id) if not f.get("false_positive") }
    return {
        "scan_a": scan_id, "scan_b": other_id,
        "new": [b[k] for k in b if k not in a],          # in b, not in a
        "fixed": [a[k] for k in a if k not in b],       # in a, not in b
        "persisting": [b[k] for k in b if k in a],      # in both
    }


def _report_findings(scan_id: str, user_id: int) -> tuple[list[Finding], str]:
    row = _require_scan(scan_id, user_id)
    findings = [_finding_from_dict(d) for d in db_list_findings(scan_id)
                if not d.get("false_positive")]
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


# ---------------------------------------------------------------- findings

@app.get("/api/findings")
async def list_findings(request: Request,
                        scan_id: Optional[str] = None,
                        severity: Optional[str] = None,
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
    return updated


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
