"""SentinelX extended API tests — 30 new backend features.

Run: cd ~/workspace/sentinelx && PYTHONPATH=. .venv/bin/python sentinelx/web/test_extended.py
"""

import asyncio as _asyncio
import http.server as _httpserv
import json
import os
import tempfile
import threading as _threading
import time

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["SENTINELX_TEST_DB"] = _tmp.name

import sentinelx.web.server as srv

import pathlib
srv.DB_PATH = pathlib.Path(_tmp.name)
srv._db = None
srv.TOKENS.clear()
srv.SCANS.clear()
srv.init_db()

from fastapi.testclient import TestClient
from sentinelx.core.models import Finding

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail and not cond else ""))


def H_(token):
    return {"Authorization": f"Bearer {token}"}


# ---- tiny local HTTP server: webhook receiver + fake login page ----
RECEIVED = []


class _Handler(_httpserv.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        RECEIVED.append({"path": self.path, "body": body,
                         "headers": dict(self.headers)})
        if self.path == "/login":
            self.send_response(200)
            self.send_header("Set-Cookie", "session=abc123; Path=/")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def _start_local_server():
    httpd = _httpserv.HTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    t = _threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, port


def _mk_finding(**kw):
    base = {"id": "sx-001", "type": "XSS", "subtype": "reflected",
            "severity": "high", "cvss_score": 7.5, "confidence": 0.9,
            "url": "http://example.com/?q=1", "method": "GET", "param": "q",
            "payload": "<script>", "cwe": "CWE-79", "owasp": "A03",
            "timestamp": time.time()}
    base.update(kw)
    return base


def main():
    httpd, port = _start_local_server()
    base_url = f"http://127.0.0.1:{port}"

    async def _fast_scan(config, on_finding=None, on_progress=None):
        return []

    async def _emit_scan(config, on_finding=None, on_progress=None):
        from sentinelx.core.models import Evidence
        f = Finding(type="SQLi", subtype="error", severity="critical",
                    url="http://example.com/?id=1", method="GET", param="id",
                    payload="' OR 1=1--", cwe="CWE-89",
                    evidence=Evidence("req", "resp", "proof"))
        f.finalize(1)
        if config.stats is not None:
            config.stats["modules"] = {"sqli": 42, "xss": 17}
        if on_finding:
            on_finding(f)
        return [f]

    async def _pausable_scan(config, on_finding=None, on_progress=None):
        for i in range(30):
            if config.pause_event is not None:
                await config.pause_event.wait()
            if on_progress:
                on_progress(f"step {i}")
            await _asyncio.sleep(0.2)
        return []

    srv.run_scan = _fast_scan

    with TestClient(srv.app) as client:
        def wait_status(sid, headers, want=("completed", "failed", "cancelled"),
                        timeout=30):
            for _ in range(int(timeout * 2)):
                r = client.get(f"/api/scans/{sid}", headers=headers)
                if r.status_code == 200 and r.json()["status"] in want:
                    return r.json()["status"]
                time.sleep(0.5)
            return None

        # ---- users: first is admin ----
        r = client.post("/api/auth/register", json={"email": "admin@x.com", "name": "A",
                                                     "password": "secret123"})
        HA = H_(r.json()["token"])
        check("first user is admin", r.json()["user"].get("role") == "admin")
        r = client.post("/api/auth/register", json={"email": "mem@x.com", "name": "M",
                                                     "password": "secret123"})
        HM = H_(r.json()["token"])
        check("second user is member", r.json()["user"].get("role") == "member")

        # ---- 22. roles: admin user management ----
        r = client.get("/api/admin/users", headers=HA)
        check("admin lists users", r.status_code == 200 and len(r.json()) >= 2)
        r = client.get("/api/admin/users", headers=HM)
        check("member cannot list users -> 403", r.status_code == 403)
        r = client.post("/api/admin/users", headers=HA,
                        json={"email": "view@x.com", "name": "V",
                              "password": "secret123", "role": "viewer"})
        check("admin creates viewer", r.status_code == 201
              and r.json()["role"] == "viewer", r.text[:120])
        HV = H_(client.post("/api/auth/login",
                            json={"email": "view@x.com",
                                  "password": "secret123"}).json()["token"])
        r = client.post("/api/admin/users", headers=HM,
                        json={"email": "z@z.com", "name": "Z", "password": "secret123"})
        check("member cannot create users -> 403", r.status_code == 403)
        r = client.post("/api/scans", headers=HV,
                        json={"target": "http://127.0.0.1:9", "confirm_own": True})
        check("viewer cannot create scan -> 403", r.status_code == 403)

        # ---- 1. templates ----
        r = client.post("/api/templates", headers=HM,
                        json={"name": "quick", "description": "fast",
                              "modules": ["sqli", "xss"], "rate_limit": 20.0})
        check("create template", r.status_code == 201 and r.json()["modules"] == ["sqli", "xss"])
        tid = r.json()["id"]
        r = client.get("/api/templates", headers=HM)
        check("list templates", any(t["id"] == tid for t in r.json()))
        r = client.put(f"/api/templates/{tid}", headers=HM,
                       json={"name": "quick2", "modules": ["sqli"], "rate_limit": 5.0})
        check("update template", r.json()["name"] == "quick2"
              and r.json()["rate_limit"] == 5.0)
        # apply template on scan create
        r = client.post("/api/scans", headers=HM,
                        json={"target": "http://127.0.0.1:9", "confirm_own": True,
                              "template_id": tid})
        check("scan with template 201", r.status_code == 201)
        tsid = r.json()["scan_id"]
        wait_status(tsid, HM)
        r = client.get(f"/api/scans/{tsid}", headers=HM)
        cfg = r.json()["config"]
        check("template applied (modules+rate)", cfg.get("modules") == ["sqli"]
              and cfg.get("rate") == 5.0, str({k: cfg.get(k) for k in ("modules", "rate")}))
        r = client.delete(f"/api/templates/{tid}", headers=HM)
        check("delete template", r.status_code == 200)
        r = client.get("/api/templates", headers=HV)
        check("viewer cannot see other's templates (isolation)",
              r.status_code == 200 and r.json() == [])

        # ---- 29. rate-limit presets ----
        r = client.post("/api/scans", headers=HM,
                        json={"target": "http://127.0.0.1:9", "confirm_own": True,
                              "rate_limit_profile": "polite"})
        psid = r.json()["scan_id"]
        wait_status(psid, HM)
        r = client.get(f"/api/scans/{psid}", headers=HM)
        check("polite profile -> rate 2.0", r.json()["config"].get("rate") == 2.0)
        r = client.post("/api/scans", headers=HM,
                        json={"target": "http://127.0.0.1:9", "confirm_own": True,
                              "rate_limit_profile": "bogus"})
        check("bad profile -> 400", r.status_code == 400)

        # ---- 6. custom scan config ----
        r = client.post("/api/scans", headers=HM,
                        json={"target": "http://127.0.0.1:9", "confirm_own": True,
                              "custom_headers": {"X-Test": "1"},
                              "custom_cookies": {"sess": "abc"},
                              "user_agent": "TestAgent/1.0",
                              "exclude_paths": ["/admin"]})
        csid = r.json()["scan_id"]
        wait_status(csid, HM)
        r = client.get(f"/api/scans/{csid}", headers=HM)
        cfg = r.json()["config"]
        check("custom config stored",
              cfg.get("custom_headers") == {"X-Test": "1"}
              and cfg.get("custom_cookies") == {"sess": "abc"}
              and cfg.get("user_agent") == "TestAgent/1.0"
              and cfg.get("exclude_paths") == ["/admin"])

        # ---- 2/3. targets CRUD + import ----
        r = client.post("/api/targets", headers=HM,
                        json={"url": "http://example.com", "name": "ex",
                              "tags": ["prod"], "notes": "n"})
        check("create target", r.status_code == 201 and r.json()["tags"] == ["prod"])
        tgtid = r.json()["id"]
        r = client.post("/api/targets/import", headers=HM,
                        json={"csv": "http://a.com,Site A\nhttp://b.com\nbad-url\n"})
        check("import csv", r.status_code == 201 and r.json()["created"] == 2
              and len(r.json()["errors"]) == 1, r.text[:150])
        r = client.get("/api/targets", headers=HM)
        check("list targets == 3", len(r.json()) == 3, str(len(r.json())))
        # last_scan_at auto-update
        r = client.post("/api/scans", headers=HM,
                        json={"target": "http://example.com", "confirm_own": True})
        lsid = r.json()["scan_id"]
        wait_status(lsid, HM)
        r = client.get(f"/api/targets/{tgtid}", headers=HM)
        check("last_scan_at updated", r.json().get("last_scan_at") is not None)
        r = client.delete(f"/api/targets/{tgtid}", headers=HM)
        check("delete target", r.status_code == 200)

        # ---- 4. schedules ----
        r = client.post("/api/targets", headers=HM, json={"url": "http://sched.com"})
        stid = r.json()["id"]
        r = client.post("/api/schedules", headers=HM,
                        json={"target_id": stid, "cron_expr": "0 * * * *"})
        check("create schedule", r.status_code == 201
              and r.json()["next_run_at"] > time.time())
        schid = r.json()["id"]
        r = client.post("/api/schedules", headers=HM,
                        json={"target_id": stid, "cron_expr": "bogus"})
        check("bad cron -> 400", r.status_code == 400)
        r = client.get("/api/schedules", headers=HM)
        check("list schedules", any(s["id"] == schid for s in r.json()))
        # cron math sanity
        nxt = srv._cron_next("0 0 * * *", 0)
        import datetime as _dt
        check("cron next midnight", _dt.datetime.fromtimestamp(nxt).hour == 0
              and nxt > 0)
        # due-schedule execution (patch _launch_scan to avoid loop issues)
        launched = []
        _orig_launch = srv._launch_scan
        srv._launch_scan = lambda u, t, c: launched.append((u, t, c)) or "fake-id"
        with srv._db_lock:
            srv.db().execute("UPDATE schedules SET next_run_at=? WHERE id=?",
                             (time.time() - 5, schid))
            srv.db().commit()
        _asyncio.run(srv._run_due_schedules())
        srv._launch_scan = _orig_launch
        check("due schedule launched scan", len(launched) == 1
              and launched[0][1] == "http://sched.com", str(launched))
        with srv._db_lock:
            row = srv.db().execute("SELECT next_run_at FROM schedules WHERE id=?",
                                   (schid,)).fetchone()
        check("next_run_at recomputed", row["next_run_at"] > time.time())
        r = client.delete(f"/api/schedules/{schid}", headers=HM)
        check("delete schedule", r.status_code == 200)

        # ---- 5. pause / resume ----
        srv.run_scan = _pausable_scan
        r = client.post("/api/scans", headers=HM,
                        json={"target": "http://127.0.0.1:9", "confirm_own": True})
        pause_id = r.json()["scan_id"]
        for _ in range(20):
            time.sleep(0.5)
            rr = client.get(f"/api/scans/{pause_id}", headers=HM)
            if rr.json()["status"] == "running":
                break
        check("scan running before pause", rr.json()["status"] == "running")
        r = client.post(f"/api/scans/{pause_id}/pause", headers=HM)
        check("pause 200", r.status_code == 200, r.text[:100])
        time.sleep(0.5)
        r = client.get(f"/api/scans/{pause_id}", headers=HM)
        check("status paused", r.json()["status"] == "paused", r.json()["status"])
        r = client.post(f"/api/scans/{pause_id}/pause", headers=HM)
        check("pause when paused -> 400", r.status_code == 400)
        r = client.post(f"/api/scans/{pause_id}/resume", headers=HM)
        check("resume 200", r.status_code == 200)
        st = wait_status(pause_id, HM, timeout=30)
        check("resumed scan completes", st == "completed", str(st))
        r = client.post(f"/api/scans/{pause_id}/resume", headers=HM)
        check("resume when not paused -> 400", r.status_code == 400)
        srv.run_scan = _fast_scan

        # ---- 8. auth profiles ----
        r = client.post("/api/auth-profiles", headers=HM,
                        json={"name": "p1", "login_url": f"{base_url}/login",
                              "username": "u", "password": "pw123"})
        check("create auth profile", r.status_code == 201
              and "password" not in r.json()
              and "password_enc" not in r.json(), r.text[:150])
        pid = r.json()["id"]
        # password really encrypted at rest
        with srv._db_lock:
            enc = srv.db().execute("SELECT password_enc FROM auth_profiles WHERE id=?",
                                   (pid,)).fetchone()["password_enc"]
        check("password encrypted", enc != "pw123"
              and srv._fernet().decrypt(enc.encode()).decode() == "pw123")
        r = client.get("/api/auth-profiles", headers=HM)
        check("list profiles (no secrets)", r.status_code == 200
              and all("password" not in p for p in r.json()))
        # real login flow against local server
        cookies = _asyncio.run(srv._profile_login(
            client.get("/api/auth/me", headers=HM).json()["id"], pid))
        check("profile login captures cookies", cookies.get("session") == "abc123",
              str(cookies))
        check("login endpoint was hit",
              any(x["path"] == "/login" for x in RECEIVED))
        # scan referencing the profile runs (login failure tolerated, success here)
        r = client.post("/api/scans", headers=HM,
                        json={"target": "http://127.0.0.1:9", "confirm_own": True,
                              "auth_profile_id": pid})
        check("scan with auth profile 201", r.status_code == 201)
        wait_status(r.json()["scan_id"], HM)
        r = client.delete(f"/api/auth-profiles/{pid}", headers=HM)
        check("delete auth profile", r.status_code == 200)

        # ---- findings playground: one scan with emitted findings ----
        srv.run_scan = _emit_scan
        r = client.post("/api/scans", headers=HM,
                        json={"target": "http://127.0.0.1:9", "confirm_own": True})
        fsid = r.json()["scan_id"]
        wait_status(fsid, HM)
        srv.run_scan = _fast_scan
        r = client.get(f"/api/findings?scan_id={fsid}", headers=HM)
        fids = [f["_db_id"] for f in r.json()]
        check("emitted finding stored", len(fids) == 1)
        fid = fids[0]

        # ---- 24. SLA stamped at finish ----
        r = client.get(f"/api/findings?scan_id={fsid}", headers=HM)
        f = r.json()[0]
        check("sla_due_at set (critical=7d)",
              f.get("sla_due_at") and abs(f["sla_due_at"] - (time.time() + 7 * 86400)) < 600,
              str(f.get("sla_due_at")))
        check("status defaults to open", f.get("status") == "open")
        # overdue
        with srv._db_lock:
            d = json.loads(srv.db().execute(
                "SELECT finding_json FROM findings WHERE id=?", (fid,)).fetchone()["finding_json"])
            d["sla_due_at"] = time.time() - 100
            srv.db().execute("UPDATE findings SET finding_json=? WHERE id=?",
                             (json.dumps(d), fid))
            srv.db().commit()
        r = client.get("/api/findings/sla-overdue", headers=HM)
        check("sla-overdue lists it", any(x["_db_id"] == fid for x in r.json()))

        # ---- 27. engine stats ----
        r = client.get(f"/api/engine/stats?scan_id={fsid}", headers=HM)
        mods = {m["module"]: m["requests"] for m in r.json()["modules"]}
        check("engine stats per module", mods.get("sqli") == 42
              and mods.get("xss") == 17, str(mods))
        r = client.get("/api/engine/stats", headers=HM)
        check("engine stats default last scan", r.json()["scan_id"] == fsid)

        # ---- 9. notes ----
        r = client.post(f"/api/findings/{fid}/notes", headers=HM, json={"note": "look closer"})
        check("add note", r.status_code == 201)
        r = client.get(f"/api/findings/{fid}/notes", headers=HM)
        check("list notes", len(r.json()) == 1 and r.json()[0]["author"] == "mem@x.com")

        # ---- 10. status workflow ----
        r = client.patch(f"/api/findings/{fid}/status", headers=HM,
                         json={"status": "in_progress"})
        check("status in_progress", r.json()["status"] == "in_progress")
        r = client.patch(f"/api/findings/{fid}/status", headers=HM,
                         json={"status": "bogus"})
        check("bad status -> 400", r.status_code == 400)
        r = client.patch(f"/api/findings/{fid}/status", headers=HM,
                         json={"status": "false_positive"})
        check("status false_positive", r.json()["status"] == "false_positive")
        r = client.get(f"/api/scans/{fsid}", headers=HM)
        check("fp-status excluded from counts", r.json()["counts"]["critical"] == 0)
        r = client.patch(f"/api/findings/{fid}/status", headers=HM,
                         json={"status": "open"})
        r = client.get(f"/api/scans/{fsid}", headers=HM)
        check("reopened counted again", r.json()["counts"]["critical"] == 1)

        # ---- 11. assignee ----
        r = client.patch(f"/api/findings/{fid}/assignee", headers=HM,
                         json={"assignee": "dev@x.com"})
        check("set assignee", r.json()["assignee"] == "dev@x.com")
        r = client.patch(f"/api/findings/{fid}/assignee", headers=HM,
                         json={"assignee": "not-an-email"})
        check("bad assignee -> 400", r.status_code == 400)

        # ---- 12. tags ----
        r = client.post("/api/tags", headers=HM, json={"name": "net", "color": "#fff"})
        tagid = r.json()["id"]
        r = client.post(f"/api/findings/{fid}/tags", headers=HM,
                        json={"tag_ids": [tagid]})
        check("tag finding", r.status_code == 200)
        r = client.get("/api/findings?tag=net", headers=HM)
        check("filter by tag", any(f["_db_id"] == fid for f in r.json()))
        r = client.get(f"/api/findings/{fid}/tags", headers=HM)
        check("finding tags listed", r.json()[0]["name"] == "net")
        r = client.delete(f"/api/findings/{fid}/tags/{tagid}", headers=HM)
        check("untag", r.status_code == 200)
        r = client.get("/api/findings?tag=net", headers=HM)
        check("untagged gone from filter", not any(f["_db_id"] == fid for f in r.json()))

        # ---- 13. risk acceptance ----
        r = client.post(f"/api/findings/{fid}/accept-risk", headers=HM,
                        json={"reason": "wontfix", "expires_at": time.time() + 3600})
        check("accept risk", r.status_code == 201)
        r = client.get(f"/api/scans/{fsid}", headers=HM)
        check("risk-accepted excluded from counts", r.json()["counts"]["critical"] == 0)
        r = client.post(f"/api/findings/{fid}/accept-risk", headers=HM,
                        json={"reason": "x", "expires_at": time.time() - 10})
        check("past expiry -> 400", r.status_code == 400)
        # expiry auto-revert
        with srv._db_lock:
            srv.db().execute("UPDATE risk_acceptances SET expires_at=?",
                             (time.time() - 5,))
            srv.db().commit()
        srv._expire_risk_acceptances()
        r = client.get(f"/api/scans/{fsid}", headers=HM)
        check("expired acceptance reverts", r.json()["counts"]["critical"] == 1)
        r = client.delete(f"/api/findings/{fid}/accept-risk", headers=HM)
        check("revoke risk", r.status_code == 200)

        # ---- 14. search ----
        r = client.get("/api/findings/search?q=OR+1%3D1", headers=HM)
        check("search finds payload", any(f["_db_id"] == fid for f in r.json()),
              r.text[:120])
        r = client.get("/api/findings/search?q=zzz-no-match", headers=HM)
        check("search no match", r.json() == [])

        # ---- 15/16. exports ----
        r = client.get(f"/api/scans/{fsid}/export/csv", headers=HM)
        check("csv export", r.status_code == 200
              and "text/csv" in r.headers["content-type"]
              and r.text.startswith("id,type,subtype"), r.text[:80])
        r = client.get(f"/api/scans/{fsid}/export/pdf", headers=HM)
        check("pdf export", r.status_code == 200
              and r.content[:5] == b"%PDF-", r.content[:20])

        # ---- 30. CWE references ----
        r = client.get(f"/api/findings/{fid}/references", headers=HM)
        j = r.json()
        check("cwe references", j["cwe"] == "CWE-89"
              and any("owasp.org" in u for u in j["curated"]), str(j)[:150])

        # ---- 17. compare ----
        fid2 = srv.db_add_finding(fsid, _mk_finding(id="sx-002", type="XSS",
                                                   severity="medium",
                                                   url="http://example.com/?q=2",
                                                   param="q", payload="<img>"))
        r = client.post("/api/scans", headers=HM,
                        json={"target": "http://127.0.0.1:9", "confirm_own": True})
        gsid = r.json()["scan_id"]
        wait_status(gsid, HM)
        srv.db_add_finding(gsid, _mk_finding(id="sx-001", type="SQLi", subtype="error",
                                            severity="critical",
                                            url="http://example.com/?id=1",
                                            param="id", payload="' OR 1=1--",
                                            cwe="CWE-89"))
        r = client.get(f"/api/scans/compare?ids={fsid},{gsid}", headers=HM)
        j = r.json()
        check("compare shape", {"new_by_scan", "fixed", "persisting"} <= set(j.keys()))
        check("compare persisting", len(j["persisting"]) == 1, str(len(j["persisting"])))
        check("compare new in second", len(j["new_by_scan"][gsid]) == 0)
        check("compare fixed (xss gone)", len(j["fixed"]) == 1, str(len(j["fixed"])))
        r = client.get(f"/api/scans/compare?ids={fsid}", headers=HM)
        check("compare needs 2 ids -> 400", r.status_code == 400)

        # ---- 18. trends ----
        r = client.get("/api/dashboard/trends?days=7", headers=HM)
        j = r.json()
        check("trends 7 days", len(j) == 7 and "critical" in j[-1], str(len(j)))
        check("trends counts today", sum(d["critical"] for d in j) >= 2)

        # ---- 19. notifications ----
        RECEIVED.clear()
        r = client.post("/api/notification-channels", headers=HM,
                        json={"name": "wh", "type": "webhook",
                              "config": {"url": f"{base_url}/hook"},
                              "events": ["scan_completed"], "enabled": True})
        check("create channel", r.status_code == 201)
        cid = r.json()["id"]
        r = client.post("/api/notification-channels", headers=HM,
                        json={"name": "bad", "type": "carrier-pigeon", "config": {}})
        check("bad channel type -> 400", r.status_code == 400)
        r = client.post(f"/api/notification-channels/{cid}/test", headers=HM)
        check("test channel fires", r.json().get("ok") is True, r.text[:150])
        check("webhook received test",
              any(x["path"] == "/hook" for x in RECEIVED))
        RECEIVED.clear()
        r = client.post("/api/scans", headers=HM,
                        json={"target": "http://127.0.0.1:9", "confirm_own": True})
        nsid = r.json()["scan_id"]
        wait_status(nsid, HM)
        # notifications fire just after the status flips; poll briefly
        fired = False
        for _ in range(20):
            if any(x["path"] == "/hook" and b"scan_completed" in x["body"]
                   for x in RECEIVED):
                fired = True
                break
            time.sleep(0.5)
        check("scan_completed notification fired", fired,
              str([x["path"] for x in RECEIVED]))
        r = client.delete(f"/api/notification-channels/{cid}", headers=HM)
        check("delete channel", r.status_code == 200)

        # ---- 20. API keys ----
        r = client.post("/api/api-keys", headers=HM, json={"name": "ci"})
        check("create api key", r.status_code == 201 and r.json()["key"].startswith("sx_"))
        rawkey = r.json()["key"]
        kid = r.json()["id"]
        import hashlib as _h
        with srv._db_lock:
            stored = srv.db().execute("SELECT key_hash, prefix FROM api_keys WHERE id=?",
                                      (kid,)).fetchone()
        check("only hash stored", stored["key_hash"] == _h.sha256(rawkey.encode()).hexdigest()
              and stored["key_hash"] != rawkey and stored["prefix"] == rawkey[:10])
        r = client.get("/api/scans", headers={"X-API-Key": rawkey})
        check("api key auth works", r.status_code == 200)
        r = client.get("/api/scans", headers={"X-API-Key": "sx_bogus"})
        check("bad api key -> 401", r.status_code == 401)
        r = client.get("/api/api-keys", headers=HM)
        check("list keys (no secrets)", r.status_code == 200
              and all("key" not in k or k["key"] != rawkey for k in r.json())
              and any(k["id"] == kid for k in r.json()))
        r = client.delete(f"/api/api-keys/{kid}", headers=HM)
        check("delete key", r.status_code == 200)
        r = client.get("/api/scans", headers={"X-API-Key": rawkey})
        check("deleted key -> 401", r.status_code == 401)

        # ---- 21. audit log ----
        r = client.get("/api/audit-log?action=login", headers=HV)
        check("audit has login entries", len(r.json()) > 0
              and all(e["action"] == "login" for e in r.json()),
              r.text[:120])
        r = client.get("/api/audit-log", headers=HM)
        acts = [e["action"] for e in r.json()]
        check("audit has scan entries", "scan_create" in acts, str(acts[:8]))
        r = client.get("/api/audit-log?action=scan_create", headers=HM)
        check("audit filter", all(e["action"] == "scan_create" for e in r.json())
              and len(r.json()) > 0)

        # ---- 23. config export/import ----
        r = client.get(f"/api/scans/{csid}/config-export", headers=HM)
        exp = r.json()
        check("config export", exp["target"] == "http://127.0.0.1:9"
              and "config" in exp)
        r = client.post("/api/scans/import-config", headers=HM,
                        json={"target": exp["target"], "config": exp["config"],
                              "confirm_own": True})
        check("config import launches", r.status_code == 201)
        wait_status(r.json()["scan_id"], HM)

        # ---- 25. share scan ----
        r = client.post(f"/api/scans/{fsid}/share", headers=HM,
                        json={"email": "view@x.com"})
        check("share scan", r.status_code == 201)
        r = client.get(f"/api/scans/{fsid}", headers=HV)
        check("grantee can read shared scan", r.status_code == 200)
        r = client.get("/api/scans", headers=HV)
        check("shared scan in grantee list", any(s["id"] == fsid for s in r.json()))
        # non-owner cannot share
        r = client.post(f"/api/scans/{fsid}/share", headers=HV,
                        json={"email": "mem@x.com"})
        check("non-owner share -> 403", r.status_code == 403)
        r = client.delete(f"/api/scans/{fsid}/share/view@x.com", headers=HM)
        check("unshare", r.status_code == 200)
        r = client.get(f"/api/scans/{fsid}", headers=HV)
        check("unshared gone -> 404", r.status_code == 404)

        # ---- 26. scan comments ----
        r = client.post(f"/api/scans/{fsid}/comments", headers=HM,
                        json={"comment": "looks bad"})
        check("add comment", r.status_code == 201)
        r = client.get(f"/api/scans/{fsid}/comments", headers=HM)
        check("list comments", len(r.json()) == 1
              and r.json()[0]["author"] == "mem@x.com")

        # ---- 28. health extended ----
        r = client.get("/api/health")
        j = r.json()
        check("health extended", j.get("version") == "1.0.0"
              and j.get("uptime_sec", 0) >= 0 and j.get("db_bytes", 0) > 0,
              str(j))

        # ---- viewer read-only still fine ----
        r = client.get("/api/scans", headers=HV)
        check("viewer can list", r.status_code == 200)

    httpd.shutdown()
    print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
    if FAIL:
        print("FAILED:", FAIL)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
