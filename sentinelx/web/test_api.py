"""SentinelX web API integration tests (fastapi.testclient).

Run: cd ~/workspace/sentinelx && .venv/bin/python -m pytest sentinelx/web/test_api.py -q
(or run this file directly)
"""

import json
import os
import tempfile
import time

# isolate test DB before importing server
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["SENTINELX_DB_PATH"] = _tmp.name
_tmp.close()
os.environ["SENTINELX_TEST_DB"] = _tmp.name

import sentinelx.web.server as srv

import pathlib
srv._db = None
srv.TOKENS.clear()
srv.SCANS.clear()
srv.init_db()

from fastapi.testclient import TestClient

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail and not cond else ""))


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def main():
    with TestClient(srv.app) as client:

        def pump(scan_id, headers):
            # serverless chunked scans: keep pumping until terminal
            for _ in range(20):
                r = client.get(f"/api/scans/{scan_id}", headers=headers)
                st = r.json().get("status") if r.status_code == 200 else None
                if st in ("completed", "failed", "cancelled"):
                    return st
                if st == "chunk_done" or st == "running":
                    rc = client.post(f"/api/scans/{scan_id}/continue", headers=headers)
                    if rc.status_code != 200:
                        time.sleep(0.5)
                else:
                    time.sleep(0.5)
            r = client.get(f"/api/scans/{scan_id}", headers=headers)
            return r.json().get("status") if r.status_code == 200 else None

        def wait_status(scan_id, headers, want=("completed", "failed", "cancelled"), timeout=90):
            for _ in range(int(timeout * 2)):
                r = client.get(f"/api/scans/{scan_id}", headers=headers)
                if r.status_code == 200 and r.json()["status"] in want:
                    return r.json()["status"]
                if r.status_code == 200 and r.json()["status"] == "chunk_done":
                    return pump(scan_id, headers)
                time.sleep(0.5)
            return None


        # ---- 1. health / version (no auth) ----
        r = client.get("/api/health")
        check("health 200", r.status_code == 200 and r.json().get("status") == "ok")
        r = client.get("/api/version")
        check("version 1.0.0", r.status_code == 200 and r.json().get("version") == "1.0.0")

        # ---- 2. unauthorized ----
        r = client.get("/api/scans")
        check("no token -> 401", r.status_code == 401)
        r = client.get("/api/auth/me")
        check("me no token -> 401", r.status_code == 401)
        r = client.get("/api/scans", headers={"Authorization": "Bearer bogus"})
        check("bad token -> 401", r.status_code == 401)

        # ---- 3. register / login / me ----
        r = client.post("/api/auth/register", json={"email": "t@t.com", "name": "T", "password": "secret123"})
        check("register 200", r.status_code == 200 and "token" in r.json(), r.text[:120])
        token = r.json()["token"]
        r = client.post("/api/auth/register", json={"email": "t@t.com", "name": "T2", "password": "secret123"})
        check("duplicate email -> 400", r.status_code == 400)
        r = client.post("/api/auth/register", json={"email": "bad", "name": "X", "password": "secret123"})
        check("bad email -> 400", r.status_code == 400)
        r = client.post("/api/auth/register", json={"email": "u2@x.com", "name": "U", "password": "short"})
        check("short password -> 422", r.status_code == 422)
        r = client.post("/api/auth/login", json={"email": "t@t.com", "password": "secret123"})
        check("login 200", r.status_code == 200 and "token" in r.json())
        token2 = r.json()["token"]
        r = client.post("/api/auth/login", json={"email": "t@t.com", "password": "wrongpass1"})
        check("wrong password -> 401", r.status_code == 401)
        H = auth_headers(token2)
        r = client.get("/api/auth/me", headers=H)
        check("me returns user", r.status_code == 200 and r.json()["email"] == "t@t.com")
        r = client.post("/api/auth/logout", headers=H)
        check("logout 200", r.status_code == 200)
        r = client.get("/api/auth/me", headers=H)
        check("token dead after logout -> 401", r.status_code == 401)
        H = auth_headers(token)  # keep using first token

        # ---- 4. scan validation ----
        r = client.post("/api/scans", headers=H, json={"target": "http://127.0.0.1:9", "confirm_own": False})
        check("confirm_own=false -> 400", r.status_code == 400)
        r = client.post("/api/scans", headers=H, json={"target": "not-a-url", "confirm_own": True})
        check("bad url -> 400", r.status_code == 400)
        r = client.post("/api/scans", headers=H, json={"target": "ftp://x.com", "confirm_own": True})
        check("non-http scheme -> 400", r.status_code == 400)

        # ---- 5. real scan pipeline (fast-failing target, exercises background job) ----
        r = client.post("/api/scans", headers=H, json={
            "target": "http://127.0.0.1:9", "confirm_own": True,
            "concurrency": 5, "rate": 20.0, "depth": 0, "timeout": 5.0})
        check("start scan 201", r.status_code == 201 and "scan_id" in r.json(), r.text[:150])
        scan_id = r.json()["scan_id"]
        status = wait_status(scan_id, H)
        check("scan reaches terminal state", status in ("completed", "failed", "cancelled"), str(status))
        r = client.get(f"/api/scans/{scan_id}", headers=H)
        check("get scan detail", r.status_code == 200 and "findings" in r.json())
        r = client.get("/api/scans", headers=H)
        check("list scans", r.status_code == 200 and any(s["id"] == scan_id for s in r.json()))

        # ---- 6. reports on finished scan ----
        for suffix, ctype in [("report.json", "application/json"),
                              ("report.html", "text/html"),
                              ("report.sarif", "application/sarif+json")]:
            r = client.get(f"/api/scans/{scan_id}/{suffix}", headers=H)
            check(f"{suffix} 200", r.status_code == 200 and ctype in r.headers.get("content-type", ""), r.text[:100])

        # ---- 7. events feed on finished scan (replaces websocket) ----
        r = client.get(f"/api/scans/{scan_id}/events?since=0", headers=H)
        evs = r.json().get("events", []) if r.status_code == 200 else []
        types = [e["type"] for e in evs]
        check("events feed has progress/done", "done" in types, str(types[:8]))

        # websocket removed in serverless port -> polling via /events
        r = client.get(f"/ws/scans/{scan_id}")
        check("ws route removed (SPA fallback, not a socket)",
              r.status_code == 200 and "text/html" in r.headers.get("content-type", ""),
              str(r.status_code))
        r = client.get(f"/api/scans/{scan_id}/events?since=0", headers=H)
        check("events endpoint 200", r.status_code == 200 and "events" in r.json())

        # ---- 8. cancel semantics ----
        r = client.post(f"/api/scans/{scan_id}/cancel", headers=H)
        check("cancel finished scan -> 400", r.status_code == 400)
        r = client.post("/api/scans/doesnotexist/cancel", headers=H)
        check("cancel unknown scan -> 404", r.status_code == 404)

        # ---- 9. cancel a live scan (slow chunk in a thread) ----
        import asyncio as _asyncio
        import threading as _th
        import sentinelx.engine as _eng

        _orig_stage = _eng.run_stage

        async def _slow_stage(ctx, stage):
            if stage == "discovery":
                await _asyncio.sleep(30)
            else:
                await _orig_stage(ctx, stage)

        _eng.run_stage = _slow_stage
        _uid = srv.db_get_user_by_email("t@t.com")["id"]
        slow_id = srv._launch_scan(_uid, "http://127.0.0.1:9",
                                   {"concurrency": 2, "rate": 5.0, "depth": 0,
                                    "timeout": 5.0, "safe_mode": True})
        th = _th.Thread(target=lambda: _asyncio.run(srv.run_scan_chunk(slow_id, budget_s=60)))
        th.start()
        time.sleep(3.0)
        r = client.post(f"/api/scans/{slow_id}/cancel", headers=H)
        check("cancel running scan 200", r.status_code == 200, r.text[:100])
        th.join(timeout=60)
        check("scan marked cancelled",
              srv._job_get(slow_id)["status"] == "cancelled",
              str(srv._job_get(slow_id)["status"]))
        _eng.run_stage = _orig_stage

        # ---- 10. rerun + diff ----
        r = client.post(f"/api/scans/{scan_id}/rerun", headers=H)
        check("rerun 201", r.status_code == 201 and r.json()["scan_id"] != scan_id, r.text[:120])
        rerun_id = r.json()["scan_id"]
        wait_status(rerun_id, H)
        r = client.get(f"/api/scans/{scan_id}/diff/{rerun_id}", headers=H)
        d = r.json()
        check("diff shape", r.status_code == 200 and all(k in d for k in ("new", "fixed", "persisting")), r.text[:120])

        # ---- 11. findings endpoints ----
        r = client.get(f"/api/findings?scan_id={scan_id}", headers=H)
        check("findings by scan", r.status_code == 200 and isinstance(r.json(), list))
        r = client.get("/api/findings?severity=critical", headers=H)
        check("findings severity filter", r.status_code == 200)
        # insert a finding directly, then patch it
        fid = srv.db_add_finding(scan_id, {"id": "sx-999", "type": "Test", "subtype": "t",
                                           "severity": "high", "url": "http://x/", "method": "GET"})
        r = client.patch(f"/api/findings/{fid}", headers=H, json={"false_positive": True})
        check("patch finding fp", r.status_code == 200 and r.json().get("false_positive") is True, r.text[:120])
        r = client.get(f"/api/scans/{scan_id}", headers=H)
        check("fp excluded from counts", r.json()["counts"]["high"] == 0)
        r = client.patch("/api/findings/99999999", headers=H, json={"false_positive": True})
        check("patch unknown finding -> 404", r.status_code == 404)

        # ---- 12. cross-user isolation ----
        r = client.post("/api/auth/register", json={"email": "o@o.com", "name": "O", "password": "secret123"})
        H2 = auth_headers(r.json()["token"])
        r = client.get(f"/api/scans/{scan_id}", headers=H2)
        check("other user cannot see scan -> 404", r.status_code == 404)

        # ---- 13. delete ----
        r = client.delete(f"/api/scans/{rerun_id}", headers=H)
        check("delete scan", r.status_code == 200)
        r = client.get(f"/api/scans/{rerun_id}", headers=H)
        check("deleted scan gone -> 404", r.status_code == 404)

        print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
        if FAIL:
            print("FAILED:", FAIL)
            raise SystemExit(1)


if __name__ == "__main__":
    main()
