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

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail and not cond else ""))


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def main():
    with TestClient(srv.app) as client:

        def wait_status(scan_id, headers, want=("completed", "failed", "cancelled"), timeout=90):
            for _ in range(int(timeout * 2)):
                r = client.get(f"/api/scans/{scan_id}", headers=headers)
                if r.status_code == 200 and r.json()["status"] in want:
                    return r.json()["status"]
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

        # ---- 7. websocket on finished scan ----
        try:
            with client.websocket_connect(f"/ws/scans/{scan_id}?token={token}") as ws:
                msgs = []
                for _ in range(600):
                    m = ws.receive_json()
                    msgs.append(m["type"])
                    if m["type"] == "done":
                        break
            check("ws streams state+done", "state" in msgs and "done" in msgs,
                  str(msgs[:12]) + f" ({len(msgs)} msgs)")
        except Exception as e:  # noqa: BLE001
            check("ws streams state+done", False, repr(e)[:150])

        # bad ws token
        try:
            with client.websocket_connect(f"/ws/scans/{scan_id}?token=bogus"):
                check("ws bad token rejected", False, "connected unexpectedly")
        except Exception:
            check("ws bad token rejected", True)

        # ---- 8. cancel semantics ----
        r = client.post(f"/api/scans/{scan_id}/cancel", headers=H)
        check("cancel finished scan -> 400", r.status_code == 400)
        r = client.post("/api/scans/doesnotexist/cancel", headers=H)
        check("cancel unknown scan -> 404", r.status_code == 404)

        # ---- 9. cancel a live scan (slow fake run_scan) ----
        import asyncio as _asyncio

        async def _slow_scan(config, on_finding=None, on_progress=None):
            if on_progress:
                on_progress("slow scan running")
            await _asyncio.sleep(30)
            return []

        _orig = srv.run_scan
        srv.run_scan = _slow_scan
        r = client.post("/api/scans", headers=H, json={"target": "http://127.0.0.1:9", "confirm_own": True,
                                                       "concurrency": 2, "rate": 5.0, "depth": 0, "timeout": 5.0})
        slow_id = r.json()["scan_id"]
        time.sleep(1.0)
        r = client.post(f"/api/scans/{slow_id}/cancel", headers=H)
        check("cancel running scan 200", r.status_code == 200, r.text[:100])
        st = wait_status(slow_id, H, want=("cancelled",), timeout=15)
        check("scan marked cancelled", st == "cancelled", str(st))
        srv.run_scan = _orig

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
