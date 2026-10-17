"""DB compatibility layer: Postgres when DATABASE_URL is set, SQLite fallback.

The rest of the codebase keeps writing SQLite-style SQL with `?` placeholders;
this module translates to Postgres (`%s`) at the boundary, converts DDL
(`INTEGER PRIMARY KEY AUTOINCREMENT` -> `SERIAL PRIMARY KEY`), and emulates
`cursor.lastrowid` via `RETURNING id`.

Rows are returned as dicts in both modes (sqlite3.Row -> dict(),
psycopg2 RealDictRow -> dict()).
"""

from __future__ import annotations

import os
import re
import sqlite3
import threading

USE_PG = bool(os.environ.get("DATABASE_URL"))

# sqlite3 exception aliases so callers can keep one except path
try:
    import psycopg2
    import psycopg2.extras
    import psycopg2.errors
    OperationalError = psycopg2.OperationalError
    IntegrityError = psycopg2.errors.UniqueViolation
except ImportError:  # pragma: no cover - only when psycopg2 missing
    psycopg2 = None  # type: ignore[assignment]
    OperationalError = sqlite3.OperationalError
    IntegrityError = sqlite3.IntegrityError


def _translate_placeholders(sql: str) -> str:
    """Rewrite `?` placeholders to `%s`, ignoring `?` inside string literals."""
    out: list[str] = []
    i, n = 0, len(sql)
    in_str = False
    while i < n:
        ch = sql[i]
        if in_str:
            out.append(ch)
            if ch == "'":
                if i + 1 < n and sql[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                in_str = False
        elif ch == "'":
            in_str = True
            out.append(ch)
        elif ch == "?":
            out.append("%s")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


_TABLE_WITH_ID = {
    "users", "findings", "templates", "targets", "schedules",
    "auth_profiles", "finding_notes", "tags", "risk_acceptances",
    "notification_channels", "api_keys", "audit_log", "scan_comments",
    "scan_shares", "engine_stats", "scan_jobs", "scan_events",
}


def _translate_ddl(sql: str) -> str:
    sql = re.sub(r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT",
                 "SERIAL PRIMARY KEY", sql, flags=re.IGNORECASE)
    return sql


def _maybe_returning(sql: str) -> str:
    """Append `RETURNING id` to INSERTs on tables that have an id column."""
    m = re.match(r"\s*INSERT\s+INTO\s+[`\"\[]?(\w+)", sql, re.IGNORECASE)
    if m and m.group(1).lower() in _TABLE_WITH_ID:
        return sql.rstrip().rstrip(";") + " RETURNING id"
    return sql


class _Cursor:
    def __init__(self, cur, pg: bool):
        self._cur = cur
        self._pg = pg
        self._lastrowid = None

    def execute(self, sql: str, params=()):
        if self._pg:
            stripped = sql.lstrip().upper()
            if stripped.startswith("CREATE TABLE"):
                sql = _translate_ddl(sql)
            sql = _translate_placeholders(sql)
            if stripped.startswith("INSERT"):
                sql = _maybe_returning(sql)
        self._cur.execute(sql, params or ())
        if self._pg and sql.lstrip().upper().startswith("INSERT") and "RETURNING id" in sql:
            try:
                row = self._cur.fetchone()
                if row:
                    self._lastrowid = row["id"] if isinstance(row, dict) else row[0]
            except Exception:
                pass
        return self

    def fetchone(self):
        r = self._cur.fetchone()
        return dict(r) if r is not None else None

    def fetchall(self):
        return [dict(r) for r in self._cur.fetchall()]

    @property
    def lastrowid(self):
        if self._lastrowid is not None:
            return self._lastrowid
        return self._cur.lastrowid

    @property
    def rowcount(self):
        return self._cur.rowcount


class _Conn:
    """Single shared connection (mirrors the old sqlite3 singleton pattern)."""

    def __init__(self):
        self._pg = USE_PG and psycopg2 is not None
        self._conn = None
        self._lock = threading.Lock()

    def _connect(self):
        if self._pg:
            import psycopg2 as _pg2
            import psycopg2.extras as _pge
            self._conn = _pg2.connect(os.environ["DATABASE_URL"],
                                      cursor_factory=_pge.RealDictCursor)
        else:
            from pathlib import Path
            override = os.environ.get("SENTINELX_DB_PATH")
            if override:
                db_path = Path(override)
            elif os.environ.get("VERCEL"):
                # Vercel's filesystem is read-only except /tmp
                db_path = Path("/tmp/sentinelx.db")
            else:
                db_path = Path(__file__).resolve().parents[2] / "sentinelx.db"
            self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row

    def _ensure(self):
        if self._conn is None:
            self._connect()
        elif self._pg:
            try:
                cur = self._conn.cursor()
                cur.execute("SELECT 1")
                cur.close()
            except Exception:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._connect()

    def execute(self, sql: str, params=()):
        with self._lock:
            self._ensure()
            try:
                return _Cursor(self._conn.cursor(), self._pg).execute(sql, params)
            except Exception:
                if self._pg:
                    # stale connection? reconnect once and retry
                    try:
                        self._conn.close()
                    except Exception:
                        pass
                    self._conn = None
                    self._ensure()
                    return _Cursor(self._conn.cursor(), self._pg).execute(sql, params)
                raise

    def commit(self):
        with self._lock:
            self._ensure()
            self._conn.commit()

    def rollback(self):
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.rollback()
                except Exception:
                    pass


_db: _Conn | None = None
_db_singleton_lock = threading.Lock()


def db() -> _Conn:
    """Return the shared DB connection (Postgres or SQLite)."""
    global _db
    if _db is None:
        with _db_singleton_lock:
            if _db is None:
                _db = _Conn()
    return _db


def is_postgres() -> bool:
    return USE_PG and psycopg2 is not None
