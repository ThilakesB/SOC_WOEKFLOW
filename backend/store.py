"""SQLite persistence. WAL mode, single file, no ORM."""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from .config import DB_PATH, settings

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id            TEXT PRIMARY KEY,
    created_at    TEXT NOT NULL,
    engine        TEXT,
    llm_used      INTEGER DEFAULT 0,
    verdict       TEXT,
    severity      TEXT,
    confidence    INTEGER DEFAULT 0,
    risk_score    INTEGER DEFAULT 0,
    title         TEXT,
    host          TEXT,
    source_ip     TEXT,
    escalate      INTEGER DEFAULT 0,
    duration_ms   INTEGER DEFAULT 0,
    payload       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inv_created ON investigations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_inv_sev    ON investigations(severity);

CREATE TABLE IF NOT EXISTS alerts (
    id           TEXT PRIMARY KEY,
    received_at  TEXT NOT NULL,
    source       TEXT,
    processed    INTEGER DEFAULT 0,
    incident_id  TEXT,
    payload      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_recv ON alerts(received_at DESC);

CREATE TABLE IF NOT EXISTS ioc_cache (
    key        TEXT PRIMARY KEY,
    verdict    TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db() -> None:
    with _lock, _connect() as conn:
        conn.executescript(_SCHEMA)


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


# ── investigations ───────────────────────────────────────────────

def save_investigation(inv: dict[str, Any]) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO investigations
               (id, created_at, engine, llm_used, verdict, severity, confidence,
                risk_score, title, host, source_ip, escalate, duration_ms, payload)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                inv["incident_id"],
                inv["created_at"],
                inv.get("engine", ""),
                int(bool(inv.get("llm_used"))),
                inv.get("verdict", "unknown"),
                inv.get("severity", "Unknown"),
                int(inv.get("confidence") or 0),
                int((inv.get("risk") or {}).get("score") or 0),
                (inv.get("alert") or {}).get("title"),
                (inv.get("alert") or {}).get("endpoint_hostname"),
                (inv.get("alert") or {}).get("source_ip"),
                int(bool((inv.get("risk") or {}).get("escalate"))),
                int(inv.get("duration_ms") or 0),
                json.dumps(inv, default=str),
            ),
        )
        conn.execute(
            """DELETE FROM investigations WHERE id NOT IN
               (SELECT id FROM investigations ORDER BY created_at DESC LIMIT ?)""",
            (settings.store_history_limit,),
        )


def list_investigations(limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    with _lock, _connect() as conn:
        rows = conn.execute(
            """SELECT id, created_at, engine, llm_used, verdict, severity, confidence,
                      risk_score, title, host, source_ip, escalate, duration_ms
               FROM investigations ORDER BY created_at DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def get_investigation(incident_id: str) -> dict[str, Any] | None:
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT payload FROM investigations WHERE id = ?", (incident_id,)
        ).fetchone()
    if not row:
        return None
    return json.loads(row["payload"])


def incident_stats() -> dict[str, Any]:
    with _lock, _connect() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM investigations").fetchone()["c"]
        by_sev = {
            r["severity"]: r["c"]
            for r in conn.execute(
                "SELECT severity, COUNT(*) c FROM investigations GROUP BY severity"
            )
        }
        by_verdict = {
            r["verdict"]: r["c"]
            for r in conn.execute(
                "SELECT verdict, COUNT(*) c FROM investigations GROUP BY verdict"
            )
        }
        agg = conn.execute(
            """SELECT AVG(risk_score) avg_risk, AVG(duration_ms) avg_ms,
                      SUM(escalate) escalations FROM investigations"""
        ).fetchone()
    return {
        "total": total,
        "by_severity": by_sev,
        "by_verdict": by_verdict,
        "avg_risk": round(agg["avg_risk"] or 0, 1),
        "avg_duration_ms": int(agg["avg_ms"] or 0),
        "escalations": agg["escalations"] or 0,
    }


def clear_investigations() -> int:
    with _lock, _connect() as conn:
        n = conn.execute("SELECT COUNT(*) c FROM investigations").fetchone()["c"]
        conn.execute("DELETE FROM investigations")
    return n


# ── raw alert inbox ──────────────────────────────────────────────

def record_alert(alert_id: str, payload: dict[str, Any], source: str) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO alerts (id, received_at, source, payload) VALUES (?,?,?,?)",
            (alert_id, _now(), source, json.dumps(payload, default=str)),
        )


def mark_alert_processed(alert_id: str, incident_id: str) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE alerts SET processed = 1, incident_id = ? WHERE id = ?",
            (incident_id, alert_id),
        )


def list_alerts(limit: int = 30) -> list[dict[str, Any]]:
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT id, received_at, source, processed, incident_id FROM alerts "
            "ORDER BY received_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── intel cache (respects strict free-tier rate limits) ──────────

def cache_get(key: str, max_age_h: int = 24) -> dict[str, Any] | None:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT verdict, fetched_at FROM ioc_cache WHERE key = ?", (key,)).fetchone()
    if not row:
        return None
    from datetime import datetime, timedelta, timezone

    try:
        fetched = datetime.fromisoformat(row["fetched_at"])
    except ValueError:
        return None
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - fetched > timedelta(hours=max_age_h):
        return None
    return json.loads(row["verdict"])


def cache_put(key: str, verdict: dict[str, Any]) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO ioc_cache (key, verdict, fetched_at) VALUES (?,?,?)",
            (key, json.dumps(verdict, default=str), _now()),
        )


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
