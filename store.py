"""SQLite storage for bug reports (thread-safe).

A single JSON column holds the LLM analysis so schema stays boring.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid

DATA_DIR = os.environ.get("BGBOX_DATA", "./data")
DB_PATH = os.path.join(DATA_DIR, "bugbox.db")
_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    with _lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                created REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                category TEXT NOT NULL DEFAULT 'other',
                name TEXT NOT NULL DEFAULT '',
                contact TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                log TEXT NOT NULL DEFAULT '',
                app_version TEXT NOT NULL DEFAULT '',
                game_patch TEXT NOT NULL DEFAULT '',
                analysis TEXT NOT NULL DEFAULT '{}'
            )
            """
        )


def add(report: dict) -> str:
    rid = uuid.uuid4().hex[:12]
    with _lock, _connect() as conn:
        conn.execute(
            """
            INSERT INTO reports (id, created, status, category, name, contact,
                                 title, body, log, app_version, game_patch)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rid, time.time(), "open", report.get("category", "other"),
                report.get("name", "")[:80], report.get("contact", "")[:160],
                (report.get("title") or "Untitled")[:160],
                report.get("body", ""), report.get("log", ""),
                report.get("app_version", "")[:32],
                report.get("game_patch", "")[:64],
            ),
        )
    return rid


def set_analysis(rid: str, analysis: dict) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE reports SET analysis = ? WHERE id = ?",
            (json.dumps(analysis, ensure_ascii=False), rid),
        )


def list_reports(status: str | None = None, limit: int = 200) -> list[dict]:
    q = "SELECT * FROM reports"
    args: list = []
    if status:
        q += " WHERE status = ?"
        args.append(status)
    q += " ORDER BY created DESC LIMIT ?"
    args.append(limit)
    with _lock, _connect() as conn:
        rows = conn.execute(q, args).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["analysis"] = json.loads(d.get("analysis") or "{}")
        except ValueError:
            d["analysis"] = {}
        out.append(d)
    return out


def get_report(rid: str) -> dict | None:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (rid,)).fetchone()
    if row is None:
        return None
    d = dict(row)
    try:
        d["analysis"] = json.loads(d.get("analysis") or "{}")
    except ValueError:
        d["analysis"] = {}
    return d


def update_status(rid: str, status: str) -> None:
    with _lock, _connect() as conn:
        conn.execute("UPDATE reports SET status = ? WHERE id = ?", (status, rid))


def delete_report(rid: str) -> None:
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM reports WHERE id = ?", (rid,))
