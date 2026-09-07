"""SQLite storage for bug reports, users and sessions (thread-safe).

A single JSON column holds the LLM analysis so schema stays boring. Users
are multi-tenant admins: one local `owner` (from env) plus GitHub-linked
accounts that start as `pending` until the owner approves them.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid

DATA_DIR = os.environ.get("BGBOX_DATA", "./data")
DB_PATH = os.path.join(DATA_DIR, "bugbox.db")
_lock = threading.Lock()

_PBKDF2_ROUNDS = 200_000


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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL DEFAULT '',
                github_id TEXT,
                github_login TEXT,
                role TEXT NOT NULL DEFAULT 'admin',
                status TEXT NOT NULL DEFAULT 'approved',
                created REAL NOT NULL,
                UNIQUE(username),
                UNIQUE(github_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created REAL NOT NULL
            )
            """
        )


# ── reports (unchanged API) ────────────────────────────────────────────────

def _s(value, default: str = "", maxlen: int = 0) -> str:
    """Coerce an untrusted report field to a bounded string."""
    if isinstance(value, bool):
        value = "1" if value else "0"
    elif not isinstance(value, (str, int, float)):
        return default
    s = str(value)
    return s[:maxlen] if maxlen else s


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
                rid, time.time(), "open",
                _s(report.get("category"), "other", 40),
                _s(report.get("name"), "", 80),
                _s(report.get("contact"), "", 160),
                _s(report.get("title"), "Untitled", 160),
                _s(report.get("body"), "", 200_000),
                _s(report.get("log"), "", 200_000),
                _s(report.get("app_version"), "", 32),
                _s(report.get("game_patch"), "", 64),
            ),
        )
    return rid


def set_analysis(rid: str, analysis: dict) -> None:
    if not isinstance(analysis, dict):
        analysis = {}
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


# ── users & sessions (multi-tenant admins) ────────────────────────────────

def _encrypt_password(password: str) -> str:
    salt = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ROUNDS)
    return f"{salt}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
        check = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt),
            _PBKDF2_ROUNDS)
        return hmac_compare(digest, check.hex())
    except Exception:
        return False


def verify_password(password: str, stored: str) -> bool:
    """Public wrapper: verify a password against a stored pbkdf2 hash."""
    return _verify_password(password, stored)


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time string compare."""
    import hmac
    return hmac.compare_digest(a, b)


def ensure_owner(username: str, password: str) -> None:
    """Create/refresh the local owner account (no-op when password empty)."""
    if not password:
        return
    now = time.time()
    with _lock, _connect() as conn:
        row = conn.execute("SELECT id FROM users WHERE role = 'owner'").fetchone()
        if row:
            conn.execute(
                "UPDATE users SET username = ?, password_hash = ?, "
                "status = 'approved' WHERE id = ?",
                (username, _encrypt_password(password), row["id"]))
        else:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, status, "
                "created) VALUES (?, ?, 'owner', 'approved', ?)",
                (username, _encrypt_password(password), now))


def user_by_username(username: str) -> dict | None:
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None


def user_by_github(github_id: str | None, github_login: str | None) -> dict | None:
    """Find a user by numeric GitHub id, then by login (owner may pre-approve
    a login before the person ever connects)."""
    with _lock, _connect() as conn:
        row = None
        if github_id:
            row = conn.execute(
                "SELECT * FROM users WHERE github_id = ?", (github_id,)).fetchone()
        if row is None and github_login:
            row = conn.execute(
                "SELECT * FROM users WHERE github_login = ?",
                (github_login,)).fetchone()
    return dict(row) if row else None


def create_github_user(github_id: str, github_login: str,
                       status: str = "pending") -> dict:
    now = time.time()
    username = github_login
    with _lock, _connect() as conn:
        existing = conn.execute(
            "SELECT * FROM users WHERE github_login = ? OR github_id = ?",
            (github_login, github_id)).fetchone()
        if existing:
            # Adopt an owner pre-approval (row created by login only) and
            # attach the numeric id; the existing status is kept, so a
            # pre-approved person stays approved.
            conn.execute(
                "UPDATE users SET github_login = ?, github_id = ? "
                "WHERE id = ?", (github_login, github_id, existing["id"]))
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (existing["id"],)).fetchone()
        else:
            conn.execute(
                "INSERT INTO users (username, github_id, github_login, role, "
                "status, created) VALUES (?, ?, ?, 'admin', ?, ?)",
                (username, github_id, github_login, status, now))
            row = conn.execute(
                "SELECT * FROM users WHERE github_id = ?", (github_id,)
            ).fetchone()
    return dict(row)


def add_github_preapproval(github_login: str) -> dict | None:
    """Owner pre-approves a GitHub login before they ever connect."""
    github_login = github_login.strip()
    if not github_login or len(github_login) > 40:
        return None
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE github_login = ?",
            (github_login,)).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO users (username, github_login, role, status, "
                "created) VALUES (?, ?, 'admin', 'approved', ?)",
                (github_login, github_login, time.time()))
            row = conn.execute(
                "SELECT * FROM users WHERE github_login = ?",
                (github_login,)).fetchone()
    return dict(row)


def set_user_status(user_id: int, status: str) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE users SET status = ? WHERE id = ?", (status, user_id))


def delete_user(user_id: int) -> None:
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


def list_users() -> list[dict]:
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM users ORDER BY role = 'owner' DESC, status, "
            "username").fetchall()
    return [dict(r) for r in rows]


def create_session(user_id: int) -> str:
    token = uuid.uuid4().hex + uuid.uuid4().hex
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created) VALUES (?, ?, ?)",
            (token, user_id, time.time()))
    return token


def session_user(token: str | None) -> dict | None:
    if not token:
        return None
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token = ?", (token,)).fetchone()
    return dict(row) if row else None


def delete_session(token: str) -> None:
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def delete_sessions_for_user(user_id: int) -> None:
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
