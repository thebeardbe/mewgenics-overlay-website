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
                analysis TEXT NOT NULL DEFAULT '{}',
                related TEXT NOT NULL DEFAULT '[]',
                activity TEXT NOT NULL DEFAULT '[]'
            )
            """
        )
        # migrate older databases that predate the related-links column
        cols = [r[1] for r in conn.execute("PRAGMA table_info(reports)")]
        if "related" not in cols:
            conn.execute(
                "ALTER TABLE reports ADD COLUMN related TEXT NOT NULL DEFAULT '[]'")
        # migrate databases that predate the admin-comments column
        if "comments" not in cols:
            conn.execute(
                "ALTER TABLE reports ADD COLUMN comments TEXT NOT NULL "
                "DEFAULT '[]'")
        # migrate databases that predate the append-only activity timeline
        if "activity" not in cols:
            conn.execute(
                "ALTER TABLE reports ADD COLUMN activity TEXT NOT NULL "
                "DEFAULT '[]'")
            # fold any legacy comments column entries into the timeline
            legacy = conn.execute(
                "SELECT id, comments FROM reports WHERE comments <> '[]'"
            ).fetchall()
            for rid_, raw in legacy:
                old = _json_list(raw, [])
                if not old:
                    continue
                act = [_json_list(r[0], []) for r in conn.execute(
                    "SELECT activity FROM reports WHERE id = ?", (rid_,))]
                act = act[0] if act else []
                merged = [dict(c) for c in old]
                merged.extend(act)
                merged.sort(key=lambda e: (float(e.get("ts") or 0.0),
                                           str(e.get("author") or "")))
                for i, e in enumerate(merged, 1):
                    e["seq"] = i
                    e.setdefault("kind", "comment")
                    e.setdefault("text", "")
                    e.setdefault("actor", e.get("author") or "system")
                    e.setdefault("body", e.get("body") or "")
                    e.setdefault("role", "admin")
                    e.setdefault("meta", None)
                conn.execute(
                    "UPDATE reports SET activity = ?, comments = '[]' "
                    "WHERE id = ?",
                    (json.dumps(merged, ensure_ascii=False), rid_))
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL DEFAULT '',
                github_id TEXT,
                github_login TEXT,
                display_name TEXT NOT NULL DEFAULT '',
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
        ucols = [r[1] for r in conn.execute("PRAGMA table_info(users)")]
        if "display_name" not in ucols:
            conn.execute(
                "ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL "
                "DEFAULT ''")


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
    created_ts = time.time()
    with _lock, _connect() as conn:
        conn.execute(
            """
            INSERT INTO reports (id, created, status, category, name, contact,
                                 title, body, log, app_version, game_patch)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rid, created_ts, "open",
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
        # every ticket starts its append-only activity timeline with 'created'
        conn.execute(
            "UPDATE reports SET activity = ? WHERE id = ?",
            (json.dumps([{
                "seq": 1, "ts": created_ts, "kind": "created",
                "actor": _s(report.get("name"), "system", 80) or "system",
                "role": "player", "text": "report created", "body": "",
                "meta": None,
            }]), rid),
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


def _json_list(value, default):
    try:
        data = json.loads(value) if value else default
    except ValueError:
        return default
    return data if isinstance(data, list) else default


def _user_display_map(ids) -> dict:
    """id -> current display name (falling back to the login username)."""
    ids = [i for i in ids if i is not None]
    if not ids:
        return {}
    with _lock, _connect() as conn:
        ph = ",".join("?" for _ in ids)
        rows = conn.execute(
            f"SELECT id, username, display_name FROM users WHERE id IN ({ph})",
            ids).fetchall()
    return {r["id"]: (r["display_name"] or r["username"]) for r in rows}


def _resolve_activity(reports: list[dict]) -> None:
    """Replace stored usernames on user events with current display names.

    Events keep the acting user's *id* (append-only); the name shown is
    resolved at read time, so a rename in People is reflected everywhere
    immediately — no baked-in copies to go stale.
    """
    ids = set()
    for r in reports:
        for e in r.get("activity") or []:
            if e.get("actor_type") == "user" and e.get("actor_id") is not None:
                ids.add(e["actor_id"])
    names = _user_display_map(ids)
    for r in reports:
        for e in r.get("activity") or []:
            if e.get("actor_type") == "user":
                shown = names.get(e.get("actor_id"))
                if shown:
                    e["actor"] = shown


def _parse_reports(rows) -> list[dict]:
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["analysis"] = json.loads(d.get("analysis") or "{}")
        except ValueError:
            d["analysis"] = {}
        d["related"] = _json_list(d.get("related"), [])
        d["comments"] = _json_list(d.get("comments"), [])
        d["activity"] = _json_list(d.get("activity"), [])
        out.append(d)
    _resolve_activity(out)
    return out


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
    return _parse_reports(rows)


def get_report(rid: str) -> dict | None:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (rid,)).fetchone()
    if row is None:
        return None
    return _parse_reports([row])[0]


def _append_event(conn, rid: str, entry: dict) -> dict | None:
    """Append an immutable activity entry (caller holds the connection).

    Every entry gets an incrementing ``seq`` and timestamp; entries are never
    mutated later except ``comment`` entries gaining ``deleted`` markers.
    """
    row = conn.execute("SELECT activity FROM reports WHERE id = ?",
                       (rid,)).fetchone()
    if row is None:
        return None
    act = _json_list(row[0], [])
    e = dict(entry)
    e["seq"] = len(act) + 1
    e.setdefault("ts", time.time())
    e["actor"] = _s(e.get("actor"), "system", 80)
    e["role"] = _s(e.get("role"), "", 24)
    e["text"] = _s(e.get("text"), "", 300)
    e["body"] = _s(e.get("body"), "", 20000)
    e.setdefault("meta", None)
    # structured actor: user events keep the id (names resolve at read time),
    # machine events are typed so the UI can badge them (auto/system/player)
    e["actor_id"] = e.get("actor_id")
    if not e.get("actor_type"):
        if e.get("actor_id") is not None:
            e["actor_type"] = "user"
        elif str(e.get("actor")) == "auto-triage":
            e["actor_type"] = "auto"
        else:
            e["actor_type"] = "system"
    act.append(e)
    conn.execute("UPDATE reports SET activity = ? WHERE id = ?",
                 (json.dumps(act, ensure_ascii=False), rid))
    return e


def log_event(rid: str, kind: str, text: str, actor: str = "system",
              role: str = "", body: str = "",
              meta: dict | None = None,
              actor_id: int | None = None) -> dict | None:
    """Public helper: append an event to a ticket's timeline."""
    with _lock, _connect() as conn:
        return _append_event(conn, rid, {
            "kind": kind, "text": text, "actor": actor, "role": role,
            "body": body, "meta": meta, "actor_id": actor_id})


def add_comment(rid: str, author: str, role: str, body: str,
                actor_id: int | None = None) -> dict | None:
    """Append a comment/note event to a report; returns it (or None)."""
    with _lock, _connect() as conn:
        return _append_event(conn, rid, {
            "kind": "comment", "text": "", "actor": author,
            "role": role, "body": _s(body, "", 20000),
            "actor_id": actor_id})


def delete_comment(rid: str, seq: int, actor: str = "system",
                   role: str = "", actor_id: int | None = None) -> bool:
    """Mark a comment event as removed — append-only, nothing is erased.

    The original comment stays in the timeline (flagged ``deleted``) and a
    ``comment_removed`` event is appended so the audit trail is complete.
    """
    with _lock, _connect() as conn:
        row = conn.execute("SELECT activity FROM reports WHERE id = ?",
                           (rid,)).fetchone()
        if row is None:
            return False
        act = _json_list(row[0], [])
        target = next((e for e in act
                       if e.get("seq") == seq and e.get("kind") == "comment"),
                      None)
        if target is None or target.get("deleted"):
            return False
        target["deleted"] = True
        target["deleted_by"] = _s(actor, "system", 80)
        target["deleted_ts"] = time.time()
        conn.execute("UPDATE reports SET activity = ? WHERE id = ?",
                     (json.dumps(act, ensure_ascii=False), rid))
        _append_event(conn, rid, {
            "kind": "comment_removed",
            "text": f"removed comment #{seq}",
            "actor": actor, "role": role, "actor_id": actor_id})
    return True


def link_reports(a: str, b: str, actor: str = "system",
                 role: str = "", actor_id: int | None = None) -> None:
    """Link two reports symmetrically and log it on both timelines."""
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT id, related FROM reports WHERE id IN (?, ?)", (a, b)
        ).fetchall()
        rel = {r["id"]: _json_list(r["related"], []) for r in rows}
        for rid, others in ((a, b), (b, a)):
            lst = rel.get(rid, [])
            if others not in lst:
                lst.append(others)
                conn.execute(
                    "UPDATE reports SET related = ? WHERE id = ?",
                    (json.dumps(lst[-12:], ensure_ascii=False), rid))
                _append_event(conn, rid, {
                    "kind": "link", "text": f"linked to #{others}",
                    "actor": actor, "role": role,
                    "meta": {"target": others}, "actor_id": actor_id})


def update_status(rid: str, status: str, actor: str = "system",
                  role: str = "", actor_id: int | None = None) -> bool:
    """Change a report's status and record it on the timeline."""
    with _lock, _connect() as conn:
        row = conn.execute("SELECT status FROM reports WHERE id = ?",
                           (rid,)).fetchone()
        if row is None:
            return False
        old = row[0]
        if old != status:
            conn.execute("UPDATE reports SET status = ? WHERE id = ?",
                         (status, rid))
            _append_event(conn, rid, {
                "kind": "status",
                "text": f"changed status: {old} → {status}",
                "actor": actor, "role": role,
                "meta": {"old": old, "new": status}, "actor_id": actor_id})
    return True


def set_tags(rid: str, severity: str | None, category: str | None,
             actor: str = "system", role: str = "",
             actor_id: int | None = None) -> None:
    """Merge edited tags into the analysis JSON and log what changed."""
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT analysis, category FROM reports WHERE id = ?",
            (rid,)).fetchone()
        if row is None:
            return
        try:
            analysis = json.loads(row[0] or "{}")
        except ValueError:
            analysis = {}
        if not isinstance(analysis, dict):
            analysis = {}
        old_sev = analysis.get("severity")
        old_cat = analysis.get("category") or row[1]
        if severity:
            analysis["severity"] = severity
        if category:
            analysis["category"] = category
        conn.execute(
            "UPDATE reports SET analysis = ?, category = ? WHERE id = ?",
            (json.dumps(analysis, ensure_ascii=False),
             category or row[1], rid))
        parts = []
        if severity and severity != old_sev:
            parts.append(f"severity: {old_sev or '—'} → {severity}")
        if category and category != old_cat:
            parts.append(f"category: {old_cat or '—'} → {category}")
        if parts:
            _append_event(conn, rid, {
                "kind": "tags",
                "text": "updated tags — " + " · ".join(parts),
                "actor": actor, "role": role, "actor_id": actor_id})


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


def ensure_owner(username: str, password: str,
                 display_name: str = "") -> None:
    """Create/refresh the local owner account (no-op when password empty).

    A display name is applied on first creation or when explicitly given (env
    BGBOX_ADMIN_NAME); otherwise an existing owner keeps the name they chose
    in the People page across restarts.
    """
    if not password:
        return
    now = time.time()
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT id, display_name FROM users WHERE role = 'owner'"
        ).fetchone()
        if row:
            name = display_name or row["display_name"] or username
            conn.execute(
                "UPDATE users SET username = ?, password_hash = ?, "
                "display_name = ?, status = 'approved' WHERE id = ?",
                (username, _encrypt_password(password), name, row["id"]))
        else:
            conn.execute(
                "INSERT INTO users (username, password_hash, display_name, "
                "role, status, created) VALUES (?, ?, ?, 'owner', "
                "'approved', ?)",
                (username, _encrypt_password(password),
                 display_name or username, now))


def set_display_name(user_id: int, name: str) -> dict | None:
    """Set a user's public display name (empty resets to their username)."""
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            return None
        clean = name.strip()[:80] or row["username"]
        conn.execute(
            "UPDATE users SET display_name = ? WHERE id = ?",
            (clean, user_id))
        out = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(out)


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
