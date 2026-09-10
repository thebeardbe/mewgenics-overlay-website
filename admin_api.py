"""Owner-only people management (extracted from app.py).

Pure logic: the route layer does authentication/owner checks, these
functions do validation and return ``(payload, status_code)``.
"""

from __future__ import annotations

import store


def find_user(uid: int) -> dict | None:
    for u in store.list_users():
        if u["id"] == uid:
            return u
    return None


def public_users() -> list[dict]:
    """User rows without password hashes, even for the owner."""
    return [{k: v for k, v in u.items() if k != "password_hash"}
            for u in store.list_users()]


def preapprove(login: str):
    created = store.add_github_preapproval(login)
    if created is None:
        return {"error": "invalid github login"}, 400
    return created, 200


def change_status(actor: dict, uid: int, status: str):
    if status not in {"approved", "pending", "denied"}:
        return {"error": "bad status"}, 400
    target = find_user(uid)
    if target is None:
        return {"error": "not found"}, 404
    if target.get("role") == "owner":
        return {"error": "cannot change the owner"}, 400
    store.set_user_status(uid, status)
    if status != "approved":
        # Locked-out users must not keep live sessions.
        store.delete_sessions_for_user(uid)
    return {"ok": True}, 200


def rename(actor: dict, uid: int, name: str):
    target = find_user(uid)
    if target is None:
        return {"error": "not found"}, 404
    if target.get("role") == "owner" and target.get("id") != actor.get("id"):
        return {"error": "cannot rename the owner"}, 400
    updated = store.set_display_name(uid, name)
    return {"ok": True, "display_name": updated["display_name"]}, 200


def remove(uid: int):
    target = find_user(uid)
    if target is None:
        return {"error": "not found"}, 404
    if target.get("role") == "owner":
        return {"error": "cannot delete the owner"}, 400
    store.delete_user(uid)
    return {"ok": True}, 200


# ── ticket mutations (owner/developer admins) ──────────────────────────────
_TICKET_STATUSES = {"open", "triaged", "fixed", "wontfix", "duplicate"}


def _actor_fields(user: dict):
    return {
        "actor": user.get("username") or user.get("github_login") or "admin",
        "role": user.get("role") or "",
        "actor_id": user.get("id"),
    }


def set_status(user: dict, rid: str, status: str):
    if status not in _TICKET_STATUSES:
        return {"error": "bad status"}, 400
    if not store.exists(rid):
        return {"error": "not found"}, 404
    store.update_status(rid, status, **_actor_fields(user))
    return {"ok": True}, 200


def delete_ticket(rid: str):
    if not store.exists(rid):
        return {"error": "not found"}, 404
    store.delete_report(rid)
    return {"ok": True}, 200


def set_tags(user: dict, rid: str, severity: str, category: str):
    import llm
    sev = (severity or "").strip().lower()
    cat = (category or "").strip().lower()
    if sev and sev not in llm._SEVERITIES:
        return {"error": f"bad severity: {sev}"}, 400
    if cat and cat not in llm._CATEGORIES:
        return {"error": f"bad category: {cat}"}, 400
    if not store.exists(rid):
        return {"error": "not found"}, 404
    store.set_tags(rid, sev or None, cat or None, **_actor_fields(user))
    return {"ok": True}, 200


def add_comment(user: dict, rid: str, body: str):
    body = (body or "").strip()
    if not body:
        return {"error": "empty comment"}, 400
    entry = store.add_comment(
        rid,
        user.get("username") or user.get("github_login") or "admin",
        user.get("role") or "admin",
        body,
        actor_id=user.get("id"))
    if entry is None:
        return {"error": "not found"}, 404
    return entry, 200


def delete_comment(user: dict, rid: str, index: int):
    ok = store.delete_comment(rid, index, **_actor_fields(user))
    return ({"ok": True}, 200) if ok else ({"error": "not found"}, 404)


def link_tickets(user: dict, rid: str, target: str):
    target = (target or "").strip()
    if not target or target == rid:
        return {"error": "pick another ticket id"}, 400
    if not store.exists(target) or not store.exists(rid):
        return {"error": "not found"}, 404
    store.link_reports(rid, target, **_actor_fields(user))
    return {"ok": True}, 200
