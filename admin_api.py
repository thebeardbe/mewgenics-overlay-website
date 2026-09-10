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
