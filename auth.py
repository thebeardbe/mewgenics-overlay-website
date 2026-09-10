"""GitHub OAuth for Bugbox (extracted from app.py).

Kept dependency-light: the route layer passes configuration in, so this
module can be unit-tested without importing the FastAPI app.
"""

from __future__ import annotations

import json
import logging
import secrets
import urllib.parse
import urllib.request

from fastapi import Request
from fastapi.responses import RedirectResponse

import store

log = logging.getLogger("bugbox.auth")


def redirect_uri(request: Request, configured: str) -> str:
    if configured:
        return configured
    return f"{request.url.scheme}://{request.url.netloc}/auth/github/callback"


def start_login(request: Request, *, client_id: str, configured_redirect: str,
                cookie_secure: bool) -> RedirectResponse:
    """Start GitHub OAuth (state cookie prevents CSRF on the callback)."""
    state = secrets.token_urlsafe(18)
    resp = RedirectResponse(
        "https://github.com/login/oauth/authorize?"
        + urllib.parse.urlencode({
            "client_id": client_id,
            "redirect_uri": redirect_uri(request, configured_redirect),
            "scope": "read:user",
            "state": state,
        }),
        status_code=303)
    resp.set_cookie("oauth_state", state, httponly=True, samesite="lax",
                    secure=cookie_secure, max_age=600)
    return resp


def complete_login(request: Request, code: str, state: str, *,
                   enabled: bool, client_id: str, client_secret: str,
                   configured_redirect: str, cookie_secure: bool,
                   login_cookie) -> RedirectResponse:
    """Exchange the OAuth code, then approve-or-pending the developer.

    ``login_cookie(resp, user_id)`` is the app's session-cookie helper, so
    this module never needs to know about CSRF/session details.
    """
    expected = request.cookies.get("oauth_state")
    if not enabled or not code or not state or not expected \
            or not store.hmac_compare(state, expected):
        return RedirectResponse("/login?bad=1", status_code=303)
    try:
        token = access_token(code, request, client_id=client_id,
                             client_secret=client_secret,
                             configured_redirect=configured_redirect)
        profile = fetch_user(token)
    except Exception:
        log.exception("github oauth failed")
        return RedirectResponse("/login?bad=1", status_code=303)
    gh_id = str(profile.get("id") or "")
    gh_login = str(profile.get("login") or "")
    if not gh_id or not gh_login:
        return RedirectResponse("/login?bad=1", status_code=303)
    user = store.user_by_github(gh_id, gh_login)
    if user is None:
        user = store.create_github_user(gh_id, gh_login, status="pending")
    if user.get("status") != "approved":
        return RedirectResponse(
            f"/access?login={urllib.parse.quote(gh_login)}"
            f"&status={user.get('status', 'pending')}",
            status_code=303)
    resp = RedirectResponse("/admin", status_code=303)
    login_cookie(resp, user["id"])
    return resp


def access_token(code: str, request: Request, *, client_id: str,
                 client_secret: str, configured_redirect: str) -> str:
    payload = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri(request, configured_redirect),
    }).encode()
    req = urllib.request.Request(
        "https://github.com/login/oauth/access_token", data=payload,
        headers={"Accept": "application/json",
                 "User-Agent": "bugbox-oauth"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    token = data.get("access_token")
    if not token:
        raise RuntimeError("no access_token in github response")
    return str(token)


def fetch_user(token: str) -> dict:
    req = urllib.request.Request(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json",
                 "User-Agent": "bugbox-oauth"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))
