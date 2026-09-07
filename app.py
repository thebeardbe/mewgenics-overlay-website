"""Bugbox: self-hosted bug intake with LLM triage.

FastAPI app. Two audiences:
  * players  -> GET /report  (no account needed, paste debug info)
  * you      -> GET /admin   (login, list/read/triage reports)
Reports may also arrive as JSON POSTs from the overlay itself.

Admin access is multi-tenant: one local `owner` account (from environment
variables) plus GitHub-linked developer accounts. New GitHub accounts start
as `pending` and only gain access after the owner approves them on the
People page (/admin/people). GitHub sign-in is optional: when
GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET are not configured, the login page
only offers the local owner account.

Run:  uvicorn app:app --host 0.0.0.0 --port 8000   (see compose.yaml)
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import secrets
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

import llm
import store

store.init()
app = FastAPI(title="Bugbox")

logger = logging.getLogger("bugbox")

TEMPLATES = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR), check_dir=False),
          name="static")

ADMIN_USER = os.environ.get("BGBOX_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("BGBOX_ADMIN_PASS", "")
COOKIE_KEY = os.environ.get("BGBOX_COOKIE_KEY", "change-me")
COOKIE_SECURE = os.environ.get("BGBOX_COOKIE_SECURE", "").lower() not in (
    "", "0", "false", "no")

# GitHub OAuth (optional). Register an OAuth App on GitHub with the callback
# URL set to your deployed /auth/github/callback.
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.environ.get("GITHUB_REDIRECT_URI", "")
GITHUB_ENABLED = bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET)

MAX_BODY_BYTES = 400_000          # reject anything larger up front (nginx too)
REPORT_RATE_LIMIT = (10, 60)      # (max, window seconds) per IP
LOGIN_RATE_LIMIT = (5, 60)

# In-memory per-IP rate buckets (restart resets them; fine for self-hosting).
_buckets: dict = {}
_bucket_lock = threading.Lock()

store.ensure_owner(ADMIN_USER, ADMIN_PASS)

if not ADMIN_PASS:
    logger.warning("BGBOX_ADMIN_PASS is not set; the local owner login is "
                   "DISABLED (fails closed). Set it in the environment.")
if COOKIE_KEY in ("", "change-me", "change-me-too"):
    logger.warning("BGBOX_COOKIE_KEY is unset or still the default. Set a "
                   "long random value so session cookies cannot be forged.")
if not GITHUB_ENABLED:
    logger.info("GitHub sign-in disabled (set GITHUB_CLIENT_ID and "
                "GITHUB_CLIENT_SECRET to enable developer accounts).")


@app.middleware("http")
async def _hardening(request: Request, call_next):
    """Payload cap + basic security headers on every response."""
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
        return Response("payload too large", status_code=413)
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "?"


def _throttled(key: str, limit: int, window: float) -> bool:
    """True when *key* has exceeded *limit* hits in *window* seconds."""
    now = time.monotonic()
    with _bucket_lock:
        bucket = _buckets.get(key)
        if bucket is None or now - bucket[0] > window:
            _buckets[key] = [now, 1]
            return False
        bucket[1] += 1
        return bucket[1] > limit


# ── auth ──────────────────────────────────────────────────────────────────

def _current_user(request: Request) -> dict | None:
    """The logged-in user, but only when they are still approved."""
    user = store.session_user(request.cookies.get("bugbox_admin"))
    if user is None or user.get("status") != "approved":
        return None
    return user


def _login_cookie(resp: Response, user_id: int) -> None:
    token = store.create_session(user_id)
    resp.set_cookie("bugbox_admin", token, httponly=True, samesite="lax",
                    secure=COOKIE_SECURE, max_age=60 * 60 * 24 * 30)


def _logout_cookie(resp: Response, request: Request) -> None:
    token = request.cookies.get("bugbox_admin")
    if token:
        store.delete_session(token)
    resp.delete_cookie("bugbox_admin")


def _render(name: str, **ctx) -> HTMLResponse:
    tpl = (TEMPLATES / name).read_text(encoding="utf-8")

    def _sub(m):
        key = m.group(1)
        return str(ctx.get(key, m.group(0)))

    # Only swap {word} placeholders; CSS braces ({ }) are left untouched.
    html_out = re.sub(r"\{(\w+)\}", _sub, tpl)
    return HTMLResponse(html_out)


def _github_redirect_uri(request: Request) -> str:
    if GITHUB_REDIRECT_URI:
        return GITHUB_REDIRECT_URI
    return f"{request.url.scheme}://{request.url.netloc}/auth/github/callback"


# ── latest-overlay-version (for the download buttons / version pill) ───────
_VERSION_URL = ("https://api.github.com/repos/thebeardbe/"
                "mewgenics-breeding-overlay/releases/latest")
_DEFAULT_VERSION = os.environ.get("BGBOX_OVERLAY_VERSION", "0.1.46")
_VERSION_TTL = 300.0
_version_cache = {"version": _DEFAULT_VERSION, "ts": 0.0}
_version_lock = threading.Lock()
_version_refreshing = False


def _fetch_github_version() -> str:
    """Fetch the newest overlay release tag (e.g. '0.1.46'); best-effort."""
    try:
        req = urllib.request.Request(
            _VERSION_URL,
            headers={"User-Agent": "bugbox-landing",
                     "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        tag = str(data.get("tag_name") or "").lstrip("v")
        if re.fullmatch(r"\d+\.\d+\.\d+", tag):
            return tag
    except Exception:
        pass
    return _version_cache["version"]


def latest_version() -> str:
    """Cached overlay version; refreshes in the background when stale."""
    global _version_refreshing
    now = time.time()
    with _version_lock:
        stale = now - _version_cache["ts"] > _VERSION_TTL
        if stale and not _version_refreshing:
            _version_refreshing = True

            def _refresh():
                global _version_refreshing
                try:
                    v = _fetch_github_version()
                    with _version_lock:
                        _version_cache["version"] = v
                        _version_cache["ts"] = time.time()
                finally:
                    _version_refreshing = False

            threading.Thread(target=_refresh, daemon=True).start()
        return _version_cache["version"]


# ── public surface ────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def home():
    return _render("index.html", version=latest_version())


@app.get("/report", response_class=HTMLResponse)
def report_page():
    return _render("report.html", report_url="/submit")


@app.post("/submit")
def submit(
    request: Request,
    category: str = Form("other"),
    title: str = Form(""),
    body: str = Form(""),
    log: str = Form(""),
    name: str = Form(""),
    contact: str = Form(""),
):
    if _throttled(f"report:{_client_ip(request)}", *REPORT_RATE_LIMIT):
        return JSONResponse(
            {"error": "too many reports, try again in a minute"},
            status_code=429)
    rid = store.add({
        "category": category, "title": title, "body": body,
        "log": log, "name": name, "contact": contact,
    })
    _analyze_in_background(rid)
    return _render("thanks.html", rid=rid)


@app.post("/api/report")
async def api_report(request: Request):
    """JSON endpoint the overlay (or power users) can POST to directly."""
    if _throttled(f"report:{_client_ip(request)}", *REPORT_RATE_LIMIT):
        return JSONResponse(
            {"error": "too many reports, try again in a minute"},
            status_code=429)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "expected JSON body"}, status_code=400)
    if not isinstance(data, dict):
        return JSONResponse({"error": "expected a JSON object"},
                            status_code=400)
    rid = store.add(data)
    _analyze_in_background(rid)
    return JSONResponse({"id": rid, "status": "open"})


def _analyze_in_background(rid: str) -> None:
    def job():
        try:
            report = store.get_report(rid)
            if report is None:
                return
            recent = [r for r in store.list_reports(limit=15) if r["id"] != rid]
            store.set_analysis(rid, llm.analyze(report, recent))
        except Exception:  # analysis must never break the request flow
            logger.exception("background analysis failed for %s", rid)
    threading.Thread(target=job, daemon=True).start()


# ── admin auth ────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    bad = ("<p class='bad'>Wrong user or password.</p>"
           if request.query_params.get("bad") else "")
    note = ""
    if request.query_params.get("note") == "gh-unavailable":
        note = ("<p class='bad'>GitHub sign-in is not enabled on this "
                "server.</p>")
    github_block = ""
    if GITHUB_ENABLED:
        github_block = (
            "<div class='or'>or</div>"
            "<a class='gh' href='/login/github'>GitHub developer sign-in</a>")
    return _render("login.html", bad=bad, note=note,
                   github_block=github_block)


@app.post("/login")
def login(request: Request, user: str = Form(""), password: str = Form("")):
    """Local owner login (the only local account)."""
    if _throttled(f"login:{_client_ip(request)}", *LOGIN_RATE_LIMIT):
        return RedirectResponse("/login?bad=1", status_code=303)
    owner = None
    if ADMIN_PASS:
        owner = store.user_by_username(ADMIN_USER)
    if owner and owner.get("role") == "owner" and owner.get("status") == \
            "approved" and store.hmac_compare(user, owner["username"]) \
            and store.verify_password(password, owner["password_hash"]):
        resp = RedirectResponse("/admin", status_code=303)
        _login_cookie(resp, owner["id"])
        return resp
    return RedirectResponse("/login?bad=1", status_code=303)


@app.get("/login/github")
def github_login(request: Request):
    """Start GitHub OAuth (state cookie prevents CSRF on the callback)."""
    if not GITHUB_ENABLED:
        return RedirectResponse("/login?note=gh-unavailable", status_code=303)
    if _throttled(f"login:{_client_ip(request)}", *LOGIN_RATE_LIMIT):
        return RedirectResponse("/login?bad=1", status_code=303)
    state = secrets.token_urlsafe(18)
    resp = RedirectResponse(
        "https://github.com/login/oauth/authorize?"
        + urllib.parse.urlencode({
            "client_id": GITHUB_CLIENT_ID,
            "redirect_uri": _github_redirect_uri(request),
            "scope": "read:user",
            "state": state,
        }),
        status_code=303)
    resp.set_cookie("oauth_state", state, httponly=True, samesite="lax",
                    secure=COOKIE_SECURE, max_age=600)
    return resp


@app.get("/auth/github/callback")
def github_callback(request: Request, code: str = "", state: str = ""):
    """Exchange the OAuth code, then approve-or-pending the developer."""
    expected = request.cookies.get("oauth_state")
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("oauth_state")
    if not GITHUB_ENABLED or not code or not state \
            or not expected or not store.hmac_compare(state, expected):
        return RedirectResponse("/login?bad=1", status_code=303)
    try:
        token = _gh_access_token(code, request)
        profile = _gh_user(token)
    except Exception:
        logger.exception("github oauth failed")
        return RedirectResponse("/login?bad=1", status_code=303)
    gh_id = str(profile.get("id") or "")
    gh_login = str(profile.get("login") or "")
    if not gh_id or not gh_login:
        return RedirectResponse("/login?bad=1", status_code=303)
    user = store.user_by_github(gh_id, gh_login)
    if user is None:
        user = store.create_github_user(gh_id, gh_login, status="pending")
    if user.get("status") != "approved":
        page = RedirectResponse(f"/access?login={urllib.parse.quote(gh_login)}"
                                f"&status={user.get('status', 'pending')}",
                                status_code=303)
        return page
    resp = RedirectResponse("/admin", status_code=303)
    _login_cookie(resp, user["id"])
    return resp


def _gh_access_token(code: str, request: Request) -> str:
    payload = urllib.parse.urlencode({
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
        "redirect_uri": _github_redirect_uri(request),
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


def _gh_user(token: str) -> dict:
    req = urllib.request.Request(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json",
                 "User-Agent": "bugbox-oauth"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


@app.get("/access", response_class=HTMLResponse)
def access_page(request: Request, login: str = "", status: str = ""):
    """Shown after a GitHub sign-in that is pending / denied."""
    safe_login = html.escape(login or "your account")
    safe_status = html.escape(status or "pending")
    if status == "denied":
        msg = (f"Access for <b>{safe_login}</b> was denied. If you believe "
               "this is a mistake, ask the owner to re-approve you.")
    else:
        msg = (f"<b>{safe_login}</b> requested access. The owner must approve "
               "the account on the People page before it can sign in.")
    return _render("access.html", message=msg, status=safe_status)


@app.get("/logout")
def logout(request: Request):
    resp = RedirectResponse("/login", status_code=303)
    _logout_cookie(resp, request)
    return resp


# ── admin ─────────────────────────────────────────────────────────────────
@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    user = _current_user(request)
    if user is None:
        return RedirectResponse("/login")
    people_link = ('<a href="/admin/people" style="color:var(--muted);'
                   'font-size:12px;margin-left:12px">People</a>'
                   if user.get("role") == "owner" else "")
    return _render("admin.html", people_link=people_link)


@app.get("/admin/people", response_class=HTMLResponse)
def people_page(request: Request):
    user = _current_user(request)
    if user is None:
        return RedirectResponse("/login")
    if user.get("role") != "owner":
        return RedirectResponse("/admin")
    return _render("people.html")


@app.get("/api/tickets")
def api_tickets(request: Request, status: str | None = None):
    if _current_user(request) is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return store.list_reports(status)


@app.post("/api/tickets/{rid}/status")
def api_status(request: Request, rid: str, status: str = Form("")):
    if _current_user(request) is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if status in {"open", "triaged", "fixed", "wontfix", "duplicate"}:
        store.update_status(rid, status)
    return {"ok": True}


@app.post("/api/tickets/{rid}/delete")
def api_delete(request: Request, rid: str):
    if _current_user(request) is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    store.delete_report(rid)
    return {"ok": True}


# ── people management (owner only) ────────────────────────────────────────
def _require_owner(request: Request):
    user = _current_user(request)
    if user is None:
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    if user.get("role") != "owner":
        return None, JSONResponse({"error": "owner only"}, status_code=403)
    return user, None


@app.get("/api/users")
def api_users(request: Request):
    user, err = _require_owner(request)
    if err:
        return err
    return store.list_users()


@app.post("/api/users/github")
def api_users_github(request: Request, login: str = Form("")):
    user, err = _require_owner(request)
    if err:
        return err
    created = store.add_github_preapproval(login)
    if created is None:
        return JSONResponse({"error": "invalid github login"}, status_code=400)
    return created


@app.post("/api/users/{uid}/status")
def api_user_status(request: Request, uid: int,
                    status: str = Form("pending")):
    user, err = _require_owner(request)
    if err:
        return err
    if status not in {"approved", "pending", "denied"}:
        return JSONResponse({"error": "bad status"}, status_code=400)
    target = _user_or_404(uid)
    if target is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    if target.get("role") == "owner":
        return JSONResponse({"error": "cannot change the owner"},
                            status_code=400)
    store.set_user_status(uid, status)
    if status != "approved":
        # Locked-out users must not keep live sessions.
        store.delete_sessions_for_user(uid)
    return {"ok": True}


@app.post("/api/users/{uid}/delete")
def api_user_delete(request: Request, uid: int):
    user, err = _require_owner(request)
    if err:
        return err
    target = _user_or_404(uid)
    if target is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    if target.get("role") == "owner":
        return JSONResponse({"error": "cannot delete the owner"},
                            status_code=400)
    store.delete_user(uid)
    return {"ok": True}


def _user_or_404(uid: int) -> dict | None:
    for u in store.list_users():
        if u["id"] == uid:
            return u
    return None
