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
import logging
import re
import os
import socket
socket.setdefaulttimeout(15)   # DNS hangs cannot stall threads
import threading
import time
import urllib.parse
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.exceptions import HTTPException as StarletteHTTPException
from api_utils import api_response as _api

import admin_api
import auth
import error_pages
import llm
import store
# The overlay-version cache, its GitHub fetch and its on-disk persistence
# live in version_cache.py; app.py keeps the VERSIONS object and
# latest_version() for the pages that render the version.
from version_cache import VERSIONS, latest_version  # noqa: F401

store.init()
app = FastAPI(title="Bugbox")

logger = logging.getLogger("bugbox")
# Uvicorn configures only its own loggers; without this, INFO lines are dropped.
logging.basicConfig(level=logging.INFO)
TEMPLATES = Path(__file__).parent / "templates"
JINJA = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
    autoescape=select_autoescape(["html"]),
    cache_size=200,
)
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR), check_dir=False),
          name="static")
FAVICON = STATIC_DIR / "favicon.ico"


@app.get("/favicon.ico", include_in_schema=False)
def favicon(request: Request) -> Response:
    """Serve the tab icon from the root path browsers ask for unprompted.

    Without this route every page load fell through to the 404 handler and
    paid for a full error-page render.
    """
    try:
        data = FAVICON.read_bytes()
    except OSError as exc:
        logger.warning("favicon.ico unreadable at %s: %s", FAVICON, exc)
        return _error_response(request, 404)
    return Response(content=data, media_type="image/x-icon",
                    headers={"Cache-Control": "public, max-age=86400"})

# ── transport / deployment expectations ─────────────────────────────────────
# BGBOX_HTTPS=1 when the reverse proxy terminates TLS: enables HSTS and is
# the recommended companion of BGBOX_COOKIE_SECURE=1.
HTTPS = os.environ.get("BGBOX_HTTPS", "").lower() not in (
    "", "0", "false", "no")
# Optional explicit allowlist of origins allowed to POST (space/comma list).
# Empty = same-origin only (Origin host must equal the Host header).
_ALLOWED_ORIGINS = {
    o.strip().lower() for o in
    (os.environ.get("BGBOX_ORIGINS", "").replace(",", " ").split()) if o.strip()
}

ADMIN_USER = os.environ.get("BGBOX_ADMIN_USER", "")
ADMIN_PASS = os.environ.get("BGBOX_ADMIN_PASS", "")
if not ADMIN_USER or not ADMIN_PASS:
    # A container with a broken login looks healthy, so refuse to start.
    logger.error("admin login is not configured: set both BGBOX_ADMIN_USER "
                 "(your sign-in name) and BGBOX_ADMIN_PASS (a long random "
                 "password) in .env, then restart; neither has a default.")
    raise SystemExit(2)
# Optional owner display name; defaults to the username (editable on People).
ADMIN_NAME = os.environ.get("BGBOX_ADMIN_NAME", "")
COOKIE_KEY = os.environ.get("BGBOX_COOKIE_KEY", "change-me")
COOKIE_SECURE = os.environ.get("BGBOX_COOKIE_SECURE", "").lower() not in (
    "", "0", "false", "no")

# GitHub OAuth (optional). Register an OAuth App on GitHub with the callback
# URL set to your deployed /auth/github/callback.
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.environ.get("GITHUB_REDIRECT_URI", "")
GITHUB_ENABLED = bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET)

# Optional self-hosted Umami page analytics. Pages that render the tag carry
# the script only when both values are set and the script URL is an https URL
# with a host and no credentials; any partial or malformed configuration logs
# one warning and stays off.
ANALYTICS_SCRIPT = os.environ.get("BGBOX_ANALYTICS_SCRIPT", "").strip()
ANALYTICS_ID = os.environ.get("BGBOX_ANALYTICS_ID", "").strip()
ANALYTICS_ORIGIN = ""
if ANALYTICS_SCRIPT and ANALYTICS_ID:
    _analytics_url = urllib.parse.urlsplit(ANALYTICS_SCRIPT)
    _analytics_host = _analytics_url.hostname or ""
    # A userinfo part (https://user:pass@host/x.js) passes a bare hostname
    # check but is not a valid policy host, so browsers refuse the script; a
    # malformed port raises, and an empty host is no host at all.
    _analytics_ok = bool(
        _analytics_url.scheme == "https" and _analytics_host
        and _analytics_url.username is None
        and _analytics_url.password is None)
    try:
        _analytics_port = _analytics_url.port if _analytics_ok else None
    except ValueError:
        _analytics_ok = False
        _analytics_port = None
    if _analytics_ok:
        # Built from the host and its port alone, so the origin can only ever
        # be https://host or https://host:port.
        _analytics_netloc = (f"[{_analytics_host}]" if ":" in _analytics_host
                             else _analytics_host)
        _analytics_suffix = f":{_analytics_port}" if _analytics_port else ""
        ANALYTICS_ORIGIN = f"https://{_analytics_netloc}{_analytics_suffix}"
    else:
        logger.warning(
            "BGBOX_ANALYTICS_SCRIPT must be an https URL with a host and no "
            "credentials, got %r; page analytics disabled", ANALYTICS_SCRIPT)
elif ANALYTICS_SCRIPT or ANALYTICS_ID:
    logger.warning(
        "page analytics needs both BGBOX_ANALYTICS_SCRIPT and "
        "BGBOX_ANALYTICS_ID, only %s is set; page analytics disabled",
        "BGBOX_ANALYTICS_SCRIPT" if ANALYTICS_SCRIPT else "BGBOX_ANALYTICS_ID")
# Exposed as Jinja globals instead of threading them through every route.
# Both are empty strings when analytics is off, so the templates stay silent.
JINJA.globals["analytics_script"] = ANALYTICS_SCRIPT if ANALYTICS_ORIGIN else ""
JINJA.globals["analytics_id"] = ANALYTICS_ID if ANALYTICS_ORIGIN else ""

MAX_BODY_BYTES = 400_000          # reject anything larger up front (nginx too)
_LOG_FIELD_MAX = 64               # cap request text in one log line
REPORT_RATE_LIMIT = (10, 60)      # (max, window seconds) per IP
LOGIN_RATE_LIMIT = (5, 60)
ADMIN_WRITE_RATE_LIMIT = (30, 60)   # per user per ticket

# In-memory per-IP rate buckets (restart resets them; fine for self-hosting).
class RateLimiter:
    """Per-key sliding-window limiter with TTL pruning and a public reset.

    Owning the state in an object (instead of module globals) gives tests a
    supported `reset()` instead of reaching into private dicts.
    """

    def __init__(self, ttl: float = 600.0) -> None:
        self._buckets: dict = {}
        self._lock = threading.Lock()
        self.ttl = ttl

    def allow(self, key: str, limit: int, window: float) -> bool:
        """True when *key* has exceeded *limit* hits in *window* seconds."""
        if len(self._buckets) > 2000:
            self.prune()
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None or now - bucket[0] > window:
                self._buckets[key] = [now, 1]
                return False
            bucket[1] += 1
            return bucket[1] > limit

    def status(self, key: str, limit: int, window: float) -> tuple[int, int]:
        """Read-only for *key*: (attempts left, seconds until the window
        frees, rounded up); counts no attempt, and 0 left means refused.
        """
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None or now - bucket[0] > window:
                return limit, 0
            left = max(0, limit - bucket[1])
            free_in = bucket[0] + window - now
            return left, (int(free_in) + 1 if left == 0 else 0)

    def prune(self, now=None) -> int:
        """Drop stale buckets (unbounded-memory guard). Returns count."""
        now = time.monotonic() if now is None else now
        with self._lock:
            stale = [k for k, (ts, _v) in self._buckets.items()
                     if now - ts > self.ttl]
            for k in stale:
                del self._buckets[k]
            return len(stale)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


RATE = RateLimiter()


def _throttled(key: str, limit: int, window: float) -> bool:
    return RATE.allow(key, limit, window)


def _prune_buckets(now=None) -> int:
    return RATE.prune(now)


def _admin_throttled(user: dict, rid: str) -> bool:
    """Per-user, per-ticket write throttle for admin mutations."""
    key = f"admin:{user.get('id')}:{rid}"
    return RATE.allow(key, *ADMIN_WRITE_RATE_LIMIT)


def _maintenance_loop() -> None:
    while True:
        time.sleep(600)
        try:
            _prune_buckets()
            store.prune_expired_sessions()
        except Exception:
            logger.exception("maintenance sweep failed")


_prev_owner = next((u for u in store.list_users() if u["role"] == "owner"), None)
store.ensure_owner(ADMIN_USER, ADMIN_PASS, ADMIN_NAME)
threading.Thread(target=_maintenance_loop, name="bugbox-maintenance",
                 daemon=True).start()
logger.info("admin login: user '%s' with the password from your .env "
            "(BGBOX_ADMIN_PASS)%s", ADMIN_USER,
            f"; owner renamed from '{(_prev_owner or {}).get('username')}'"
            if _prev_owner and _prev_owner["username"] != ADMIN_USER else "")
if len(ADMIN_PASS) < 12 or ADMIN_PASS.lower().startswith("change-me"):
    logger.warning("BGBOX_ADMIN_PASS looks short or placeholder-like. Use a "
                   "long random value (>= 12 chars).")
if COOKIE_KEY in ("", "change-me", "change-me-too"):
    logger.warning("BGBOX_COOKIE_KEY is unset or still the default. Set a "
                   "long random value so session cookies cannot be forged.")
if not GITHUB_ENABLED:
    logger.info("GitHub sign-in disabled (set GITHUB_CLIENT_ID and "
                "GITHUB_CLIENT_SECRET to enable developer accounts).")

# Log hardening: optional rotating log file. Only this file is scrubbed, the
# console handler is not.
LOG_FILE = os.environ.get("BGBOX_LOG_FILE", "")
if LOG_FILE:
    from logging.handlers import RotatingFileHandler

    # The values that must never reach the file (short values would redact
    # ordinary words, hence the length floor).
    _LOG_SECRETS = [v for v in (COOKIE_KEY, ADMIN_PASS, GITHUB_CLIENT_SECRET)
                    if v and len(v) >= 6]

    class _ScrubFormatter(logging.Formatter):
        """The single scrub point for the log file.

        It scrubs the rendered line, not the record: the traceback is
        appended by the formatter, and a parameterized call keeps its secret
        in record.args, so the formatted string is the only place that holds
        the values and the traceback together. A filter would also mutate the
        shared record and leak the mangled form to the other handlers."""

        def __init__(self):
            super().__init__(
                "%(asctime)s %(levelname)s %(name)s: %(message)s")

        def format(self, record: logging.LogRecord) -> str:
            line = super().format(record)
            for secret in _LOG_SECRETS:
                if secret in line:
                    line = line.replace(secret, "[redacted]")
            return line

    _fh = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5)
    _fh.setFormatter(_ScrubFormatter())
    logger.addHandler(_fh)



# ── content-security policies ──────────────────────────────────────────────
def _csp(*, inline: bool, analytics: bool) -> str:
    """One builder for every policy, so no directive list is written twice.

    *inline* allows the inline <style> that the standalone public pages and
    the error page carry. *analytics* adds the configured Umami origin, which
    its script is fetched from and beacons to, so it belongs in script-src and
    connect-src together; only a page that renders the tag is ever built with
    it, see _csp_for.
    """
    extra = f" {ANALYTICS_ORIGIN}" if analytics and ANALYTICS_ORIGIN else ""
    sources = "'self' 'unsafe-inline'" if inline else "'self'"
    return ("default-src 'self'; "
            f"script-src {sources}{extra}; "
            f"style-src {sources}; img-src 'self' data:; "
            f"font-src 'self'; connect-src 'self'{extra}; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


# Auth'd pages ship their CSS/JS from /static (no inline), so they get a
# strict policy without 'unsafe-inline'. Public marketing/landing pages are
# still allowed inline styles (they contain no inline scripts), and only a
# page that renders the analytics tag may reach the analytics origin.
_CSP_STRICT = _csp(inline=False, analytics=False)
_CSP_BASELINE = _csp(inline=True, analytics=False)
_CSP_PUBLIC = _csp(inline=True, analytics=True)

# The paths whose normal responses render the analytics tag: the landing
# page, the report form and the thanks page (the POST /submit response).
_ANALYTICS_PATHS = frozenset({"/", "/report", "/submit"})
# Private and machine surfaces: their normal responses get the strict policy
# and their error responses stay untracked (no tag, no origin). /auth is
# private because the OAuth callback carries an authorization code and a
# state value in its query string, and a code is a credential: an error there
# must never render a tracked page that reports that URL to analytics.
_PRIVATE_PREFIXES = ("/admin", "/login", "/api", "/auth")


def _renders_analytics(path: str, *, error: bool = False) -> bool:
    """Whether the response for *path* renders the analytics tag.

    The single decision behind the tag and the analytics origin in the
    policy. Normal responses render it only on _ANALYTICS_PATHS. An error
    response tracks every public path, because the failing URL is how a
    broken inbound link is found; _PRIVATE_PREFIXES stay untracked. With
    analytics off, nothing renders it.
    """
    if not ANALYTICS_ORIGIN:
        return False
    if error:
        return not path.startswith(_PRIVATE_PREFIXES)
    return path in _ANALYTICS_PATHS


def _csp_for(path: str) -> str:
    """The policy for a normal response on *path* (errors set their own).

    The analytics origin is granted only when _renders_analytics says the
    response carries the tag; other non-private paths keep the baseline
    policy, which still allows the standalone pages' inline styles.
    """
    if path.startswith(_PRIVATE_PREFIXES):
        return _CSP_STRICT
    if _renders_analytics(path):
        return _CSP_PUBLIC
    return _CSP_BASELINE


def _origin_allowed(request: Request) -> bool:
    """CSRF gate for state-changing requests, in decision order.

    First the BGBOX_ORIGINS allowlist, explicit operator configuration: an
    Origin whose netloc is listed is admitted whatever Sec-Fetch-Site says,
    cross-site included. The Origin header is browser-controlled, so this
    only admits the origins the operator chose.

    An Origin outside the allowlist goes to the fetch metadata, which the
    browser also controls, so it still holds when privacy settings make the
    browser serialize Origin as the literal "null": same-origin and none
    (typed URL or bookmark) are allowed, cross-site is rejected. Anything
    else (same-site, unknown, or absent: curl, the overlay's direct JSON
    POST) keeps the legacy rule: no Origin header means allowed, and an
    Origin netloc must be in BGBOX_ORIGINS when that list is set, else match
    the request Host. That allowlist exclusivity only applies to a request
    carrying no trustworthy fetch metadata, which is why this app's own
    forms are still admitted when the list is set and does not list them. A
    literal Origin: null (empty netloc) stays rejected.
    """
    origin = request.headers.get("origin")
    site = (request.headers.get("sec-fetch-site") or "").strip().lower()
    host = urllib.parse.urlsplit(origin).netloc.lower() if origin else ""
    if host and host in _ALLOWED_ORIGINS:
        ok = True
    elif site in ("same-origin", "none"):
        ok = True
    elif site == "cross-site":
        ok = False
    elif not origin:                  # non-browser clients (curl, tests)
        ok = True
    # Trustworthy fetch metadata was decided above, so for the rest the
    # allowlist is exclusive: matching this app's own Host is not enough.
    elif _ALLOWED_ORIGINS:
        ok = False
    else:
        ok = bool(host) and host == (request.headers.get("host") or "").lower()
    if not ok:
        logger.warning(
            "cross-origin request rejected: %s %s origin=%r sec-fetch-site=%r "
            "host=%r", request.method, request.url.path, origin or "",
            request.headers.get("sec-fetch-site") or "",
            request.headers.get("host") or "")
    return ok


def _security_headers(request: Request, resp: Response) -> Response:
    """Add the security headers to *resp*, never overwriting what it has.

    The error path calls this too, because the middleware's own early returns
    and the 500 never pass back through it. `setdefault` keeps a header a
    handler supplied, such as a 405's `Allow`; HSTS stays gated on HTTPS.
    """
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Robots-Tag", "noindex, nofollow")
    resp.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
    resp.headers.setdefault("Content-Security-Policy",
                            _csp_for(request.url.path))
    if HTTPS:
        resp.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains")
    return resp


@app.middleware("http")
async def _hardening(request: Request, call_next):
    """Payload cap + CSRF origin gate + security headers on every response."""
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
        return _error_response(request, 413)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if not _origin_allowed(request):
            return _error_response(
                request, 403,
                JSONResponse({"error": "cross-origin request rejected"},
                             status_code=403))
        _token = request.cookies.get("bugbox_admin")
        _path = request.url.path
        _public = _path in ("/submit", "/api/report", "/login")
        if _token and not _public:
            _sess = store.session_user(_token)
            _stored = (_sess or {}).get("csrf") or ""
            if _stored:
                _sent = request.headers.get("x-bugbox-csrf") or ""
                if not store.hmac_compare(_sent, _stored):
                    return _error_response(
                        request, 403,
                        JSONResponse({"error": "csrf check failed"},
                                     status_code=403))
    return _security_headers(request, await call_next(request))


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "?"



# ── auth ──────────────────────────────────────────────────────────────────

def _current_user(request: Request) -> dict | None:
    """The logged-in user, but only when they are still approved."""
    user = store.session_user(request.cookies.get("bugbox_admin"))
    if user is None or user.get("status") != "approved":
        return None
    return user


def _who(user: dict | None) -> str:
    """The name shown for a user on timelines (display name first)."""
    u = user or {}
    return (u.get("display_name") or u.get("username")
            or u.get("github_login") or "admin")


def _login_cookie(resp: Response, user_id: int) -> None:
    token = store.create_session(user_id)
    resp.set_cookie("bugbox_admin", token, httponly=True, samesite="lax",
                    secure=COOKIE_SECURE, max_age=60 * 60 * 24 * 30)
    sess = store.session_user(token)
    csrf = (sess or {}).get("csrf") or ""
    resp.set_cookie("bugbox_csrf", csrf, httponly=False, samesite="lax",
                    secure=COOKIE_SECURE, max_age=60 * 60 * 24 * 30)


def _logout_cookie(resp: Response, request: Request) -> None:
    token = request.cookies.get("bugbox_admin")
    if token:
        store.delete_session(token)
    resp.delete_cookie("bugbox_admin")


def _render_html(name: str, **ctx) -> str:
    """Render a template to a string (autoescaped, cached)."""
    return JINJA.get_template(name).render(**ctx)


def _render(name: str, **ctx) -> HTMLResponse:
    """Render a template through Jinja2 (autoescaped, cached)."""
    return HTMLResponse(_render_html(name, **ctx))


# ── friendly error pages ──────────────────────────────────────────────────
# The copy and the API/JSON carve-out live in error_pages.py; the wiring and
# the app-specific bodies (the two 403s, the report 429) stay here.

def _error_response(request: Request, code: int,
                    fallback: Response | None = None,
                    headers: dict | None = None) -> Response:
    """Error page for a browser, today's exact response for an API client.

    A browser error on a public path renders the tag, so it gets the public
    policy. A JSON client gets bytes, not a page, so no tag renders and it
    keeps the baseline policy; the shape is decided once here with the same
    predicate render_error uses, so the tag and the origin always agree.
    Errors under _PRIVATE_PREFIXES, and every error with analytics off, keep
    the baseline policy (no origin, inline styles allowed).
    The page itself is static copy plus an integer code, its styling is the
    inline <style> block that the strict policy would drop (which left a
    mistyped admin URL unstyled), and the policy is set explicitly here,
    which wins because _security_headers only fills absent values.
    """
    page = not error_pages.wants_json(request)
    tracked = page and _renders_analytics(request.url.path, error=True)
    resp = error_pages.render_error(
        request, code, fallback, headers=headers,
        render=lambda name, **ctx: _render_html(
            name, analytics_page=tracked, **ctx))
    resp.headers["Content-Security-Policy"] = (
        _CSP_PUBLIC if tracked else _CSP_BASELINE)
    return _security_headers(request, resp)


@app.exception_handler(404)
@app.exception_handler(405)
async def _routing_error(request: Request,
                         exc: StarletteHTTPException) -> Response:
    """404/405 used to reach a browser as raw JSON."""
    return _error_response(request, exc.status_code, headers=exc.headers)


@app.exception_handler(Exception)
async def _server_error(request: Request, exc: Exception) -> Response:
    """500: log the traceback, show a page that leaks nothing from it."""
    logger.error("unhandled error on %s %s", request.method,
                 request.url.path, exc_info=exc)
    return _error_response(request, 500)


# ── public surface ────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def home():
    return _public_page("index.html", version=latest_version(), path="/")


def _public_page(template: str, title: str = "", active: str = "",
                 *, path: str, **ctx) -> HTMLResponse:
    """Render a public page through Jinja2 (autoescaped, cached templates).

    The analytics flag comes from _renders_analytics, never a template
    default, so only a tracked path carries the tag.
    """
    ctx["nav_active"] = active
    ctx["analytics_page"] = _renders_analytics(path)
    return HTMLResponse(JINJA.get_template(template).render(**ctx))

@app.get("/report", response_class=HTMLResponse)
def report_page():
    return _public_page("report.html", "Report a problem", "active",
                        report_url="/submit", path="/report")


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
        return _error_response(
            request, 429,
            JSONResponse(
                {"error": "too many reports, try again in a minute"},
                status_code=429))
    rid = store.add({
        "category": category, "title": title, "body": body,
        "log": log, "name": name, "contact": contact,
    })
    _analyze_in_background(rid)
    return _public_page("thanks.html", "Thanks", rid=rid, path="/submit")


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
        return _api({"error": "expected JSON body"}, 400)
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
            analysis = llm.analyze(report, recent)
            store.set_analysis(rid, analysis)
            # Auto-actions are logged on the timeline with an explicit 'auto'
            # marker so nobody mistakes machine triage for a human decision.
            parts = []
            sev = analysis.get("severity")
            cat = analysis.get("category")
            if sev:
                parts.append(f"severity: {sev}")
            if cat:
                parts.append(f"category: {cat}")
            if parts:
                store.log_event(
                    rid, "auto_triage",
                    "auto-triage assigned " + " · ".join(parts),
                    actor="auto-triage", role="auto", meta={"auto": True})
            elif analysis.get("note"):
                store.log_event(
                    rid, "auto_triage", "auto-triage skipped — "
                    + str(analysis.get("note")),
                    actor="auto-triage", role="auto", meta={"auto": True})
        except Exception:  # analysis must never break the request flow
            logger.exception("background analysis failed for %s", rid)
    threading.Thread(target=job, daemon=True).start()


# ── admin auth ────────────────────────────────────────────────────────────
def _login_failed(request: Request, user: str, key: str) -> RedirectResponse:
    """Warn about one failed login, then send the visitor back with their count."""
    left, wait = RATE.status(key, *LOGIN_RATE_LIMIT)
    logger.warning("login failed for user %r from %s: %d left, %ds wait",
                   user[:_LOG_FIELD_MAX], _client_ip(request), left, wait)
    return RedirectResponse(f"/login?bad=1&left={left}&wait={wait}",
                            status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    bad = ""
    if request.query_params.get("bad"):
        # Only these clamped integers are interpolated, never request text.
        def num(name: str, high: int) -> int:
            raw = request.query_params.get(name, "")
            fits = raw.isdigit() and len(raw) <= len(str(high))
            return min(int(raw), high) if fits else 0
        left = num("left", LOGIN_RATE_LIMIT[0])
        wait = num("wait", LOGIN_RATE_LIMIT[1])
        bad = (f"<p class='bad'>Too many attempts. Try again in {wait} "
               f"second{'' if wait == 1 else 's'}.</p>" if wait else
               f"<p class='bad'>Wrong user or password. {left} "
               f"attempt{'' if left == 1 else 's'} left.</p>")
    note = ("<p class='bad'>GitHub sign-in is not enabled on this server.</p>"
            if request.query_params.get("note") == "gh-unavailable" else "")
    github_block = (
        "<div class='or'>or</div>"
        "<a class='gh' href='/login/github'>GitHub developer sign-in</a>"
        if GITHUB_ENABLED else "")
    return _render("login.html", bad=bad, note=note, github_block=github_block)


@app.post("/login")
def login(request: Request, user: str = Form(""), password: str = Form("")):
    """Local owner login (the only local account)."""
    key = f"login:{_client_ip(request)}"
    if _throttled(key, *LOGIN_RATE_LIMIT):
        return _login_failed(request, user, key)
    owner = store.user_by_username(ADMIN_USER)
    if owner and owner.get("role") == "owner" and owner.get("status") == \
            "approved" and store.hmac_compare(user, owner["username"]) \
            and store.verify_password(password, owner["password_hash"]):
        resp = RedirectResponse("/admin", status_code=303)
        _login_cookie(resp, owner["id"])
        return resp
    return _login_failed(request, user, key)


@app.get("/login/github")
def github_login(request: Request):
    """Start GitHub OAuth (state cookie prevents CSRF on the callback)."""
    if not GITHUB_ENABLED:
        return RedirectResponse("/login?note=gh-unavailable", status_code=303)
    if _throttled(f"login:{_client_ip(request)}", *LOGIN_RATE_LIMIT):
        return _login_failed(request, "", f"login:{_client_ip(request)}")
    return auth.start_login(request, client_id=GITHUB_CLIENT_ID,
                            configured_redirect=GITHUB_REDIRECT_URI,
                            cookie_secure=COOKIE_SECURE)


@app.get("/auth/github/callback")
def github_callback(request: Request, code: str = "", state: str = ""):
    """Exchange the OAuth code (logic lives in auth.py)."""
    resp = auth.complete_login(
        request, code, state, enabled=GITHUB_ENABLED,
        client_id=GITHUB_CLIENT_ID, client_secret=GITHUB_CLIENT_SECRET,
        configured_redirect=GITHUB_REDIRECT_URI, cookie_secure=COOKIE_SECURE,
        login_cookie=_login_cookie)
    resp.delete_cookie("oauth_state")
    return resp


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
    people_link = ('<a class="prim" href="/admin/people">👥 People</a>'
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
def api_tickets(request: Request, status: str | None = None,
                limit: int = 50, offset: int = 0):
    if _current_user(request) is None:
        return _api({"error": "unauthorized"}, 401)
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    tickets = store.list_reports(status, limit=limit, offset=offset)
    return {"tickets": tickets, "total": store.count_reports(status),
            "limit": limit, "offset": offset}


@app.get("/api/tickets/{rid}")
def api_ticket_detail(request: Request, rid: str):
    """Full ticket incl. the heavy body/log columns — the list endpoint never
    ships those, so the admin UI fetches them lazily on expand."""
    if _current_user(request) is None:
        return _api({"error": "unauthorized"}, 401)
    rep = store.get_report(rid)
    if rep is None:
        return _api({"error": "not found"}, 404)
    return rep


@app.post("/api/tickets/{rid}/status")
def api_status(request: Request, rid: str, status: str = Form("")):
    user = _current_user(request)
    if user is None:
        return _api({"error": "unauthorized"}, 401)
    if _admin_throttled(user, rid):
        return _api({"error": "too many actions on this ticket, slow down"}, 429)
    payload, code = admin_api.set_status(user, rid, status)
    return _api(payload, code)


@app.post("/api/tickets/{rid}/delete")
def api_delete(request: Request, rid: str):
    user = _current_user(request)
    if user is None:
        return _api({"error": "unauthorized"}, 401)
    if _admin_throttled(user, rid):
        return _api({"error": "too many actions on this ticket, slow down"}, 429)
    payload, code = admin_api.delete_ticket(rid)
    return _api(payload, code)


@app.post("/api/tickets/{rid}/tags")
def api_tags(request: Request, rid: str,
             severity: str = Form(""), category: str = Form("")):
    user = _current_user(request)
    if user is None:
        return _api({"error": "unauthorized"}, 401)
    if _admin_throttled(user, rid):
        return _api({"error": "too many actions on this ticket, slow down"}, 429)
    payload, code = admin_api.set_tags(user, rid, severity, category)
    return _api(payload, code)


@app.post("/api/tickets/{rid}/comments")
def api_comment_add(request: Request, rid: str, body: str = Form("")):
    user = _current_user(request)
    if user is None:
        return _api({"error": "unauthorized"}, 401)
    if _admin_throttled(user, rid):
        return _api({"error": "too many actions on this ticket, slow down"}, 429)
    payload, code = admin_api.add_comment(user, rid, body)
    return _api(payload, code)


@app.post("/api/tickets/{rid}/comments/delete")
def api_comment_delete(request: Request, rid: str, index: int = Form(0)):
    user = _current_user(request)
    if user is None:
        return _api({"error": "unauthorized"}, 401)
    if _admin_throttled(user, rid):
        return _api({"error": "too many actions on this ticket, slow down"}, 429)
    payload, code = admin_api.delete_comment(user, rid, index)
    return _api(payload, code)


@app.post("/api/tickets/{rid}/link")
def api_ticket_link(request: Request, rid: str, target: str = Form("")):
    user = _current_user(request)
    if user is None:
        return _api({"error": "unauthorized"}, 401)
    if _admin_throttled(user, rid):
        return _api({"error": "too many actions on this ticket, slow down"}, 429)
    payload, code = admin_api.link_tickets(user, rid, target)
    return _api(payload, code)


# people management (owner only)
def _require_owner(request: Request):
    user = _current_user(request)
    if user is None:
        return None, _api({"error": "unauthorized"}, 401)
    if user.get("role") != "owner":
        return None, _api({"error": "owner only"}, 403)
    return user, None


@app.get("/api/users")
def api_users(request: Request):
    user, err = _require_owner(request)
    if err:
        return err
    return admin_api.public_users()


@app.post("/api/users/github")
def api_users_github(request: Request, login: str = Form("")):
    user, err = _require_owner(request)
    if err:
        return err
    payload, status = admin_api.preapprove(login)
    return _api(payload, status)


@app.post("/api/users/{uid}/status")
def api_user_status(request: Request, uid: int,
                    status: str = Form("pending")):
    user, err = _require_owner(request)
    if err:
        return err
    payload, code = admin_api.change_status(user, uid, status)
    return _api(payload, code)


@app.post("/api/users/{uid}/display-name")
def api_user_display_name(request: Request, uid: int,
                          name: str = Form("")):
    """Set a user's public display name (owner only). Empty resets to the
    username; the name shows on ticket timelines."""
    user, err = _require_owner(request)
    if err:
        return err
    payload, code = admin_api.rename(user, uid, name)
    return _api(payload, code)


@app.post("/api/users/{uid}/delete")
def api_user_delete(request: Request, uid: int):
    user, err = _require_owner(request)
    if err:
        return err
    payload, code = admin_api.remove(uid)
    return _api(payload, code)

