"""Bugbox — self-hosted bug intake with LLM triage.

FastAPI app. Two audiences:
  * players  -> GET /report  (no account needed, paste debug info)
  * you      -> GET /admin   (token login, list/read/triage reports)
Reports may also arrive as JSON POSTs from the overlay itself.

Run:  uvicorn app:app --host 0.0.0.0 --port 8000   (see compose.yaml)
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import threading
import time
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

import llm
import store

store.init()
app = FastAPI(title="Bugbox")

logger = logging.getLogger("bugbox")

TEMPLATES = Path(__file__).parent / "templates"
ADMIN_USER = os.environ.get("BGBOX_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("BGBOX_ADMIN_PASS", "")
COOKIE_KEY = os.environ.get("BGBOX_COOKIE_KEY", "change-me")
COOKIE_SECURE = os.environ.get("BGBOX_COOKIE_SECURE", "").lower() not in (
    "", "0", "false", "no")

MAX_BODY_BYTES = 400_000          # reject anything larger up front (nginx too)
REPORT_RATE_LIMIT = (10, 60)      # (max, window seconds) per IP
LOGIN_RATE_LIMIT = (5, 60)

# In-memory per-IP rate buckets (restart resets them; fine for self-hosting).
_buckets: dict = {}
_bucket_lock = threading.Lock()


if not ADMIN_PASS:
    logger.warning("BGBOX_ADMIN_PASS is not set — the admin login is DISABLED "
                   "(fails closed); set it in the environment.")
if COOKIE_KEY in ("", "change-me", "change-me-too"):
    logger.warning("BGBOX_COOKIE_KEY is unset or still the default — set a "
                   "long random value so admin cookies cannot be forged.")


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


def _admin_token(user: str, password: str) -> str:
    return hmac.new(
        COOKIE_KEY.encode(), f"{user}:{password}".encode(), hashlib.sha256
    ).hexdigest()


def _is_admin(request: Request) -> bool:
    want = _admin_token(ADMIN_USER, ADMIN_PASS)
    got = request.cookies.get("bugbox_admin")
    return bool(got and ADMIN_PASS) and hmac.compare_digest(got, want)


def _render(name: str, **ctx) -> HTMLResponse:
    html = (TEMPLATES / name).read_text(encoding="utf-8")

    def _sub(m):
        key = m.group(1)
        return str(ctx.get(key, m.group(0)))

    # Only swap {word} placeholders; CSS braces ({ }) are left untouched.
    html = re.sub(r"\{(\w+)\}", _sub, html)
    return HTMLResponse(html)


# ── public surface ────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def home():
    return _render("index.html")


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
            {"error": "too many reports — try again in a minute"},
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
            {"error": "too many reports — try again in a minute"},
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


# ── admin ─────────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    bad = ("<p class='bad'>Wrong user or password.</p>"
           if request.query_params.get("bad") else "")
    return _render("login.html", bad=bad)


@app.post("/login")
def login(request: Request, user: str = Form(""), password: str = Form("")):
    if _throttled(f"login:{_client_ip(request)}", *LOGIN_RATE_LIMIT):
        return RedirectResponse("/login?bad=1", status_code=303)
    if ADMIN_PASS and hmac.compare_digest(user, ADMIN_USER) \
            and hmac.compare_digest(password, ADMIN_PASS):
        resp = RedirectResponse("/admin", status_code=303)
        resp.set_cookie("bugbox_admin", _admin_token(user, password),
                        httponly=True, samesite="lax", secure=COOKIE_SECURE,
                        max_age=60 * 60 * 24 * 30)
        return resp
    return RedirectResponse("/login?bad=1", status_code=303)


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("bugbox_admin")
    return resp


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    if not _is_admin(request):
        return RedirectResponse("/login")
    return _render("admin.html")


@app.get("/api/tickets")
def api_tickets(request: Request, status: str | None = None):
    if not _is_admin(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return store.list_reports(status)


@app.post("/api/tickets/{rid}/status")
def api_status(request: Request, rid: str, status: str = Form("")):
    if not _is_admin(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if status in {"open", "triaged", "fixed", "wontfix", "duplicate"}:
        store.update_status(rid, status)
    return {"ok": True}


@app.post("/api/tickets/{rid}/delete")
def api_delete(request: Request, rid: str):
    if not _is_admin(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    store.delete_report(rid)
    return {"ok": True}
