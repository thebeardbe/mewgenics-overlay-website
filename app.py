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
import os
import re
import threading
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

import llm
import store

store.init()
app = FastAPI(title="Bugbox")

TEMPLATES = Path(__file__).parent / "templates"
ADMIN_USER = os.environ.get("BGBOX_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("BGBOX_ADMIN_PASS", "")
COOKIE_KEY = os.environ.get("BGBOX_COOKIE_KEY", "change-me")


def _admin_token(user: str, password: str) -> str:
    return hmac.new(
        COOKIE_KEY.encode(), f"{user}:{password}".encode(), hashlib.sha256
    ).hexdigest()


def _is_admin(request: Request) -> bool:
    return request.cookies.get("bugbox_admin") == _admin_token(ADMIN_USER, ADMIN_PASS)


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
    return RedirectResponse("/report")


@app.get("/report", response_class=HTMLResponse)
def report_page():
    return _render("report.html", report_url="/submit")


@app.post("/submit")
def submit(
    category: str = Form("other"),
    title: str = Form(""),
    body: str = Form(""),
    log: str = Form(""),
    name: str = Form(""),
    contact: str = Form(""),
):
    rid = store.add({
        "category": category, "title": title, "body": body,
        "log": log[:60000], "name": name, "contact": contact,
    })
    _analyze_in_background(rid)
    return _render("thanks.html", rid=rid)


@app.post("/api/report")
async def api_report(request: Request):
    """JSON endpoint the overlay (or power users) can POST to directly."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "expected JSON body"}, status_code=400)
    rid = store.add(data)
    _analyze_in_background(rid)
    return JSONResponse({"id": rid, "status": "open"})


def _analyze_in_background(rid: str) -> None:
    def job():
        report = store.get_report(rid)
        if report is None:
            return
        recent = [r for r in store.list_reports(limit=15) if r["id"] != rid]
        store.set_analysis(rid, llm.analyze(report, recent))
    threading.Thread(target=job, daemon=True).start()


# ── admin ─────────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    bad = "<p class='bad'>Wrong user or password.</p>" if request.query_params.get("bad") else ""
    return _render("login.html", bad=bad)


@app.post("/login")
def login(user: str = Form(""), password: str = Form("")):
    if ADMIN_PASS and user == ADMIN_USER and password == ADMIN_PASS:
        resp = RedirectResponse("/admin", status_code=303)
        resp.set_cookie("bugbox_admin", _admin_token(user, password),
                        httponly=True, samesite="lax", max_age=60 * 60 * 24 * 30)
        return resp
    return RedirectResponse("/login?bad=1", status_code=303)


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
