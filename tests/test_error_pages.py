"""Friendly error pages (error_pages.py) and the error responses wired in app.py.

Two layers:

* unit tests for the new leaf module (copy table, JSON carve-out, defaults);
* integration tests driving 404/405/413/403/429/500 through the app for both
  browser (`Accept: text/html`) and JSON (`/api/` or `Accept: application/json`)
  callers, including the security headers and the 500 leak check.

Run (see tests/test_bugbox.py for the environment):

    BGBOX_ADMIN_USER=admin BGBOX_ADMIN_PASS=test-pass \
        BGBOX_COOKIE_KEY=test-key python -m pytest tests/ -q
"""

import itertools
import json
import logging
import os
import tempfile
import traceback

# Isolate storage + secrets BEFORE importing the app (mirrors test_bugbox.py).
os.environ.setdefault("BGBOX_DATA", tempfile.mkdtemp(prefix="bugbox-errpages-"))
os.environ.setdefault("BGBOX_ADMIN_USER", "admin")
os.environ.setdefault("BGBOX_ADMIN_PASS", "test-pass")
os.environ.setdefault("BGBOX_COOKIE_KEY", "test-cookie-key")
os.environ.pop("LLM_API_KEY", None)   # analysis disabled in tests

import pytest
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.requests import Request

import app as bugbox_app
import error_pages
import store

client = TestClient(bugbox_app.app)
# The 500 handler runs inside ServerErrorMiddleware; the default test client
# re-raises, so the leak test needs the "server" behaviour instead.
soft_client = TestClient(bugbox_app.app, raise_server_exceptions=False)

FORM = {"category": "ui", "title": "probe", "body": "x"}
_IPS = itertools.count(1)
SECURITY_HEADERS = ("content-security-policy", "x-content-type-options",
                    "x-frame-options", "referrer-policy", "x-robots-tag",
                    "permissions-policy")


def _ip():
    return f"10.30.{next(_IPS) % 250}.{next(_IPS) % 250}"


def _login_client():
    """A fresh client that has completed the owner login (cookie persisted)."""
    c = TestClient(bugbox_app.app)
    r = c.post("/login",
               data={"user": bugbox_app.ADMIN_USER,
                     "password": bugbox_app.ADMIN_PASS},
               headers={"X-Forwarded-For": "10.31.0.1"},
               follow_redirects=False)
    assert r.status_code == 303
    return c


def _soft_login_client():
    """A logged-in client that does not re-raise server exceptions, for
    driving a 500 out of an authenticated path."""
    c = TestClient(bugbox_app.app, raise_server_exceptions=False)
    r = c.post("/login",
               data={"user": bugbox_app.ADMIN_USER,
                     "password": bugbox_app.ADMIN_PASS},
               headers={"X-Forwarded-For": "10.31.0.2"},
               follow_redirects=False)
    assert r.status_code == 303
    return c


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(bugbox_app, "_analyze_in_background", lambda rid: None)
    for name in os.listdir(store.DATA_DIR):
        path = os.path.join(store.DATA_DIR, name)
        if os.path.isfile(path):
            os.unlink(path)
    bugbox_app.RATE.reset()
    bugbox_app.VERSIONS.set_for_test("0.1.46", float("inf"))
    store.init()
    store.ensure_owner(bugbox_app.ADMIN_USER, bugbox_app.ADMIN_PASS)


# ══ unit: the copy table and the JSON carve-out (E) ════════════════════════
REQUIRED_CODES = (400, 403, 404, 405, 413, 429, 500)


def test_quote_table_covers_the_required_codes():
    for code in REQUIRED_CODES:
        assert code in error_pages.QUOTES, code


def test_every_table_code_has_a_quote_and_an_explanation():
    assert error_pages.QUOTES, "quote table must not be empty"
    for code, pair in error_pages.QUOTES.items():
        assert isinstance(pair, tuple) and len(pair) == 2, code
        quote, explanation = pair
        assert isinstance(quote, str) and quote.strip(), code
        assert isinstance(explanation, str) and explanation.strip(), code
        assert error_pages.error_copy(code) == (quote, explanation)


@pytest.mark.parametrize("code", [0, -1, 418, 599, 999, 1000])
def test_unknown_code_falls_back_to_the_generic_line(code):
    assert error_pages.error_copy(code) == error_pages.GENERIC_CODE_COPY
    assert error_pages.GENERIC_CODE_COPY[0].strip()
    assert error_pages.GENERIC_CODE_COPY[1].strip()


def _request(path="/x", headers=None):
    raw = [(k.lower().encode("latin-1"), v.encode("latin-1"))
           for k, v in (headers or {}).items()]
    return Request({
        "type": "http", "http_version": "1.1", "method": "GET",
        "scheme": "http", "path": path, "raw_path": path.encode(),
        "query_string": b"", "headers": raw, "root_path": "",
        "client": ("127.0.0.1", 12345), "server": ("testserver", 80),
    })


def test_wants_json_for_api_paths_and_json_accept():
    assert error_pages.wants_json(_request("/api/report")) is True
    assert error_pages.wants_json(
        _request("/api/nope", {"accept": "application/json"})) is True
    assert error_pages.wants_json(
        _request("/x", {"accept": "application/json"})) is True
    assert error_pages.wants_json(
        _request("/x", {"accept": "APPLICATION/JSON"})) is True
    assert error_pages.wants_json(
        _request("/x", {"accept": "text/html, application/json"})) is True
    assert error_pages.wants_json(_request("/x", {"accept": "text/html"})) is False
    assert error_pages.wants_json(_request("/x")) is False
    # A path that merely begins with "api" is not the API surface.
    assert error_pages.wants_json(_request("/apiary")) is False


def test_api_response_reproduces_framework_defaults():
    r = error_pages.api_response(404)
    assert r.status_code == 404
    assert json.loads(r.body) == {"detail": "Not Found"}
    r = error_pages.api_response(405)
    assert r.status_code == 405
    assert json.loads(r.body) == {"detail": "Method Not Allowed"}
    r = error_pages.api_response(403)
    assert r.status_code == 403
    assert json.loads(r.body) == {"detail": "Forbidden"}
    # The two raw bodies the app produced itself stay byte-identical.
    r = error_pages.api_response(413)
    assert r.status_code == 413 and r.body == b"payload too large"
    r = error_pages.api_response(500)
    assert r.status_code == 500 and r.body == b"Internal Server Error"
    # Unregistered status codes fall back to a stable label.
    r = error_pages.api_response(599)
    assert json.loads(r.body) == {"detail": "HTTP 599"}


def test_render_error_uses_copy_and_render_for_browsers():
    seen = {}

    def render(name, **ctx):
        seen["name"] = name
        seen["ctx"] = ctx
        return "<html>stub</html>"

    resp = error_pages.render_error(_request("/x", {"accept": "text/html"}),
                                    404, render=render)
    assert resp.status_code == 404
    assert resp.body == b"<html>stub</html>"
    assert seen["name"] == error_pages.TEMPLATE
    assert seen["ctx"]["code"] == 404
    assert seen["ctx"]["quote"] == error_pages.QUOTES[404][0]
    assert seen["ctx"]["explanation"] == error_pages.QUOTES[404][1]


def test_render_error_returns_the_fallback_unchanged_for_json():
    fallback = JSONResponse({"error": "nope"}, status_code=403)
    resp = error_pages.render_error(
        _request("/x", {"accept": "application/json"}), 403, fallback,
        render=lambda *a, **k: "<html>must not be used</html>")
    assert resp is fallback
    assert json.loads(resp.body) == {"error": "nope"}


def test_render_error_reproduces_the_default_for_json_without_fallback():
    resp = error_pages.render_error(_request("/api/x"), 404,
                                    render=lambda *a, **k: "<html>x</html>")
    assert resp.status_code == 404
    assert json.loads(resp.body) == {"detail": "Not Found"}


# ══ integration helpers ════════════════════════════════════════════════════
def _assert_error_page(resp, code):
    assert resp.status_code == code
    assert resp.headers["content-type"].startswith("text/html")
    body = resp.text
    assert f">{code}</h1>" in body          # the numeric code, as the heading
    quote, explanation = error_pages.QUOTES[code]
    assert quote in body
    assert explanation in body
    # The page must carry *this* code's copy, not another row of the table.
    for other, (other_quote, other_explanation) in error_pages.QUOTES.items():
        if other != code:
            assert other_quote not in body, other
            assert other_explanation not in body, other
    # Both escape hatches are on every page.
    assert 'href="/"' in body
    assert 'href="/report"' in body
    # Shared public layout (nav + footer), not a bare fragment.
    assert "<nav>" in body
    assert "Mewgenics" in body
    return body


def _assert_security_headers_once(resp):
    for header in SECURITY_HEADERS:
        values = resp.headers.get_list(header)
        assert len(values) == 1, f"{header} appears {len(values)}x: {values}"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["x-robots-tag"] == "noindex, nofollow"


def _flood(ip, accept):
    """Drive one client IP past the report rate limit; return the 429."""
    headers = {"X-Forwarded-For": ip, "Accept": accept}
    for _ in range(10):
        assert client.post("/submit", data=FORM, headers=headers).status_code == 200
    return client.post("/submit", data=FORM, headers=headers)


# ══ 404 ═══════════════════════════════════════════════════════════════════
def test_404_page_for_browser():
    _assert_error_page(
        client.get("/no-such-page", headers={"Accept": "text/html"}), 404)


def test_404_json_body_unchanged_via_accept_and_via_api_path():
    r = client.get("/no-such-page", headers={"Accept": "application/json"})
    assert r.status_code == 404
    assert r.json() == {"detail": "Not Found"}
    r = client.get("/api/no-such-page", headers={"Accept": "text/html"})
    assert r.status_code == 404
    assert r.json() == {"detail": "Not Found"}


# ══ 405 ═══════════════════════════════════════════════════════════════════
def test_405_page_for_browser_keeps_allow_header():
    r = client.post("/report", headers={"Accept": "text/html",
                                        "X-Forwarded-For": _ip()})
    _assert_error_page(r, 405)
    assert "GET" in r.headers["allow"]


def test_405_json_body_and_allow_header_unchanged():
    r = client.post("/api/tickets", headers={"Accept": "application/json",
                                             "X-Forwarded-For": _ip()})
    assert r.status_code == 405
    assert r.json() == {"detail": "Method Not Allowed"}
    assert "GET" in r.headers["allow"]


# ══ 413 ═══════════════════════════════════════════════════════════════════
def test_413_page_for_browser():
    r = client.post("/submit", data={"log": "a" * 500_000},
                    headers={"Accept": "text/html", "X-Forwarded-For": _ip()})
    _assert_error_page(r, 413)


def test_413_json_body_unchanged():
    r = client.post("/submit", data={"log": "a" * 500_000},
                    headers={"Accept": "application/json",
                             "X-Forwarded-For": _ip()})
    assert r.status_code == 413
    assert r.text == "payload too large"


# ══ 403 (CSRF gate) ═══════════════════════════════════════════════════════
def test_403_page_for_browser():
    r = client.post("/submit", data=FORM, headers={
        "Accept": "text/html", "Origin": "https://evil.example",
        "Sec-Fetch-Site": "cross-site", "X-Forwarded-For": _ip()})
    _assert_error_page(r, 403)


def test_403_json_body_unchanged():
    r = client.post("/submit", data=FORM, headers={
        "Accept": "application/json", "Origin": "https://evil.example",
        "Sec-Fetch-Site": "cross-site", "X-Forwarded-For": _ip()})
    assert r.status_code == 403
    assert r.json() == {"error": "cross-origin request rejected"}


# ══ 403 (CSRF token mismatch: the second, distinct 403) ════════════════════
def _csrf_mismatch(accept):
    """An authenticated non-public POST carrying a wrong CSRF token.

    The path is deliberately not under /api/, so each caller's Accept header
    decides between the page and the JSON body; the middleware rejects before
    the router ever sees the method mismatch.
    """
    c = _login_client()
    return c.post("/admin",
                  data={"status": "open"},
                  headers={"Accept": accept,
                           "X-Bugbox-CSRF": "wrong-token",
                           "X-Forwarded-For": _ip()})


def test_csrf_token_mismatch_page_for_browser():
    _assert_error_page(_csrf_mismatch("text/html"), 403)


def test_csrf_token_mismatch_json_body_unchanged():
    r = _csrf_mismatch("application/json")
    assert r.status_code == 403
    assert r.headers["content-type"].startswith("application/json")
    assert r.json() == {"error": "csrf check failed"}


# ══ 429 (report rate limit) ═══════════════════════════════════════════════
def test_429_page_for_browser():
    _assert_error_page(_flood(_ip(), "text/html"), 429)


def test_429_json_body_unchanged():
    r = _flood(_ip(), "application/json")
    assert r.status_code == 429
    assert r.json() == {"error": "too many reports, try again in a minute"}


# ══ 500 (unhandled exception) ═════════════════════════════════════════════
def _boom():
    raise RuntimeError("SECRET_TRACEBACK_MARKER_9f3a")


def test_500_page_for_browser_hides_traceback_but_logs_it(monkeypatch, caplog):
    monkeypatch.setattr(bugbox_app, "latest_version", _boom)
    with caplog.at_level(logging.ERROR, logger="bugbox"):
        r = soft_client.get("/", headers={"Accept": "text/html"})
    body = _assert_error_page(r, 500)

    # Nothing from the exception may reach the page.
    assert "SECRET_TRACEBACK_MARKER_9f3a" not in body
    assert "RuntimeError" not in body
    assert "Traceback" not in body
    assert "app.py" not in body

    # ...while the traceback is still logged.
    errors = [rec for rec in caplog.records
              if rec.name == "bugbox" and rec.levelno >= logging.ERROR]
    assert len(errors) == 1
    assert errors[0].exc_info is not None
    assert errors[0].exc_info[0] is RuntimeError
    frames = traceback.extract_tb(errors[0].exc_info[2])
    assert any(os.path.basename(f.filename) == "app.py" for f in frames)
    for frame in frames:
        assert os.path.basename(frame.filename) not in body


def test_500_json_body_unchanged(monkeypatch):
    monkeypatch.setattr(bugbox_app, "latest_version", _boom)
    r = soft_client.get("/", headers={"Accept": "application/json"})
    assert r.status_code == 500
    assert r.text == "Internal Server Error"
    assert r.headers["content-type"].startswith("text/plain")


# ══ D: security headers on error responses ════════════════════════════════
def test_security_headers_exactly_once_on_browser_error_pages():
    responses = [
        client.get("/no-such-page", headers={"Accept": "text/html"}),
        client.post("/report", headers={"Accept": "text/html",
                                        "X-Forwarded-For": _ip()}),
        client.post("/submit", data={"log": "a" * 500_000},
                    headers={"Accept": "text/html", "X-Forwarded-For": _ip()}),
        client.post("/submit", data=FORM, headers={
            "Accept": "text/html", "Origin": "null",
            "X-Forwarded-For": _ip()}),
        _flood(_ip(), "text/html"),
    ]
    assert [r.status_code for r in responses] == [404, 405, 413, 403, 429]
    for resp in responses:
        _assert_security_headers_once(resp)


def test_security_headers_exactly_once_on_json_error_responses():
    responses = [
        client.get("/api/no-such-page", headers={"Accept": "text/html"}),
        client.post("/api/tickets", headers={"Accept": "application/json",
                                             "X-Forwarded-For": _ip()}),
        client.post("/submit", data={"log": "a" * 500_000},
                    headers={"Accept": "application/json",
                             "X-Forwarded-For": _ip()}),
        client.post("/submit", data=FORM, headers={
            "Accept": "application/json", "Origin": "null",
            "X-Forwarded-For": _ip()}),
        _flood(_ip(), "application/json"),
    ]
    assert [r.status_code for r in responses] == [404, 405, 413, 403, 429]
    for resp in responses:
        _assert_security_headers_once(resp)


def test_405_does_not_lose_allow_or_duplicate_headers():
    # 405 is raised by the router and its response then passes back through
    # the hardening middleware, so both the error path and the middleware add
    # the security headers. Neither may duplicate them, and Allow must survive.
    browser = client.post("/report", headers={"Accept": "text/html",
                                              "X-Forwarded-For": _ip()})
    assert browser.status_code == 405
    assert browser.headers.get_list("allow") == ["GET"]
    _assert_security_headers_once(browser)

    api = client.post("/api/tickets", headers={"Accept": "application/json",
                                               "X-Forwarded-For": _ip()})
    assert api.status_code == 405
    assert "GET" in api.headers["allow"]
    _assert_security_headers_once(api)


def test_hsts_present_only_when_https_enabled(monkeypatch):
    r = client.get("/no-such-page", headers={"Accept": "text/html"})
    assert r.headers.get("strict-transport-security") is None

    monkeypatch.setattr(bugbox_app, "HTTPS", True)
    r = client.get("/no-such-page", headers={"Accept": "text/html"})
    assert (r.headers["strict-transport-security"]
            == "max-age=31536000; includeSubDomains")
    _assert_security_headers_once(r)


# ══ E: error pages carry the baseline CSP, not the strict one ═════════════
# The error page is static copy plus an integer code; its styling is the
# inline <style> block in base_public.html, which the strict /admin/ and
# /login/ policy forbids. A mistyped admin URL or a server error on those
# paths used to render unstyled for exactly that reason.

ERROR_PATHS = ("/admin/anything-missing", "/login/anything-missing",
               "/no-such-page")


@pytest.mark.parametrize("path", ERROR_PATHS)
def test_error_page_on_a_strict_path_gets_the_baseline_csp(path):
    r = client.get(path, headers={"Accept": "text/html"})
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("text/html")
    csp = r.headers["content-security-policy"]
    assert csp == bugbox_app._CSP_BASELINE
    assert "style-src 'self' 'unsafe-inline'" in csp
    # The baseline CSP is only worth anything if the page actually needs the
    # inline styles it permits.
    assert "<style>" in r.text


def test_500_on_a_login_path_also_gets_the_baseline_csp(monkeypatch):
    def _render_boom(*_args, **_kwargs):
        raise RuntimeError("render failed on purpose")

    monkeypatch.setattr(bugbox_app, "_render", _render_boom)
    r = soft_client.get("/login", headers={"Accept": "text/html"})
    _assert_error_page(r, 500)
    assert r.headers["content-security-policy"] == bugbox_app._CSP_BASELINE
    assert "<style>" in r.text


def test_500_on_an_admin_path_also_gets_the_baseline_csp(monkeypatch):
    # The same defect as the login case, on the other strict-CSP prefix: a
    # failing /admin/ URL used to render unstyled. The login happens before
    # the renderer is broken, so only the admin request hits the 500.
    c = _soft_login_client()

    def _render_boom(*_args, **_kwargs):
        raise RuntimeError("render failed on purpose")

    monkeypatch.setattr(bugbox_app, "_render", _render_boom)
    r = c.get("/admin/people", headers={"Accept": "text/html"})
    _assert_error_page(r, 500)
    csp = r.headers["content-security-policy"]
    assert csp == bugbox_app._CSP_BASELINE
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "<style>" in r.text


def test_normal_login_page_still_gets_the_strict_csp():
    r = client.get("/login", headers={"Accept": "text/html"})
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert csp == bugbox_app._CSP_STRICT
    assert "'unsafe-inline'" not in csp
    assert "<style>" not in r.text


def test_normal_admin_page_still_gets_the_strict_csp():
    r = _login_client().get("/admin", headers={"Accept": "text/html"})
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert csp == bugbox_app._CSP_STRICT
    assert "'unsafe-inline'" not in csp
    assert "<style>" not in r.text


@pytest.mark.parametrize("path", ERROR_PATHS)
def test_error_page_keeps_the_shared_nav_and_escape_links(path):
    body = client.get(path, headers={"Accept": "text/html"}).text
    assert "<nav>" in body                              # shared public layout
    assert 'href="/"' in body                           # back home
    assert 'href="/report"' in body                     # report a problem
    assert "Mewgenics" in body
