"""Favicon delivery, optional Umami analytics, and the content-security policy.

Derived from app.py (the ``/favicon.ico`` route, the ``BGBOX_ANALYTICS_*``
block, the ``_csp`` builder, ``_ANALYTICS_PATHS`` / ``_csp_for`` and
``_error_response``), ``templates/*.html`` and ``static/*``.

Every expectation here is observed from the HTTP responses themselves (status,
headers, body) and from the app's own warning log, so the checks survive
refactors of the module internals. The favicon route is static, but every
analytics and CSP expectation is decided at import time from the environment.
Each configuration therefore runs in a fresh interpreter (the pattern
``tests/test_log_scrub.py`` already uses) and the parent process never imports
``app``: module state, the log handler and the CSP constants stay isolated to
each check.

Run (see tests/test_bugbox.py for the environment):

    BGBOX_ADMIN_PASS=test-pass BGBOX_COOKIE_KEY=test-key python -m pytest tests/ -q
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Configuration under test. The website id is an opaque string; the URLs are
# only ever compared as strings (nothing is fetched).
SCRIPT_URL = "https://analytics.example.com/script.js"
ORIGIN = "https://analytics.example.com"
WEBSITE_ID = "3f1c9a2e-7b44-4d51-9f8c-0a1b2c3d4e5f"
HTTP_SCRIPT_URL = "http://analytics.example.com/script.js"
NO_HOST_SCRIPT_URL = "https:///script.js"
PORT_SCRIPT_URL = "https://analytics.example.com:8443/umami.js"
PORT_ORIGIN = "https://analytics.example.com:8443"
# Credentials in the authority used to pass a bare hostname check, but the
# origin built from that authority is not a valid policy host, so the script
# silently never loaded.
CREDS_SCRIPT_URL = "https://user:pass@analytics.example.com/script.js"
USER_ONLY_SCRIPT_URL = "https://user@analytics.example.com/script.js"
# ``urlsplit(...).port`` raises for this, which is the malformed-port rule.
BAD_PORT_SCRIPT_URL = "https://analytics.example.com:not-a-port/script.js"

# The two policies exactly as they read before this feature landed
# (git show HEAD:app.py); the baseline must not drift when analytics is off.
PRE_FEATURE_BASELINE = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
STRICT = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'self'")

DISCLOSURE = "Page views are counted anonymously and without cookies."

TEMPLATES_WITH_HEAD = (
    "base_public.html",
    "admin.html",
    "login.html",
    "access.html",
    "people.html",
    "index.html",
)
ICON_LINKS = (
    '<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">',
    '<link rel="icon" type="image/x-icon" href="/static/favicon.ico">',
    '<link rel="apple-touch-icon" href="/static/apple-touch-icon.png">',
)

# The only normal responses that render the analytics tag (app.py
# _ANALYTICS_PATHS): the landing page, the report form and the thanks page
# returned by POST /submit.
TAG_PAGES = ("home", "report", "submit")
# Every other surface this suite can reach: none of them may be handed the
# analytics origin.
NON_TAG_PAGES = (
    "access", "admin", "people", "login", "api_tickets",
    "public_error", "admin_error", "login_error", "api_error",
)
NON_TAG_ASSETS = (
    "favicon", "static_favicon", "favicon_svg", "apple_touch_icon",
)
# Non-admin/login/api paths that keep the inline-style baseline (no origin).
BASELINE_STYLE_PAGES = ("access",)
BASELINE_STYLE_ASSETS = NON_TAG_ASSETS


def _cfg(**env):
    """A hashable environment overlay for one child-interpreter run."""
    return tuple(sorted(env.items()))


OFF = _cfg()
ON = _cfg(BGBOX_ANALYTICS_SCRIPT=SCRIPT_URL, BGBOX_ANALYTICS_ID=WEBSITE_ID)
SCRIPT_ONLY = _cfg(BGBOX_ANALYTICS_SCRIPT=SCRIPT_URL)
ID_ONLY = _cfg(BGBOX_ANALYTICS_ID=WEBSITE_ID)
HTTP_URL = _cfg(BGBOX_ANALYTICS_SCRIPT=HTTP_SCRIPT_URL,
                BGBOX_ANALYTICS_ID=WEBSITE_ID)
NO_HOST = _cfg(BGBOX_ANALYTICS_SCRIPT=NO_HOST_SCRIPT_URL,
               BGBOX_ANALYTICS_ID=WEBSITE_ID)
BLANK_ID = _cfg(BGBOX_ANALYTICS_SCRIPT=SCRIPT_URL, BGBOX_ANALYTICS_ID="   ")
ON_PORT = _cfg(BGBOX_ANALYTICS_SCRIPT=PORT_SCRIPT_URL,
               BGBOX_ANALYTICS_ID=WEBSITE_ID)
CREDS = _cfg(BGBOX_ANALYTICS_SCRIPT=CREDS_SCRIPT_URL,
             BGBOX_ANALYTICS_ID=WEBSITE_ID)
USER_ONLY = _cfg(BGBOX_ANALYTICS_SCRIPT=USER_ONLY_SCRIPT_URL,
                 BGBOX_ANALYTICS_ID=WEBSITE_ID)
BAD_PORT = _cfg(BGBOX_ANALYTICS_SCRIPT=BAD_PORT_SCRIPT_URL,
                BGBOX_ANALYTICS_ID=WEBSITE_ID)

# Only one of the two settings is set: the warning has to name the missing one.
PARTIAL = [
    (SCRIPT_ONLY, "BGBOX_ANALYTICS_ID", "script-only"),
    (ID_ONLY, "BGBOX_ANALYTICS_SCRIPT", "id-only"),
    (BLANK_ID, "BGBOX_ANALYTICS_ID", "blank-id"),
]
# Both settings are set but the URL is unusable: the warning names the script
# setting and (for the URL-shape rules) the reason.
MALFORMED = [
    (HTTP_URL, "https", "http-url"),
    (NO_HOST, "host", "no-host"),
    (CREDS, "credentials", "credentials"),
    (USER_ONLY, "credentials", "username-only"),
    (BAD_PORT, "BGBOX_ANALYTICS_SCRIPT", "bad-port"),
]
ALL_OFF = [c for c, _, _ in PARTIAL] + [c for c, _, _ in MALFORMED]
ALL_OFF_IDS = [i for _, _, i in PARTIAL] + [i for _, _, i in MALFORMED]

# In its own interpreter: the env is set by the parent before the import, so
# app.py reads the analytics settings, builds the CSP and seeds Jinja exactly
# as the deployment would.
_CHILD = r'''
import hashlib
import json
import logging
import os

_records = []


class _Capture(logging.Handler):
    def emit(self, record):
        _records.append({
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        })


_log = logging.getLogger("bugbox")
_log.addHandler(_Capture())
_log.setLevel(logging.DEBUG)
_log.propagate = False                  # keep stdout clean for the JSON dump

import app as bugbox_app                      # noqa: E402
from fastapi.testclient import TestClient    # noqa: E402

bugbox_app.VERSIONS.set_for_test("0.1.46", float("inf"))  # no GitHub fetch

client = TestClient(bugbox_app.app, raise_server_exceptions=False)
admin = TestClient(bugbox_app.app, raise_server_exceptions=False)
_login = admin.post(
    "/login",
    data={"user": bugbox_app.ADMIN_USER, "password": bugbox_app.ADMIN_PASS},
    follow_redirects=False,
)


def grab(requester, path, accept="text/html", method="GET"):
    if method == "POST":
        resp = requester.post(path, data={"category": "other",
                                          "title": "probe"},
                              headers={"Accept": accept})
    else:
        resp = requester.get(path, headers={"Accept": accept})
    return {
        "status": resp.status_code,
        "csp": resp.headers.get("content-security-policy"),
        "content_type": resp.headers.get("content-type"),
        "cache_control": resp.headers.get("cache-control"),
        "location": resp.headers.get("location"),
        "body": resp.text,
    }


def asset(path):
    resp = client.get(path)
    return {
        "status": resp.status_code,
        "csp": resp.headers.get("content-security-policy"),
        "content_type": resp.headers.get("content-type"),
        "cache_control": resp.headers.get("cache-control"),
        "sha256": hashlib.sha256(resp.content).hexdigest(),
        "length": len(resp.content),
    }


print(json.dumps({
    "logs": _records,
    "login_status": _login.status_code,
    "responses": {
        "home": grab(client, "/"),
        "report": grab(client, "/report"),
        "submit": grab(client, "/submit", method="POST"),
        "login": grab(client, "/login"),
        "access": grab(client, "/access?login=devone"),
        "admin": grab(admin, "/admin"),
        "people": grab(admin, "/admin/people"),
        "public_error": grab(client, "/no-such-page"),
        "admin_error": grab(admin, "/admin/no-such-page"),
        "login_error": grab(client, "/login/no-such-page"),
        "api_error": grab(client, "/api/no-such-page"),
        "api_tickets": grab(client, "/api/tickets",
                            accept="application/json"),
    },
    "assets": {
        "favicon": asset("/favicon.ico"),
        "static_favicon": asset("/static/favicon.ico"),
        "favicon_svg": asset("/static/favicon.svg"),
        "apple_touch_icon": asset("/static/apple-touch-icon.png"),
    },
}))
'''


@lru_cache(maxsize=None)
def _run(config):
    """Import app once in a fresh interpreter under *config*; return its JSON.

    Cached because each config is deterministic and the whole point is one
    clean interpreter per environment.
    """
    tmp = tempfile.mkdtemp(prefix="bugbox-favicon-analytics-")
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("BGBOX_ANALYTICS")}
    env.update({
        "BGBOX_DATA": os.path.join(tmp, "data"),
        "BGBOX_ADMIN_PASS": "test-pass",
        "BGBOX_COOKIE_KEY": "test-cookie-key",
        "BGBOX_OVERLAY_VERSION": "0.1.46",
        "PYTHONPATH": REPO,
    })
    env.pop("LLM_API_KEY", None)          # no analysis / network in the child
    env.update(dict(config))
    proc = subprocess.run([sys.executable, "-c", _CHILD], cwd=REPO, env=env,
                          capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, (proc.stdout[-2000:], proc.stderr[-4000:])
    data = json.loads(proc.stdout)
    assert data["login_status"] == 303, data["login_status"]
    return data


def _body(data, key):
    return data["responses"][key]["body"]


def _view(data, key):
    """The recorded response for *key*, whichever surface it came from."""
    if key in data["responses"]:
        return data["responses"][key]
    return data["assets"][key]


def _directives(csp):
    """Parse a CSP header into {directive: [sources]}."""
    parsed = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, value = part.partition(" ")
        parsed[name] = value.split()
    return parsed


def _analytics_warnings(data):
    return [rec["message"] for rec in data["logs"]
            if rec["level"] == "WARNING"
            and "analytics" in rec["message"].lower()]


# ══ A. the favicon route ═══════════════════════════════════════════════════

def test_favicon_ico_is_served_as_an_image_with_status_200():
    fav = _run(OFF)["assets"]["favicon"]
    assert fav["status"] == 200
    assert fav["content_type"].startswith("image/")
    assert "html" not in fav["content_type"].lower()
    assert fav["length"] > 0


def test_favicon_bytes_match_the_file_in_static():
    fav = _run(OFF)["assets"]["favicon"]
    path = Path(REPO) / "static" / "favicon.ico"
    assert fav["length"] == path.stat().st_size
    assert fav["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_favicon_is_no_longer_the_error_page():
    # A 404 error page is HTML and says "No cat here"; the icon route must be
    # neither. Serving the real bytes with an image type rules both out.
    fav = _run(OFF)["assets"]["favicon"]
    assert fav["status"] != 404
    assert fav["content_type"].startswith("image/")


def test_favicon_response_is_cacheable():
    cc = _run(OFF)["assets"]["favicon"]["cache_control"]
    assert cc, "the icon response carries no Cache-Control header"
    assert "public" in cc
    match = re.search(r"max-age=(\d+)", cc)
    assert match, cc
    assert int(match.group(1)) > 0, cc


@pytest.mark.parametrize("name", TEMPLATES_WITH_HEAD)
def test_icon_links_are_in_the_head_of_every_template(name):
    text = (Path(REPO) / "templates" / name).read_text(encoding="utf-8")
    head = text[text.index("<head>"):text.index("</head>")]
    for link in ICON_LINKS:
        assert link in head, f"{name} <head> is missing {link}"


@pytest.mark.parametrize("page", ["report", "public_error", "home", "submit"],
                         ids=["report", "error", "landing", "thanks"])
def test_rendered_pages_carry_the_icon_links(page):
    body = _body(_run(OFF), page)
    for link in ICON_LINKS:
        assert link in body, f"the /{page} page is missing {link}"


def test_each_icon_asset_path_resolves():
    data = _run(OFF)
    for key in ("favicon_svg", "static_favicon", "apple_touch_icon"):
        resp = data["assets"][key]
        assert resp["status"] == 200, key
        assert resp["content_type"].startswith("image/"), (
            key, resp["content_type"])


# ══ B. analytics, configured by environment ════════════════════════════════

def _script_tag():
    return (f'<script defer src="{SCRIPT_URL}" '
            f'data-website-id="{WEBSITE_ID}"></script>')


def test_both_settings_render_the_deferred_script_on_tag_pages():
    data = _run(ON)
    for page in TAG_PAGES:
        body = _body(data, page)
        assert _script_tag() in body, page
        assert body.count("data-website-id=") == 1, page
        directives = _directives(data["responses"][page]["csp"])
        assert ORIGIN in directives["script-src"], page
        assert ORIGIN in directives["connect-src"], page


def test_both_settings_present_logs_no_analytics_warning():
    assert _analytics_warnings(_run(ON)) == []


@pytest.mark.parametrize("config,missing", [(c, m) for c, m, _ in PARTIAL],
                         ids=[i for _, _, i in PARTIAL])
def test_partial_config_warns_about_the_missing_setting(config, missing):
    warnings = _analytics_warnings(_run(config))
    assert len(warnings) == 1, warnings
    assert missing in warnings[0], warnings[0]


@pytest.mark.parametrize("config,needle", [(c, n) for c, n, _ in MALFORMED],
                         ids=[i for _, _, i in MALFORMED])
def test_malformed_url_warns_and_stays_off(config, needle):
    data = _run(config)
    warnings = _analytics_warnings(data)
    assert len(warnings) == 1, warnings
    assert "BGBOX_ANALYTICS_SCRIPT" in warnings[0], warnings[0]
    assert needle in warnings[0], warnings[0]
    # Analytics stays off: no tag anywhere and no origin in any policy.
    for page in TAG_PAGES:
        resp = data["responses"][page]
        assert "data-website-id" not in resp["body"], page
        assert ORIGIN not in (resp["csp"] or ""), page


@pytest.mark.parametrize("config", ALL_OFF, ids=ALL_OFF_IDS)
def test_bad_or_partial_config_renders_no_script_anywhere(config):
    data = _run(config)
    for key, resp in data["responses"].items():
        assert "data-website-id" not in resp["body"], key
        assert "analytics.example.com" not in resp["body"], key


def test_analytics_off_public_pages_are_unchanged_by_the_feature():
    off = _run(OFF)
    on = _run(ON)
    # The thanks page carries a per-report id, so its bytes are not stable
    # across processes; the tag decision is shared with these two pages and
    # the tag/script assertions above cover it.
    for page in ("home", "report"):
        body = _body(off, page)
        assert "data-website-id" not in body, page
        assert DISCLOSURE not in body, page
        # The only lines the feature ever adds are the script tag and the
        # disclosure; strip them from the "on" page and it must match exactly.
        stripped = [line for line in _body(on, page).splitlines()
                    if SCRIPT_URL not in line and DISCLOSURE not in line]
        assert stripped == body.splitlines(), page


def test_analytics_on_adds_one_disclosure_line_to_the_shared_footer():
    assert _body(_run(ON), "report").count(DISCLOSURE) == 1
    assert DISCLOSURE not in _body(_run(OFF), "report")


def test_analytics_on_discloses_on_the_landing_page_footer_too():
    # The landing page is a public page that loads the script, so its footer
    # owes the same single line.
    assert _body(_run(ON), "home").count(DISCLOSURE) == 1


def test_analytics_on_discloses_on_the_thanks_page_footer_too():
    # POST /submit renders thanks.html, the third tag-rendering page.
    assert _body(_run(ON), "submit").count(DISCLOSURE) == 1


def test_analytics_on_keeps_the_user_configured_origin_with_its_port():
    data = _run(ON_PORT)
    for page in TAG_PAGES:
        directives = _directives(data["responses"][page]["csp"])
        assert PORT_ORIGIN in directives["script-src"], page
        assert PORT_ORIGIN in directives["connect-src"], page


# ══ C. the content security policy ═════════════════════════════════════════

def test_public_csp_with_analytics_off_is_the_pre_feature_policy():
    data = _run(OFF)
    for page in TAG_PAGES + BASELINE_STYLE_PAGES + ("public_error",):
        assert data["responses"][page]["csp"] == PRE_FEATURE_BASELINE, page
    for key in BASELINE_STYLE_ASSETS:
        assert data["assets"][key]["csp"] == PRE_FEATURE_BASELINE, key


@pytest.mark.parametrize("config", [OFF, ON], ids=["off", "on"])
def test_strict_paths_keep_the_unchanged_strict_policy(config):
    data = _run(config)
    for page in ("login", "admin", "people", "api_tickets"):
        assert data["responses"][page]["csp"] == STRICT, page


def test_analytics_on_public_csp_gains_only_the_script_and_connect_origin():
    data = _run(ON)
    base = _directives(PRE_FEATURE_BASELINE)
    for page in TAG_PAGES:
        got = _directives(data["responses"][page]["csp"])
        assert got["script-src"] == ["'self'", "'unsafe-inline'", ORIGIN], page
        assert got["connect-src"] == ["'self'", ORIGIN], page
        assert set(got) == set(base), page
        for name in base:
            if name in ("script-src", "connect-src"):
                continue
            assert got[name] == base[name], (page, name)


def test_analytics_origin_is_granted_only_to_paths_that_render_the_tag():
    data = _run(ON)
    for page in TAG_PAGES:
        resp = data["responses"][page]
        assert ORIGIN in (resp["csp"] or ""), page
        assert "data-website-id" in resp["body"], page
    for key in NON_TAG_PAGES + NON_TAG_ASSETS:
        resp = _view(data, key)
        assert ORIGIN not in (resp["csp"] or ""), key


@pytest.mark.parametrize("key", BASELINE_STYLE_PAGES + BASELINE_STYLE_ASSETS)
def test_other_public_paths_keep_inline_styles_without_the_origin(key):
    # The description is explicit: the access page, the static assets and the
    # icon keep the policy without the analytics origin, but with the inline
    # styles the standalone templates carry.
    directives = _directives(_view(_run(ON), key)["csp"])
    assert directives["script-src"] == ["'self'", "'unsafe-inline'"], key
    assert directives["style-src"] == ["'self'", "'unsafe-inline'"], key


def test_analytics_on_error_responses_get_the_baseline_policy():
    data = _run(ON)
    for page in ("public_error", "admin_error", "login_error", "api_error"):
        assert data["responses"][page]["csp"] == PRE_FEATURE_BASELINE, page


@pytest.mark.parametrize("config", [OFF, ON], ids=["off", "on"])
def test_strict_policy_never_permits_the_analytics_origin(config):
    data = _run(config)
    host = ORIGIN.split("//", 1)[1]
    for page in ("login", "admin", "people", "api_tickets"):
        assert host not in data["responses"][page]["csp"], page


def test_error_response_on_a_strict_prefix_never_permits_the_origin():
    # The safety rule is that a third-party script is never permitted on an
    # admin/API surface. An error response served under /admin, /login or /api
    # is still one of those surfaces, so the origin must not appear in its
    # policy either.
    data = _run(ON)
    host = ORIGIN.split("//", 1)[1]
    for page in ("admin_error", "login_error", "api_error"):
        resp = data["responses"][page]
        assert host not in (resp["csp"] or ""), page
        assert ORIGIN not in (resp["csp"] or ""), page


# ══ D. no script on error pages or authenticated surfaces ══════════════════

@pytest.mark.parametrize("page", TAG_PAGES)
def test_analytics_on_public_pages_do_carry_the_script(page):
    assert "data-website-id" in _body(_run(ON), page)


@pytest.mark.parametrize("page", ["public_error", "admin_error",
                                  "login_error", "api_error"])
def test_analytics_on_error_responses_never_carry_the_script(page):
    data = _run(ON)
    resp = data["responses"][page]
    assert "data-website-id" not in resp["body"], page
    assert SCRIPT_URL not in resp["body"], page
    assert "https://analytics.example.com" not in resp["body"], page


def test_error_pages_do_not_advertise_analytics_without_the_script():
    # An error response is explicitly "never a real public page" here, so it
    # must not claim that page views are being counted.
    for page in ("public_error", "admin_error", "login_error"):
        assert DISCLOSURE not in _body(_run(ON), page), page


@pytest.mark.parametrize("page", ["admin", "login", "people", "access"])
def test_authenticated_and_login_pages_never_carry_the_script(page):
    data = _run(ON)
    assert "data-website-id" not in data["responses"][page]["body"], page
    assert SCRIPT_URL not in data["responses"][page]["body"], page
