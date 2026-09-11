"""Admin settings are mandatory, and failed logins report their own state.

Derived from ``app.py``:

* a missing or empty ``BGBOX_ADMIN_USER`` / ``BGBOX_ADMIN_PASS`` logs one error
  and exits with status 2 (observed in a fresh interpreter, because it happens
  before the app object exists);
* startup logs one INFO line naming the sign-in user and noting that the
  password comes from ``.env``, plus the previous username when the configured
  name renamed an existing owner row;
* ``RateLimiter.status`` is a read-only report of (attempts left, seconds until
  the window frees) that agrees with ``allow`` and counts nothing;
* the login page reports the remaining attempts or the retry countdown, and
  never echoes a query parameter back into the page;
* every failed login logs exactly one WARNING with the attempted username, the
  caller address and the remaining allowance, and never the password.

Run (see tests/test_bugbox.py for the environment):

    BGBOX_ADMIN_USER=admin BGBOX_ADMIN_PASS=test-pass \
        BGBOX_COOKIE_KEY=test-key python -m pytest tests/ -q
"""

import logging
import os
import subprocess
import sys
import tempfile

# Isolate storage + secrets BEFORE importing the app (mirrors test_bugbox.py).
os.environ.setdefault("BGBOX_DATA", tempfile.mkdtemp(prefix="bugbox-admincfg-"))
os.environ.setdefault("BGBOX_ADMIN_USER", "admin")
os.environ.setdefault("BGBOX_ADMIN_PASS", "test-pass")
os.environ.setdefault("BGBOX_COOKIE_KEY", "test-cookie-key")
os.environ.pop("LLM_API_KEY", None)   # analysis disabled in tests

import pytest
from fastapi.testclient import TestClient

import app as bugbox_app
import store

client = TestClient(bugbox_app.app, raise_server_exceptions=False)
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LONG_PASS = "correct-horse-battery-staple"


@pytest.fixture(autouse=True)
def _fresh_db():
    # Each test gets a clean database, fresh rate buckets and a seeded owner.
    for name in os.listdir(store.DATA_DIR):
        path = os.path.join(store.DATA_DIR, name)
        if os.path.isfile(path):
            os.unlink(path)
    bugbox_app.RATE.reset()
    store.init()
    store.ensure_owner(bugbox_app.ADMIN_USER, bugbox_app.ADMIN_PASS)


def _child_env(data_dir, **overrides):
    """A child environment other than the admin settings and data dir.

    The parent already exported both admin settings plus a data dir; the child
    starts from a clean slate so each case is exactly what it says.
    """
    env = dict(os.environ)
    for name in ("BGBOX_ADMIN_USER", "BGBOX_ADMIN_PASS", "BGBOX_DATA",
                 "LLM_API_KEY"):
        env.pop(name, None)
    env["BGBOX_DATA"] = str(data_dir)
    env["PYTHONPATH"] = REPO
    for name, value in overrides.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    return env


def _run_child(code, data_dir, **overrides):
    proc = subprocess.run([sys.executable, "-c", code], cwd=REPO,
                          env=_child_env(data_dir, **overrides),
                          capture_output=True, text=True, timeout=120)
    return proc


# ── fail-fast on a missing admin setting ───────────────────────────────────
@pytest.mark.parametrize("user,password,label", [
    (None, None, "neither"),
    ("", LONG_PASS, "empty user"),
    ("admin", "", "empty password"),
    ("admin", None, "unset password"),
    (None, LONG_PASS, "unset user"),
])
def test_missing_admin_settings_exit_two(user, password, label, tmp_path):
    proc = _run_child("import app", tmp_path,
                      BGBOX_ADMIN_USER=user, BGBOX_ADMIN_PASS=password)
    assert proc.returncode == 2, (label, proc.returncode, proc.stderr)
    assert proc.stderr.count("admin login is not configured") == 1, proc.stderr
    assert "BGBOX_ADMIN_USER" in proc.stderr
    assert "BGBOX_ADMIN_PASS" in proc.stderr
    assert "Traceback" not in proc.stderr, proc.stderr


def test_a_complete_admin_config_starts(tmp_path):
    proc = _run_child("import app", tmp_path,
                      BGBOX_ADMIN_USER="admin", BGBOX_ADMIN_PASS=LONG_PASS)
    assert proc.returncode == 0, proc.stderr
    assert "admin login is not configured" not in proc.stderr


# ── the startup line ───────────────────────────────────────────────────────
def test_startup_line_names_the_sign_in_user_and_the_password_source(tmp_path):
    proc = _run_child("import app", tmp_path,
                      BGBOX_ADMIN_USER="alice", BGBOX_ADMIN_PASS=LONG_PASS)
    assert proc.returncode == 0, proc.stderr
    line = next(l for l in proc.stderr.splitlines()
                if "admin login: user 'alice'" in l)
    assert "from your .env" in line
    assert "BGBOX_ADMIN_PASS" in line
    assert "renamed" not in line           # a fresh data dir has no old owner


def test_startup_line_reports_an_owner_rename(tmp_path):
    seed = ("import store\n"
            "store.init()\n"
            "store.ensure_owner('oldname', 'old-password-12345')\n")
    seeded = _run_child(seed, tmp_path)
    assert seeded.returncode == 0, seeded.stderr

    proc = _run_child("import app", tmp_path,
                      BGBOX_ADMIN_USER="newname", BGBOX_ADMIN_PASS=LONG_PASS)
    assert proc.returncode == 0, proc.stderr
    line = next(l for l in proc.stderr.splitlines()
                if "admin login: user 'newname'" in l)
    assert "owner renamed from 'oldname'" in line


def test_startup_line_omits_the_rename_when_the_name_is_unchanged(tmp_path):
    seed = ("import store\n"
            "store.init()\n"
            "store.ensure_owner('samename', 'old-password-12345')\n")
    assert _run_child(seed, tmp_path).returncode == 0

    proc = _run_child("import app", tmp_path,
                      BGBOX_ADMIN_USER="samename", BGBOX_ADMIN_PASS=LONG_PASS)
    assert proc.returncode == 0, proc.stderr
    line = next(l for l in proc.stderr.splitlines()
                if "admin login: user 'samename'" in l)
    assert "renamed" not in line


# ── RateLimiter.status ─────────────────────────────────────────────────────
def test_status_reports_the_full_allowance_and_counts_nothing():
    limiter = bugbox_app.RateLimiter()
    for _ in range(4):
        assert limiter.status("k", 5, 60) == (5, 0)
    for _ in range(5):
        assert limiter.allow("k", 5, 60) is False
    # If any status call had counted, the sixth allow would already refuse.
    assert limiter.allow("k", 5, 60) is True


def test_status_agrees_with_the_limiter_at_every_count():
    limiter = bugbox_app.RateLimiter()
    for count in range(1, 7):
        limiter.allow("k", 5, 60)
        left, wait = limiter.status("k", 5, 60)
        assert left == max(0, 5 - count)
        assert (wait > 0) == (left == 0)
        assert 0 <= wait <= 60


def test_zero_left_means_the_next_attempt_is_refused():
    limiter = bugbox_app.RateLimiter()
    for _ in range(5):
        limiter.allow("k", 5, 60)
    assert limiter.status("k", 5, 60)[0] == 0
    assert limiter.allow("k", 5, 60) is True


def test_an_expired_window_restores_the_allowance(monkeypatch):
    limiter = bugbox_app.RateLimiter()
    clock = [1_000.0]
    monkeypatch.setattr(bugbox_app.time, "monotonic", lambda: clock[0])
    for _ in range(5):
        limiter.allow("k", 5, 60)
    assert limiter.status("k", 5, 60)[0] == 0
    clock[0] += 61.0
    assert limiter.status("k", 5, 60) == (5, 0)
    assert limiter.allow("k", 5, 60) is False


# ── login page feedback ────────────────────────────────────────────────────
def test_login_page_reports_the_attempts_left():
    body = client.get("/login?bad=1&left=3&wait=0").text
    assert "Wrong user or password. 3 attempts left." in body


def test_login_page_uses_the_singular_for_one_attempt():
    body = client.get("/login?bad=1&left=1&wait=0").text
    assert "1 attempt left." in body
    assert "1 attempts left" not in body


def test_login_page_reports_the_countdown():
    body = client.get("/login?bad=1&left=0&wait=30").text
    assert "Too many attempts. Try again in 30 seconds." in body


def test_login_page_uses_the_singular_for_one_second():
    body = client.get("/login?bad=1&left=0&wait=1").text
    assert "1 second." in body
    assert "1 seconds" not in body


def test_login_page_prefers_the_countdown_when_both_are_given():
    body = client.get("/login?bad=1&left=3&wait=10").text
    assert "Try again in 10 seconds." in body
    assert "3 attempts left" not in body


def test_login_page_without_bad_shows_no_feedback():
    body = client.get("/login?left=3&wait=2").text
    assert "attempts left" not in body
    assert "Too many attempts" not in body


def test_attempts_left_is_not_shown_above_the_configured_limit():
    body = client.get("/login?bad=1&left=9&wait=0").text
    assert "9 attempts" not in body
    assert "5 attempts left." in body


def test_the_wait_is_capped_at_the_window():
    body = client.get("/login?bad=1&left=0&wait=99").text
    assert "99 seconds" not in body
    assert "Try again in 60 seconds." in body


HOSTILE_VALUES = (
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "'; DROP TABLE users; --",
)


@pytest.mark.parametrize("value", HOSTILE_VALUES)
@pytest.mark.parametrize("field", ["left", "wait"])
def test_hostile_login_query_parameters_are_never_echoed(value, field):
    body = client.get("/login", params={"bad": "1", field: value}).text
    assert value not in body
    assert "alert(1)" not in body
    assert "onload" not in body
    assert "DROP TABLE" not in body


# ── failed-login logging ───────────────────────────────────────────────────
def _failures(caplog):
    return [r for r in caplog.records if "login failed" in r.getMessage()]


def test_failed_login_warns_once_with_user_caller_and_allowance(caplog):
    caplog.set_level(logging.WARNING, logger="bugbox")
    secret = "correct-horse-battery-staple"
    r = client.post("/login", data={"user": "intruder", "password": secret},
                    headers={"X-Forwarded-For": "203.0.113.9"},
                    follow_redirects=False)
    assert r.status_code == 303
    records = _failures(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    message = records[0].getMessage()
    assert "'intruder'" in message
    assert "203.0.113.9" in message
    assert "4 left" in message          # five allowed, one just used
    assert secret not in caplog.text


def test_repeated_failed_logins_report_the_countdown(caplog):
    caplog.set_level(logging.WARNING, logger="bugbox")
    headers = {"X-Forwarded-For": "203.0.113.10"}
    for _ in range(5):
        client.post("/login", data={"user": "u", "password": "nope"},
                    headers=headers, follow_redirects=False)
    last = client.post("/login", data={"user": "u", "password": "nope"},
                       headers=headers, follow_redirects=False)
    assert last.status_code == 303
    assert "left=0" in last.headers["location"]
    assert "wait=" in last.headers["location"]
    assert "wait=0" not in last.headers["location"]
    assert len(_failures(caplog)) == 6
    assert "0 left" in _failures(caplog)[-1].getMessage()


def test_a_successful_login_logs_no_failure_warning(caplog):
    caplog.set_level(logging.WARNING, logger="bugbox")
    r = client.post("/login",
                    data={"user": bugbox_app.ADMIN_USER,
                          "password": bugbox_app.ADMIN_PASS},
                    headers={"X-Forwarded-For": "203.0.113.12"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/admin"
    assert _failures(caplog) == []


def test_a_hostile_long_username_is_capped_in_the_log(caplog):
    caplog.set_level(logging.WARNING, logger="bugbox")
    client.post("/login", data={"user": "A" * 500, "password": "nope"},
                headers={"X-Forwarded-For": "203.0.113.13"},
                follow_redirects=False)
    message = _failures(caplog)[0].getMessage()
    assert "A" * 64 in message
    assert "A" * 65 not in message
