"""Bugbox endpoint + hardening tests.

Run (in the site repo, python env with fastapi/httpx/pytest):

    BGBOX_ADMIN_PASS=test-pass BGBOX_COOKIE_KEY=test-key python -m pytest tests/ -q
"""

import os
import tempfile

# Isolate storage + secrets BEFORE importing the app.
_DATA = tempfile.mkdtemp(prefix="bugbox-test-")
os.environ["BGBOX_DATA"] = _DATA
os.environ.setdefault("BGBOX_ADMIN_PASS", "test-pass")
os.environ.setdefault("BGBOX_COOKIE_KEY", "test-cookie-key")
os.environ.pop("LLM_API_KEY", None)   # analysis disabled in tests

import pytest
from fastapi.testclient import TestClient

import app as bugbox_app
import llm
import store

client = TestClient(bugbox_app.app)

ADMIN = {"X-Forwarded-For": "10.0.0.1"}
REPORTER = {"X-Forwarded-For": "10.0.0.2"}


def _login_client() -> TestClient:
    """A fresh client that has completed an admin login (cookie persisted)."""
    c = TestClient(bugbox_app.app)
    r = c.post("/login", data={"user": "admin", "password": "test-pass"},
               headers=ADMIN, follow_redirects=False)
    assert r.status_code == 303
    return c


@pytest.fixture(autouse=True)
def _fresh_db():
    # Each test gets a clean database + fresh rate buckets.
    for f in os.listdir(_DATA):
        os.unlink(os.path.join(_DATA, f))
    bugbox_app._buckets.clear()
    store.init()


def test_pages_render():
    assert client.get("/").status_code == 200
    assert client.get("/report").status_code == 200
    assert "v0.1.46" in client.get("/").text


def test_submit_creates_ticket():
    r = client.post("/submit", headers=REPORTER, data={
        "category": "breeding", "title": "Risk looks wrong",
        "body": "saw 0% for a mother+kitten pair", "log": "debug…",
        "name": "Catmom87",
    })
    assert r.status_code == 200
    tickets = store.list_reports()
    assert len(tickets) == 1
    assert tickets[0]["title"] == "Risk looks wrong"


def test_admin_required():
    assert client.get("/api/tickets", headers=ADMIN).status_code == 401
    logged = _login_client()
    assert logged.get("/api/tickets", headers=ADMIN).status_code == 200
    assert logged.get("/admin", headers=ADMIN).status_code == 200


def test_login_wrong_password():
    r = client.post("/login", data={"user": "admin", "password": "nope"},
                    headers=ADMIN, follow_redirects=False)
    assert r.status_code == 303
    assert "bad" in r.headers["location"]


def test_logout_clears_cookie():
    logged = _login_client()
    assert logged.get("/api/tickets", headers=ADMIN).status_code == 200
    assert logged.get("/logout", headers=ADMIN, follow_redirects=False).status_code == 303
    assert logged.get("/api/tickets", headers=ADMIN).status_code == 401


def test_api_report_garbage_types_do_not_crash():
    r = client.post("/api/report", headers=REPORTER, json={
        "title": {"nested": True}, "body": 12345, "log": ["a", "b"],
        "name": None, "app_version": 42,
    })
    assert r.status_code == 200
    row = store.get_report(r.json()["id"])
    assert row["title"] == "Untitled"
    assert row["body"] == "12345"
    assert row["log"] == ""
    assert row["name"] == ""
    assert row["app_version"] == "42"


def test_oversized_payload_rejected():
    r = client.post("/submit", headers=REPORTER,
                    data={"title": "x", "log": "a" * 500_000})
    assert r.status_code == 413


def test_store_truncates_long_fields():
    rid = store.add({"title": "ok", "body": "b" * 300_000, "log": "l" * 300_000})
    row = store.get_report(rid)
    assert len(row["body"]) == 200_000
    assert len(row["log"]) == 200_000


def test_rate_limit_reporting():
    ip = {"X-Forwarded-For": "10.9.9.9"}
    for _ in range(10):
        assert client.post("/submit", headers=ip,
                           data={"title": "x"}).status_code == 200
    assert client.post("/submit", headers=ip,
                       data={"title": "x"}).status_code == 429


def test_throttle_helper():
    bugbox_app._buckets.clear()
    for i in range(5):
        assert bugbox_app._throttled("t:1", 5, 60) is False
    assert bugbox_app._throttled("t:1", 5, 60) is True
    assert bugbox_app._throttled("t:2", 5, 60) is False  # different key


def test_llm_output_is_sanitized():
    # A prompt-injected model reply must come out as bounded, safe data.
    parsed = llm._clean({
        "severity": "CRITICAL",
        "category": "parser",
        "summary": "<script>alert(1)</script>",
        "likely_cause": "x" * 5000,
        "needs_reply": "yes",
        "dupe_ids": ["abc123def456",
                     "<img src=x onerror=alert(1)>",
                     "a" * 100, 12345, "ok", "one", "two", "three"],
    })
    assert parsed["severity"] == "critical"      # normalised
    assert parsed["category"] == "parser"
    assert "<script>" in parsed["summary"]       # stored as text (escaped on render)
    assert len(parsed["likely_cause"]) == 800    # bounded
    assert parsed["needs_reply"] is True
    assert parsed["dupe_ids"] == ["abc123def456", "12345", "ok", "one", "two"]
    assert llm._clean("not a dict") == {}
    assert llm._clean({"category": "weird", "severity": "bogus"})["severity"] == "medium"


def test_dupe_ids_are_escaped_in_admin_html():
    template = open("templates/admin.html", encoding="utf-8").read()
    # dupe ids must go through esc() so a hostile id can never become markup.
    assert '.map(x => "#" + esc(x))' in template


def test_status_and_delete_require_auth_and_work():
    rid = store.add({"title": "t"})
    # anonymous client cannot touch tickets
    assert client.post(f"/api/tickets/{rid}/status",
                       data={"status": "triaged"},
                       headers=ADMIN).status_code == 401
    assert client.post(f"/api/tickets/{rid}/delete",
                       headers=ADMIN).status_code == 401
    # logged-in client can
    logged = _login_client()
    r = logged.post(f"/api/tickets/{rid}/status",
                    data={"status": "triaged"}, headers=ADMIN)
    assert r.status_code == 200
    assert store.get_report(rid)["status"] == "triaged"
    assert logged.post(f"/api/tickets/{rid}/delete", headers=ADMIN).status_code == 200
    assert store.get_report(rid) is None
