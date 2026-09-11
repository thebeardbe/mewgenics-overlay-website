"""CSRF origin-gate decision order and rejection logging.

Derived from ``_origin_allowed`` in app.py, exercised through the app with the
same request approach the existing suite uses (POST /submit).

Run (see tests/test_bugbox.py for the environment):

    BGBOX_ADMIN_USER=admin BGBOX_ADMIN_PASS=test-pass \
        BGBOX_COOKIE_KEY=test-key python -m pytest tests/ -q
"""

import itertools
import logging
import os
import tempfile

# Isolate storage + secrets BEFORE importing the app (mirrors test_bugbox.py).
os.environ.setdefault("BGBOX_DATA", tempfile.mkdtemp(prefix="bugbox-csrf-"))
os.environ.setdefault("BGBOX_ADMIN_USER", "admin")
os.environ.setdefault("BGBOX_ADMIN_PASS", "test-pass")
os.environ.setdefault("BGBOX_COOKIE_KEY", "test-cookie-key")
os.environ.pop("LLM_API_KEY", None)   # analysis disabled in tests

import pytest
from fastapi.testclient import TestClient

import app as bugbox_app
import store

client = TestClient(bugbox_app.app)

HOST = "testserver"
FORM = {"category": "ui", "title": "csrf probe", "body": "x"}
_IPS = itertools.count(1)


def _post(extra_headers=None):
    """POST /submit from a fresh client IP so rate limits never interfere."""
    headers = {"X-Forwarded-For": f"10.11.0.{next(_IPS) % 250}"}
    headers.update(extra_headers or {})
    return client.post("/submit", data=FORM, headers=headers)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    # No background analysis: the gate tests must not add writes/threads.
    monkeypatch.setattr(bugbox_app, "_analyze_in_background", lambda rid: None)
    for name in os.listdir(store.DATA_DIR):
        path = os.path.join(store.DATA_DIR, name)
        if os.path.isfile(path):
            os.unlink(path)
    bugbox_app.RATE.reset()
    bugbox_app.VERSIONS.set_for_test("0.1.46", float("inf"))
    store.init()
    store.ensure_owner(bugbox_app.ADMIN_USER, bugbox_app.ADMIN_PASS)


# ── Sec-Fetch-Site is checked first ────────────────────────────────────────
def test_same_origin_with_null_origin_is_allowed():
    """The live production case: a privacy-configured browser serialises the
    Origin of a same-origin form POST as the literal "null". It must stay
    allowed, so this is the most important test in the set."""
    r = _post({"Sec-Fetch-Site": "same-origin", "Origin": "null"})
    assert r.status_code == 200


def test_fetch_site_none_with_null_origin_is_allowed():
    # Typed URL / bookmark navigation: Origin is null but the site is trusted.
    r = _post({"Sec-Fetch-Site": "none", "Origin": "null"})
    assert r.status_code == 200


def test_cross_site_is_rejected_even_when_origin_matches_host():
    # A cross-site attacker can spoof Origin, so cross-site loses outright,
    # even when the Origin host equals the request Host.
    r = _post({"Sec-Fetch-Site": "cross-site", "Origin": f"http://{HOST}"})
    assert r.status_code == 403


@pytest.mark.parametrize("value", [
    "same-origin", "SAME-ORIGIN", "Same-Origin", "  same-origin  ",
    "\tsame-origin\t",
])
def test_same_origin_value_is_case_and_whitespace_insensitive(value):
    r = _post({"Sec-Fetch-Site": value, "Origin": "null"})
    assert r.status_code == 200


@pytest.mark.parametrize("value", [
    "cross-site", "CROSS-SITE", "Cross-Site", "  cross-site  ",
    "\tcross-site\t",
])
def test_cross_site_value_is_case_and_whitespace_insensitive(value):
    r = _post({"Sec-Fetch-Site": value, "Origin": f"http://{HOST}"})
    assert r.status_code == 403


# ── same-site is not trusted on its own ────────────────────────────────────
def test_same_site_falls_through_to_the_origin_comparison():
    # Matching Origin: the legacy rule allows it.
    assert _post({"Sec-Fetch-Site": "same-site",
                  "Origin": f"http://{HOST}"}).status_code == 200
    # Differing Origin: rejected.
    r = _post({"Sec-Fetch-Site": "same-site", "Origin": "https://evil.example"})
    assert r.status_code == 403


def test_unknown_fetch_site_value_falls_through_to_origin_comparison():
    # Any value the gate does not recognise is not trusted: it must go through
    # the legacy Origin/Host check just like an absent header.
    assert _post({"Sec-Fetch-Site": "same-origin-ish",
                  "Origin": f"http://{HOST}"}).status_code == 200
    assert _post({"Sec-Fetch-Site": "same-origin-ish",
                  "Origin": "null"}).status_code == 403


# ── no fetch metadata: legacy Origin / Host comparison ─────────────────────
def test_no_fetch_metadata_matching_origin_passes():
    assert _post({"Origin": f"http://{HOST}"}).status_code == 200


def test_no_fetch_metadata_null_origin_is_rejected():
    assert _post({"Origin": "null"}).status_code == 403


def test_no_origin_header_at_all_is_allowed():
    # Non-browser clients (curl, the game overlay) send no Origin.
    assert _post({}).status_code == 200


def test_overlay_direct_json_post_without_origin_is_allowed():
    # The overlay's real path: a direct JSON POST with no browser metadata.
    r = client.post("/api/report",
                    headers={"X-Forwarded-For": "10.11.9.9"},
                    json={"title": "overlay report"})
    assert r.status_code == 200
    assert r.json()["status"] == "open"


# ── BGBOX_ORIGINS allowlist wins over the Host comparison ──────────────────
def test_allowlist_decides_instead_of_host(monkeypatch):
    # BGBOX_ORIGINS entries are Origin *netlocs* (host[:port]), matching the
    # docstring of _origin_allowed; the scheme is not part of the entry.
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS", {"allowed.example"})
    # Outside the allowlist: rejected even though it matches the request Host.
    r = _post({"Origin": f"http://{HOST}"})
    assert r.status_code == 403
    # Inside the allowlist: accepted even though it differs from the Host.
    assert _post({"Origin": "https://allowed.example"}).status_code == 200


def test_allowlist_comparison_is_case_insensitive(monkeypatch):
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS", {"allowed.example"})
    assert _post({"Origin": "https://ALLOWED.example"}).status_code == 200


def test_allowlist_entry_is_a_netloc_not_a_full_origin(monkeypatch):
    # A scheme-prefixed entry can never match: the gate compares the Origin
    # netloc, so "https://allowed.example" is not "allowed.example".
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS",
                        {"https://allowed.example"})
    assert _post({"Origin": "https://allowed.example"}).status_code == 403
    assert _post({"Origin": "http://testserver"}).status_code == 403


def test_non_empty_allowlist_admits_trusted_fetch_metadata(monkeypatch):
    """The allowlist's exclusive rejection sits after the fetch-metadata
    trust branch, so an operator who lists only other origins does not lock
    the app's own forms out. The browser vouches for them with same-origin
    (or none), and that branch is consulted first."""
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS", {"other.example"})
    r = _post({"Origin": f"http://{HOST}", "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 200


def test_non_empty_allowlist_admits_none_fetch_metadata(monkeypatch):
    # Typed URL / bookmark navigation also carries trustworthy fetch
    # metadata, so a non-empty allowlist must not override it either.
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS", {"other.example"})
    r = _post({"Origin": f"http://{HOST}", "Sec-Fetch-Site": "none"})
    assert r.status_code == 200


# ── the allowlist admits a configured cross-site origin (defect fix) ───────
def test_allowlisted_origin_is_admitted_on_a_cross_site_post(monkeypatch):
    """The defect: cross-site used to be rejected before the allowlist was
    consulted, so a documented BGBOX_ORIGINS entry could never take effect.
    The allowlist is operator configuration, so it decides first."""
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS", {"allowed.example"})
    r = _post({"Origin": "https://allowed.example",
               "Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 200


def test_cross_site_origin_outside_the_allowlist_is_rejected(monkeypatch):
    # Same cross-site metadata and an Origin outside the list: still denied.
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS", {"other.example"})
    r = _post({"Origin": "https://allowed.example",
               "Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403


def test_allowlist_match_is_case_insensitive_on_cross_site(monkeypatch):
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS", {"allowed.example"})
    r = _post({"Origin": "https://ALLOWED.Example",
               "Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 200


def test_allowlist_netloc_includes_the_port(monkeypatch):
    # The comparison is on the netloc, so a port is part of the key: the
    # same host without the port is a different origin and is rejected.
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS",
                        {"allowed.example:8443"})
    assert _post({"Origin": "https://allowed.example:8443",
                  "Sec-Fetch-Site": "cross-site"}).status_code == 200
    assert _post({"Origin": "https://allowed.example",
                  "Sec-Fetch-Site": "cross-site"}).status_code == 403


def test_allowlist_match_is_exact_not_a_suffix(monkeypatch):
    # An Origin whose host merely ends with a listed entry must not slip in.
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS", {"allowed.example"})
    r = _post({"Origin": "https://allowed.example.evil.test",
               "Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403


def test_allowlist_entry_with_a_scheme_matches_nothing(monkeypatch):
    # Pins the netloc semantics from both sides: the scheme-prefixed entry is
    # dead, and the bare netloc entry accepts the very same request. same-site
    # metadata makes the allowlist the deciding branch, not the cross-site
    # rejection, so this cannot pass for the wrong reason.
    request = {"Origin": "https://allowed.example",
               "Sec-Fetch-Site": "same-site"}
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS",
                        {"https://allowed.example"})
    assert _post(request).status_code == 403
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS", {"allowed.example"})
    assert _post(request).status_code == 200


def test_non_empty_allowlist_is_exclusive_without_fetch_metadata(monkeypatch):
    """Without trustworthy fetch metadata, a non-empty BGBOX_ORIGINS is
    exclusive: matching the request Host is not enough, the Origin must be
    listed. Clearing the list restores the same-origin fallback. This does
    not hold for requests that carry same-origin/none fetch metadata; those
    are admitted by the trust branch before this rule."""
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS", {"other.example"})
    assert _post({"Origin": f"http://{HOST}"}).status_code == 403
    assert _post({"Origin": f"http://{HOST}",
                  "Sec-Fetch-Site": "same-site"}).status_code == 403
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS", set())
    assert _post({"Origin": f"http://{HOST}"}).status_code == 200


def test_allowlist_does_not_block_clients_that_send_no_origin(monkeypatch):
    # Curl and the overlay send no Origin at all: an allowlist is irrelevant
    # to them and must not turn a non-browser POST into a rejection.
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS", {"allowed.example"})
    assert _post({}).status_code == 200


# ── rejection logging (B) ──────────────────────────────────────────────────
def _warnings(caplog):
    return [rec for rec in caplog.records
            if rec.name == "bugbox" and rec.levelno >= logging.WARNING]


def test_rejection_logs_exactly_one_warning_with_full_context(caplog):
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        r = _post({"Sec-Fetch-Site": "cross-site",
                   "Origin": "https://evil.example"})
    assert r.status_code == 403
    records = _warnings(caplog)
    assert len(records) == 1
    msg = records[0].getMessage()
    assert "cross-origin request rejected" in msg
    assert "POST" in msg
    assert "/submit" in msg
    assert "origin=https://evil.example" in msg.replace("'", "")
    assert "sec-fetch-site=cross-site" in msg.replace("'", "")
    assert "host=testserver" in msg.replace("'", "")


def test_rejection_logging_reports_the_raw_header_values(caplog):
    # The gate used to reject silently; the log must name every input so the
    # production null-Origin case is diagnosable.
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        _post({"Sec-Fetch-Site": "same-site", "Origin": "null"})
    records = _warnings(caplog)
    assert len(records) == 1
    msg = records[0].getMessage()
    assert "cross-origin request rejected" in msg
    assert "origin='null'" in msg
    assert "sec-fetch-site='same-site'" in msg


def test_accepted_request_logs_no_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        r = _post({"Sec-Fetch-Site": "same-origin", "Origin": "null"})
    assert r.status_code == 200
    assert _warnings(caplog) == []


def test_accepted_legacy_origin_request_logs_no_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        r = _post({"Origin": f"http://{HOST}"})
    assert r.status_code == 200
    assert _warnings(caplog) == []


def test_accepted_allowlisted_cross_site_request_logs_no_warning(monkeypatch,
                                                                 caplog):
    # Admission through the allowlist is a deliberate operator choice, not a
    # reason to cry cross-origin in the log.
    monkeypatch.setattr(bugbox_app, "_ALLOWED_ORIGINS", {"allowed.example"})
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        r = _post({"Origin": "https://allowed.example",
                   "Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 200
    assert _warnings(caplog) == []
