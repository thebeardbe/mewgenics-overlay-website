"""Overlay-version cache: seeding, persistence and the fetch rules.

Derived from ``version_cache.py``:

* the cache seeds itself from ``<data dir>/overlay-version.txt`` at startup, so
  the first page load after a restart shows the last known release;
* a successful fetch updates the in-memory value *and* persists it atomically;
* a failed fetch keeps the last known value (never the built-in default);
* a corrupt, unreadable or unwritable file only logs a warning and continues;
* ``BGBOX_OVERLAY_VERSION`` that is empty or whitespace means "unset" and the
  built-in default is shown.

Every test points the cache at a temporary path (``tmp_path``) or a throw-away
``BGBOX_DATA`` in a fresh interpreter; the real data directory is never
touched. The interpreter tests run the import in a child so the import-time
environment read is exercised for real (the pattern tests/test_log_scrub.py
uses).

Run (see tests/test_bugbox.py for the environment):

    BGBOX_ADMIN_USER=admin BGBOX_ADMIN_PASS=test-pass \
        BGBOX_COOKIE_KEY=test-key python -m pytest tests/ -q
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
import time
import types

# A throw-away data dir before version_cache (and store) is imported, so the
# module-level VERSIONS never points at the real deployment data.
os.environ.setdefault("BGBOX_DATA", tempfile.mkdtemp(prefix="bugbox-vcache-"))

import pytest

import version_cache

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_FILENAME = version_cache.CACHE_FILENAME
FALLBACK = version_cache._FALLBACK_VERSION


def _cache(dir_path, default="0.0.1"):
    """A cache at a temporary path, never the module-default data dir."""
    return version_cache.VersionCache(default, path=dir_path / CACHE_FILENAME)


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """The module-level cache redirected to a temporary file.

    ``latest_version`` / ``_refresh`` read the module global, so swapping it
    (and restoring it afterwards via monkeypatch) keeps the background thread
    rule testable without touching the real data directory.
    """
    c = _cache(tmp_path)
    monkeypatch.setattr(version_cache, "VERSIONS", c)
    return c


# ── seeding from disk ──────────────────────────────────────────────────────
def test_cache_seeds_itself_from_the_persisted_file(tmp_path):
    (tmp_path / CACHE_FILENAME).write_text("1.2.3", encoding="utf-8")
    assert _cache(tmp_path).get() == "1.2.3"


def test_first_start_without_a_file_uses_the_default(tmp_path):
    assert _cache(tmp_path, default="7.0.0").get() == "7.0.0"


def test_corrupt_persisted_file_is_ignored_and_warned(tmp_path, caplog):
    (tmp_path / CACHE_FILENAME).write_text("not-a-version", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        c = _cache(tmp_path, default="7.0.0")
    assert c.get() == "7.0.0"
    assert any("not a version" in r.getMessage() for r in caplog.records), \
        caplog.text


def test_whitespace_only_persisted_file_is_ignored(tmp_path):
    (tmp_path / CACHE_FILENAME).write_text(" \n\t ", encoding="utf-8")
    assert _cache(tmp_path, default="7.0.0").get() == "7.0.0"


def test_unreadable_persisted_file_is_ignored_and_warned(tmp_path, caplog):
    path = tmp_path / CACHE_FILENAME
    path.mkdir()                       # a directory cannot be read as text
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        c = version_cache.VersionCache("7.0.0", path=path)
    assert c.get() == "7.0.0"
    assert any("unreadable" in r.getMessage() for r in caplog.records), \
        caplog.text


# ── persisting after a fetch ───────────────────────────────────────────────
def test_a_successful_refresh_persists_the_tag(cache, monkeypatch):
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: "2.0.0")
    version_cache._refresh()
    assert cache.get() == "2.0.0"
    assert cache.path.read_text(encoding="utf-8") == "2.0.0"


def test_the_persisted_write_leaves_no_temp_file(cache):
    cache.finish_refresh("4.0.0")
    assert sorted(p.name for p in cache.path.parent.iterdir()) == \
        [CACHE_FILENAME]


def test_a_failed_refresh_keeps_the_last_known_tag(cache, monkeypatch):
    cache.finish_refresh("1.9.9")
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: None)
    version_cache._refresh()
    assert cache.get() == "1.9.9"
    assert cache.path.read_text(encoding="utf-8") == "1.9.9"


def test_a_raising_fetch_keeps_the_last_known_tag(cache, monkeypatch, caplog):
    cache.finish_refresh("1.9.9")

    def boom():
        raise RuntimeError("network down")

    monkeypatch.setattr(version_cache, "fetch_latest", boom)
    with caplog.at_level(logging.ERROR, logger="bugbox"):
        version_cache._refresh()
    assert cache.get() == "1.9.9"
    assert cache.path.read_text(encoding="utf-8") == "1.9.9"
    assert any("version refresh thread failed" in r.getMessage()
               for r in caplog.records), caplog.text


def test_a_write_failure_keeps_the_value_in_memory_and_warns(tmp_path, caplog):
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        c = version_cache.VersionCache("0.0.1", path=blocker / CACHE_FILENAME)
        c.finish_refresh("3.0.0")
    assert c.get() == "3.0.0"
    assert any("could not persist" in r.getMessage() for r in caplog.records), \
        caplog.text


# ── lazy background refresh ────────────────────────────────────────────────
def test_latest_version_serves_the_cached_value_within_the_ttl(cache,
                                                               monkeypatch):
    cache.set_for_test("1.0.0", time.time())
    monkeypatch.setattr(
        version_cache, "fetch_latest",
        lambda: pytest.fail("must not fetch within the TTL"))
    assert version_cache.latest_version() == "1.0.0"


def test_latest_version_starts_one_non_blocking_refresh(cache, monkeypatch):
    started = []

    class _Thread:
        def __init__(self, target=None, name=None, daemon=None):
            self.target, self.name, self.daemon = target, name, daemon

        def start(self):
            started.append(self)

    # Only the thread factory is replaced; no real thread runs, which is what
    # makes the "return before the fetch completes" rule deterministic.
    monkeypatch.setattr(version_cache, "threading",
                        types.SimpleNamespace(Thread=_Thread))
    cache.set_for_test("1.0.0", 0.0)
    # The stale cache still answers immediately with the last known value.
    assert version_cache.latest_version() == "1.0.0"
    assert len(started) == 1
    assert started[0].target is version_cache._refresh
    # While that refresh is in flight, no second one is started.
    assert version_cache.latest_version() == "1.0.0"
    assert len(started) == 1


# ── fetch_latest ───────────────────────────────────────────────────────────
class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen(payload):
    def opener(req, timeout=None):
        assert timeout == version_cache._FETCH_TIMEOUT
        return _FakeResponse(payload)

    return opener


def test_fetch_latest_reads_and_normalises_the_release_tag(monkeypatch):
    monkeypatch.setattr(
        version_cache.urllib.request, "urlopen",
        _fake_urlopen(json.dumps({"tag_name": "v0.2.0"}).encode()))
    assert version_cache.fetch_latest() == "0.2.0"


@pytest.mark.parametrize("tag", ["latest", "nightly-2024", ""])
def test_fetch_latest_rejects_an_unusable_tag(tag, monkeypatch, caplog):
    monkeypatch.setattr(
        version_cache.urllib.request, "urlopen",
        _fake_urlopen(json.dumps({"tag_name": tag}).encode()))
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        assert version_cache.fetch_latest() is None
    assert any("unusable release tag" in r.getMessage()
               for r in caplog.records), caplog.text


def test_fetch_latest_returns_none_on_a_network_error(monkeypatch, caplog):
    def boom(req, timeout=None):
        raise OSError("offline")

    monkeypatch.setattr(version_cache.urllib.request, "urlopen", boom)
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        assert version_cache.fetch_latest() is None
    assert any("refresh failed" in r.getMessage() for r in caplog.records), \
        caplog.text


# ── the environment variable, read at import time ──────────────────────────
_CHILD = """
import json
import version_cache

print(json.dumps({
    "default": version_cache.DEFAULT_VERSION,
    "current": version_cache.VERSIONS.get(),
}))
"""


def _run_child(data_dir, env_overlay):
    """Import version_cache in a fresh interpreter with a throw-away data dir."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("BGBOX_")}
    env["BGBOX_DATA"] = str(data_dir)
    env["PYTHONPATH"] = REPO
    env.update({k: v for k, v in env_overlay.items() if v is not None})
    proc = subprocess.run([sys.executable, "-c", _CHILD], cwd=REPO, env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@pytest.mark.parametrize("value", [None, "", "   ", "\t\n"])
def test_blank_or_unset_overlay_version_uses_the_builtin(value, tmp_path):
    out = _run_child(tmp_path, {"BGBOX_OVERLAY_VERSION": value})
    assert out["default"] == FALLBACK
    assert out["current"] == FALLBACK


def test_overlay_version_is_the_first_start_default(tmp_path):
    out = _run_child(tmp_path, {"BGBOX_OVERLAY_VERSION": " 9.9.9 "})
    assert out["default"] == "9.9.9"
    assert out["current"] == "9.9.9"


def test_persisted_tag_wins_over_the_environment_on_restart(tmp_path):
    (tmp_path / CACHE_FILENAME).write_text("1.2.3", encoding="utf-8")
    out = _run_child(tmp_path, {"BGBOX_OVERLAY_VERSION": "9.9.9"})
    assert out["current"] == "1.2.3"


def test_persisted_tag_is_shown_when_the_environment_is_unset(tmp_path):
    (tmp_path / CACHE_FILENAME).write_text("1.2.3", encoding="utf-8")
    out = _run_child(tmp_path, {"BGBOX_OVERLAY_VERSION": None})
    assert out["current"] == "1.2.3"
    assert out["default"] == FALLBACK
