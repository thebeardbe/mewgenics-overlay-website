"""Overlay-version cache: seeding, persistence and the fetch claim.

Derived from ``version_cache.py``:

* the cache seeds itself from ``<data dir>/overlay-version.txt`` at startup, so
  the first page load after a restart shows the last known release;
* ``snapshot()`` reads the held tag together with its source in one lock
  acquisition, so the two can never be paired across two fetches;
* a successful fetch updates the in-memory value *and* persists it atomically;
* a failed fetch keeps the last known value (never the built-in default);
* the startup prime and the lazy refresh share one in-flight claim, identified
  by an integer that only the owning worker may release;
* a corrupt, unreadable, non-UTF-8 or unwritable file only logs a warning and
  continues (the decode error must not escape cache construction, which runs
  at import time);
* ``BGBOX_OVERLAY_VERSION`` that is empty or whitespace means "unset" and the
  built-in default is shown.

Every test points the cache at a temporary path (``tmp_path``) or a throw-away
``BGBOX_DATA`` in a fresh interpreter; the real data directory is never
touched and no test reaches the network (``fetch_latest`` is stubbed
everywhere). The interpreter tests run the import in a child so the
import-time environment read is exercised for real (the pattern
tests/test_log_scrub.py uses).

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
import threading
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

    ``latest_version`` / ``_refresh`` / ``prime`` read the module global, so
    swapping it (and restoring it afterwards via monkeypatch) keeps the
    background-thread rules testable without touching the real data dir.
    """
    c = _cache(tmp_path)
    monkeypatch.setattr(version_cache, "VERSIONS", c)
    return c


# ── thread test doubles ────────────────────────────────────────────────────
def _record_threads(monkeypatch):
    """Replace version_cache's thread factory with a recorder that never runs.

    Returns the list the fake appends built workers to, so a test can assert
    that no worker was started (and that target/args/name/daemon were passed)
    without a real thread racing the assertion.
    """
    built = []

    class _RecordingThread:
        def __init__(self, target=None, args=(), kwargs=None, name=None,
                     daemon=None):
            self.target = target
            self.args = args
            self.kwargs = kwargs or {}
            self.name = name
            self.daemon = daemon
            self.started = False
            built.append(self)

        def start(self):
            self.started = True

    monkeypatch.setattr(version_cache, "threading",
                        types.SimpleNamespace(Thread=_RecordingThread,
                                              Lock=threading.Lock))
    return built


class _GatedFetch:
    """A ``fetch_latest`` stub that blocks until the test releases it.

    ``entered`` is set once the fetch has actually been called and ``release``
    lets the test finish it; both are Events, so there is no sleep and the
    worker thread can be joined deterministically. ``result`` is what the call
    returns (``None`` models a failed fetch); ``raises`` makes it raise
    instead.
    """

    def __init__(self, result=None, raises=None):
        self.result = result
        self.raises = raises
        self.entered = threading.Event()
        self.release = threading.Event()
        self._calls = 0
        self._lock = threading.Lock()

    @property
    def calls(self):
        with self._lock:
            return self._calls

    def __call__(self):
        with self._lock:
            self._calls += 1
        self.entered.set()
        # Safety net only: every test releases this long before it fires.
        assert self.release.wait(timeout=30), "test never released the fetch"
        if self.raises is not None:
            raise self.raises
        return self.result


def _capture_workers(monkeypatch):
    """Wrap ``_refresh`` to record the worker thread for each claim id."""
    workers = []
    real_refresh = version_cache._refresh

    def capture(claim_id):
        workers.append(threading.current_thread())
        real_refresh(claim_id)

    monkeypatch.setattr(version_cache, "_refresh", capture)
    return workers


def _timed_out_prime(cache, monkeypatch, caplog, fetch, timeout=0.2):
    """Prime against a blocked fetch and return (worker, held value/source).

    The prime's wait expires while the fetch is still in flight, which is the
    state the shared-claim rules are about. The caller owns releasing ``fetch``
    and joining the returned worker thread.
    """
    workers = _capture_workers(monkeypatch)
    monkeypatch.setattr(version_cache, "fetch_latest", fetch)
    monkeypatch.setattr(version_cache, "PRIME_TIMEOUT", timeout)
    cache.set_for_test("1.0.0", time.time(), version_cache.SOURCE_FILE)
    try:
        with caplog.at_level(logging.WARNING, logger="bugbox"):
            result = version_cache.prime()
        assert fetch.entered.wait(timeout=5), "the prime worker never started"
        assert result == "1.0.0"
        assert len(workers) == 1, "the prime must start exactly one fetch"
        assert fetch.calls == 1
    except BaseException:
        fetch.release.set()
        for worker in workers:
            worker.join(timeout=5)
        raise
    return workers[0]


# ── seeding from disk ──────────────────────────────────────────────────────
def test_cache_seeds_itself_from_the_persisted_file(tmp_path):
    (tmp_path / CACHE_FILENAME).write_text("1.2.3", encoding="utf-8")
    c = _cache(tmp_path)
    assert c.get() == "1.2.3"
    # Provenance: the value came from the file, not the seed default.
    assert c.source() == version_cache.SOURCE_FILE
    assert c.snapshot() == ("1.2.3", version_cache.SOURCE_FILE)


def test_first_start_without_a_file_uses_the_default(tmp_path):
    c = _cache(tmp_path, default="7.0.0")
    assert c.get() == "7.0.0"
    assert c.source() == version_cache.SOURCE_DEFAULT
    assert c.snapshot() == ("7.0.0", version_cache.SOURCE_DEFAULT)


def test_a_seed_value_carries_the_constructor_source(tmp_path):
    """An environment override must not be labelled the built-in default."""
    c = version_cache.VersionCache(
        "9.9.9", path=tmp_path / CACHE_FILENAME,
        default_source=version_cache.SOURCE_ENV_OVERRIDE)
    assert c.snapshot() == ("9.9.9", version_cache.SOURCE_ENV_OVERRIDE)


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


# Bytes that cannot decode as UTF-8: a truncated multi-byte sequence, a
# binary prefix, a lone continuation byte, and an ASCII-looking tag followed
# by a stray high byte (which must not be salvaged by decoding a prefix).
_NON_UTF8_BYTES = [
    b"0.2.\xc3",
    b"\xff\xfe\x00\x00",
    b"\x80",
    b"0.2.2\xff",
]


@pytest.mark.parametrize("payload", _NON_UTF8_BYTES)
def test_non_utf8_persisted_file_is_ignored_and_warned(payload, tmp_path,
                                                       caplog):
    """A binary or truncated file must degrade, not raise out of construction.

    _read_cached runs during cache construction, which the module performs at
    import time, so a UnicodeDecodeError used to abort application startup.
    The cache must fall back to the seed value and label its source.
    """
    (tmp_path / CACHE_FILENAME).write_bytes(payload)
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        c = _cache(tmp_path, default="7.0.0")
    assert c.get() == "7.0.0"
    assert c.source() == version_cache.SOURCE_DEFAULT
    assert c.snapshot() == ("7.0.0", version_cache.SOURCE_DEFAULT)
    assert any("not valid UTF-8" in r.getMessage()
               and CACHE_FILENAME in r.getMessage()
               for r in caplog.records
               if r.levelno == logging.WARNING), caplog.text


def test_non_utf8_file_keeps_the_seed_source_not_the_file(tmp_path, caplog):
    """An unusable file must not relabel the seed as coming from the file."""
    (tmp_path / CACHE_FILENAME).write_bytes(b"\xff\xfe\x00\x00")
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        c = version_cache.VersionCache(
            "9.9.9", path=tmp_path / CACHE_FILENAME,
            default_source=version_cache.SOURCE_ENV_OVERRIDE)
    assert c.snapshot() == ("9.9.9", version_cache.SOURCE_ENV_OVERRIDE)
    assert c.source() != version_cache.SOURCE_FILE


def test_empty_persisted_file_is_ignored(tmp_path):
    """The zero-byte boundary behaves like the whitespace-only case."""
    (tmp_path / CACHE_FILENAME).write_bytes(b"")
    assert _cache(tmp_path, default="7.0.0").get() == "7.0.0"


# ── one atomic read of value and source ────────────────────────────────────
def test_snapshot_reports_the_pair_after_a_fetch(cache):
    cache.set_for_test("1.0.0", time.time(), version_cache.SOURCE_FILE)
    assert cache.snapshot() == ("1.0.0", version_cache.SOURCE_FILE)
    cache.finish_refresh(cache.claim_prime(), "2.0.0")
    assert cache.snapshot() == ("2.0.0", version_cache.SOURCE_NETWORK)


def test_snapshot_is_never_torn_between_two_acquisitions(cache):
    """snapshot() must report one acquisition's pair, never get()+source()."""
    consistent = {
        ("1.1.1", version_cache.SOURCE_FILE),
        ("2.2.2", version_cache.SOURCE_NETWORK),
    }
    stop = threading.Event()
    torn = []

    cache.set_for_test("1.1.1", time.time(), version_cache.SOURCE_FILE)

    def reader():
        while not stop.is_set():
            pair = cache.snapshot()
            if pair not in consistent:
                torn.append(pair)
                return

    def writer():
        for _ in range(2000):
            cache.set_for_test("1.1.1", time.time(),
                               version_cache.SOURCE_FILE)
            cache.set_for_test("2.2.2", time.time(),
                               version_cache.SOURCE_NETWORK)
        stop.set()

    readers = [threading.Thread(target=reader, daemon=True,
                                name="vcache-snapshot-reader")
               for _ in range(4)]
    writer_thread = threading.Thread(target=writer, daemon=True,
                                     name="vcache-snapshot-writer")
    for r in readers:
        r.start()
    writer_thread.start()
    writer_thread.join(timeout=10)
    stop.set()                       # defensive: unblock readers on a failure
    for r in readers:
        r.join(timeout=10)
    assert torn == []


# ── the in-memory swap moves all three fields ──────────────────────────────
def test_set_for_test_moves_the_value_and_source_together(cache):
    """A swapped value must never keep the source of the value it replaced."""
    for value, source in (
        ("1.1.1", version_cache.SOURCE_FILE),
        ("2.2.2", version_cache.SOURCE_NETWORK),
        ("3.3.3", version_cache.SOURCE_ENV_OVERRIDE),
        ("4.4.4", version_cache.SOURCE_DEFAULT),
    ):
        cache.set_for_test(value, time.time(), source)
        assert cache.get() == value
        assert cache.source() == source
        assert cache.snapshot() == (value, source)


def test_set_for_test_defaults_the_source_to_the_network(cache):
    cache.set_for_test("9.9.9", 0.0, version_cache.SOURCE_DEFAULT)
    assert cache.source() == version_cache.SOURCE_DEFAULT
    cache.set_for_test("9.9.9", 0.0)
    assert cache.source() == version_cache.SOURCE_NETWORK


def test_set_for_test_moves_the_timestamp_with_the_value(cache):
    """The swap must move the TTL clock too, not leave it stale."""
    cache.set_for_test("1.1.1", 0.0, version_cache.SOURCE_FILE)
    claim = cache.begin_refresh(version_cache.VERSION_TTL)
    assert isinstance(claim, int)
    cache.finish_refresh(claim)                  # release the claim
    cache.set_for_test("2.2.2", time.time(), version_cache.SOURCE_FILE)
    # The fresh clock answers within the TTL and claims no refresh.
    assert cache.begin_refresh(version_cache.VERSION_TTL) is None
    assert cache.get() == "2.2.2"


# ── persisting after a fetch ───────────────────────────────────────────────
def test_a_successful_refresh_persists_the_tag(cache, monkeypatch):
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: "2.0.0")
    version_cache._refresh(cache.claim_prime())
    assert cache.get() == "2.0.0"
    assert cache.source() == version_cache.SOURCE_NETWORK
    assert cache.path.read_text(encoding="utf-8") == "2.0.0"


def test_the_persisted_write_leaves_no_temp_file(cache):
    cache.finish_refresh(cache.claim_prime(), "4.0.0")
    assert sorted(p.name for p in cache.path.parent.iterdir()) == \
        [CACHE_FILENAME]


def test_a_failed_refresh_keeps_the_last_known_tag(cache, monkeypatch):
    cache.finish_refresh(cache.claim_prime(), "1.9.9")
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: None)
    version_cache._refresh(cache.claim_prime())
    assert cache.get() == "1.9.9"
    assert cache.path.read_text(encoding="utf-8") == "1.9.9"


def test_a_raising_fetch_keeps_the_last_known_tag(cache, monkeypatch, caplog):
    cache.finish_refresh(cache.claim_prime(), "1.9.9")

    def boom():
        raise RuntimeError("network down")

    monkeypatch.setattr(version_cache, "fetch_latest", boom)
    with caplog.at_level(logging.ERROR, logger="bugbox"):
        version_cache._refresh(cache.claim_prime())
    assert cache.get() == "1.9.9"
    assert cache.path.read_text(encoding="utf-8") == "1.9.9"
    assert any("version refresh thread failed" in r.getMessage()
               for r in caplog.records), caplog.text


def test_a_write_failure_keeps_the_value_in_memory_and_warns(tmp_path, caplog):
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        c = version_cache.VersionCache("0.0.1", path=blocker / CACHE_FILENAME)
        c.finish_refresh(c.claim_prime(), "3.0.0")
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
    monkeypatch.setattr(
        version_cache, "fetch_latest",
        lambda: pytest.fail("the recorded worker must never run"))
    # No real thread runs, which is what makes the "return before the fetch
    # completes" rule deterministic.
    built = _record_threads(monkeypatch)
    cache.set_for_test("1.0.0", 0.0)
    # The stale cache still answers immediately with the last known value.
    assert version_cache.latest_version() == "1.0.0"
    assert len(built) == 1
    assert built[0].target is version_cache._refresh
    assert built[0].name == "bugbox-version"
    assert built[0].daemon is True
    # The single claim id is handed to the worker.
    assert built[0].args == (built[0].args[0],)
    assert isinstance(built[0].args[0], int)
    # While that refresh is in flight, no second one is started.
    assert version_cache.latest_version() == "1.0.0"
    assert len(built) == 1


def test_begin_refresh_refuses_a_second_claim_while_one_is_held(cache):
    claim = cache.claim_prime()
    assert isinstance(claim, int)
    # Forced stale, so only the held claim can be the reason for the refusal.
    assert cache.begin_refresh(-1.0) is None
    assert cache.claim_prime() is None


# ── the claim is owned by exactly one worker ───────────────────────────────
def test_an_outdated_claim_cannot_release_the_live_claim(cache, caplog):
    claim = cache.claim_prime()
    assert isinstance(claim, int)
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        cache.finish_refresh(claim + 1, "9.9.9")
    # The stale id changed nothing: not the value, not the disk, not the claim.
    assert cache.snapshot() == ("0.0.1", version_cache.SOURCE_DEFAULT)
    assert not cache.path.exists()
    assert cache.begin_refresh(-1.0) is None
    assert any("not held" in r.getMessage() for r in caplog.records), \
        caplog.text

    # The real owner can still release it, and then the slot is free again.
    cache.finish_refresh(claim, "9.9.9")
    assert cache.snapshot() == ("9.9.9", version_cache.SOURCE_NETWORK)
    assert cache.path.read_text(encoding="utf-8") == "9.9.9"
    assert isinstance(cache.begin_refresh(-1.0), int)


def test_a_released_claim_cannot_release_a_newer_claim(cache, caplog):
    first = cache.claim_prime()
    cache.finish_refresh(first, "1.0.0")
    second = cache.claim_prime()
    assert second != first

    with caplog.at_level(logging.WARNING, logger="bugbox"):
        cache.finish_refresh(first, "2.0.0")     # stale owner, ignored
    assert cache.get() == "1.0.0"                # value not overwritten
    assert cache.claim_prime() is None           # second claim still live
    assert any("not held" in r.getMessage() for r in caplog.records), \
        caplog.text

    cache.finish_refresh(second, "2.0.0")        # the live owner releases
    assert cache.get() == "2.0.0"


def test_a_thread_start_failure_releases_the_claim(cache, monkeypatch,
                                                   caplog):
    """A claim no fetch will ever release must not lock out later refreshes."""
    class _BoomThread:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("cannot start threads")

    monkeypatch.setattr(version_cache, "threading",
                        types.SimpleNamespace(Thread=_BoomThread,
                                              Lock=threading.Lock))
    cache.set_for_test("1.0.0", 0.0)
    with caplog.at_level(logging.ERROR, logger="bugbox"):
        assert version_cache.latest_version() == "1.0.0"
    assert any("could not start" in r.getMessage() for r in caplog.records), \
        caplog.text
    # The claim was released on the failed worker's behalf.
    assert isinstance(cache.claim_prime(), int)


# ── startup priming ────────────────────────────────────────────────────────
# prime() resolves the tag once from the app's lifespan hook: fetch first,
# fall back to the persisted file, and only then to the built-in default.
def test_prime_holds_and_persists_the_fetched_tag(cache, monkeypatch):
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: "3.1.4")
    assert version_cache.prime() == "3.1.4"
    assert cache.get() == "3.1.4"
    assert cache.source() == version_cache.SOURCE_NETWORK
    # The fetched tag is on disk, so the next restart starts from it.
    assert cache.path.read_text(encoding="utf-8") == "3.1.4"


def test_prime_logs_the_resolved_version_and_source(cache, monkeypatch,
                                                   caplog):
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: "3.1.4")
    with caplog.at_level(logging.INFO, logger="bugbox"):
        version_cache.prime()
    lines = [r.getMessage() for r in caplog.records
             if r.levelno == logging.INFO]
    assert len(lines) == 1, caplog.text
    assert "3.1.4" in lines[0]
    assert version_cache.SOURCE_NETWORK in lines[0]


def test_prime_keeps_the_persisted_tag_when_the_fetch_fails(tmp_path,
                                                            monkeypatch):
    (tmp_path / CACHE_FILENAME).write_text("1.2.3", encoding="utf-8")
    c = _cache(tmp_path)
    monkeypatch.setattr(version_cache, "VERSIONS", c)
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: None)
    # A failed fetch is not fatal: it returns the persisted value instead.
    assert version_cache.prime() == "1.2.3"
    assert c.get() == "1.2.3"
    assert c.source() == version_cache.SOURCE_FILE
    assert c.path.read_text(encoding="utf-8") == "1.2.3"


def test_prime_uses_the_builtin_default_when_nothing_is_available(cache,
                                                                  monkeypatch):
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: None)
    assert version_cache.prime() == "0.0.1"
    assert cache.get() == "0.0.1"
    assert cache.source() == version_cache.SOURCE_DEFAULT


def test_prime_ignores_a_corrupt_persisted_file_and_uses_the_default(
        tmp_path, monkeypatch):
    (tmp_path / CACHE_FILENAME).write_text("not-a-version", encoding="utf-8")
    c = _cache(tmp_path)
    monkeypatch.setattr(version_cache, "VERSIONS", c)
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: None)
    assert version_cache.prime() == "0.0.1"
    assert c.source() == version_cache.SOURCE_DEFAULT


def test_prime_ignores_a_non_utf8_persisted_file_and_uses_the_seed(
        tmp_path, monkeypatch, caplog):
    """The startup prime must also survive a non-UTF-8 persisted file.

    Construction already fell back to the seed; priming with a failed fetch
    must return that seed value normally instead of raising.
    """
    (tmp_path / CACHE_FILENAME).write_bytes(b"\xff\xfe\x00\x00")
    c = _cache(tmp_path)
    monkeypatch.setattr(version_cache, "VERSIONS", c)
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: None)
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        assert version_cache.prime() == "0.0.1"
    assert c.get() == "0.0.1"
    assert c.source() == version_cache.SOURCE_DEFAULT
    assert any("not valid UTF-8" in r.getMessage()
               for r in caplog.records), caplog.text


def test_a_successful_prime_serves_without_a_second_fetch(cache, monkeypatch):
    calls = []
    monkeypatch.setattr(version_cache, "fetch_latest",
                        lambda: calls.append(1) or "3.1.4")
    version_cache.prime()
    assert calls == [1]

    built = _record_threads(monkeypatch)
    # The TTL clock was restarted by the prime, so a read is served from
    # memory without touching the network.
    assert version_cache.latest_version() == "3.1.4"
    assert built == []
    assert calls == [1]


def test_a_stale_read_after_a_prime_is_still_allowed_to_refresh(cache,
                                                               monkeypatch):
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: "3.1.4")
    version_cache.prime()

    built = _record_threads(monkeypatch)
    cache.set_for_test("3.1.4", time.time() - version_cache.VERSION_TTL - 1)
    assert version_cache.latest_version() == "3.1.4"
    assert len(built) == 1
    assert built[0].target is version_cache._refresh
    assert built[0].name == "bugbox-version"
    assert isinstance(built[0].args[0], int)


def test_a_failed_prime_leaves_the_lazy_refresh_available(cache, monkeypatch):
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: None)
    version_cache.prime()

    built = _record_threads(monkeypatch)
    # The failed prime must not have claimed a refresh or restarted the TTL.
    assert version_cache.latest_version() == "0.0.1"
    assert len(built) == 1
    assert built[0].target is version_cache._refresh


def test_a_raising_prime_leaves_the_lazy_refresh_available(cache, monkeypatch,
                                                           caplog):
    def boom():
        raise RuntimeError("network down")

    monkeypatch.setattr(version_cache, "fetch_latest", boom)
    with caplog.at_level(logging.ERROR, logger="bugbox"):
        version_cache.prime()

    built = _record_threads(monkeypatch)
    assert version_cache.latest_version() == "0.0.1"
    assert len(built) == 1
    assert built[0].target is version_cache._refresh


def test_prime_keeps_the_environment_override_and_its_source(tmp_path,
                                                              monkeypatch):
    """A failed startup fetch leaves the override and names it as the source.

    The value came from BGBOX_OVERLAY_VERSION, so the reported source must
    be the override, never the built-in default.
    """
    c = version_cache.VersionCache(
        "9.9.9", path=tmp_path / CACHE_FILENAME,
        default_source=version_cache.SOURCE_ENV_OVERRIDE)
    monkeypatch.setattr(version_cache, "VERSIONS", c)
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: None)
    assert version_cache.prime() == "9.9.9"
    assert c.get() == "9.9.9"
    assert c.source() == version_cache.SOURCE_ENV_OVERRIDE
    assert c.source() != version_cache.SOURCE_DEFAULT
    assert not c.path.exists()                   # nothing was persisted


def test_a_successful_prime_reports_the_network_even_when_persist_fails(
        tmp_path, monkeypatch, caplog):
    """An unwritable persistence target must not change what is reported."""
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    c = version_cache.VersionCache("0.0.1", path=blocker / CACHE_FILENAME)
    monkeypatch.setattr(version_cache, "VERSIONS", c)
    monkeypatch.setattr(version_cache, "fetch_latest", lambda: "3.0.0")
    with caplog.at_level(logging.WARNING, logger="bugbox"):
        assert version_cache.prime() == "3.0.0"
    assert c.get() == "3.0.0"
    assert c.source() == version_cache.SOURCE_NETWORK
    assert any("could not persist" in r.getMessage() for r in caplog.records), \
        caplog.text


# ── the prime's shared in-flight claim ─────────────────────────────────────
def test_prime_returns_within_the_bound_when_the_fetch_hangs(
        cache, monkeypatch, caplog):
    """A fetch that outlives PRIME_TIMEOUT must not stall startup.

    The stub blocks on an Event instead of sleeping, so the test is
    deterministic and the caller can release the worker afterwards; no
    non-daemon thread is left behind that could hold the interpreter open.
    """
    fetch = _GatedFetch(result="5.5.5")
    workers = _capture_workers(monkeypatch)
    monkeypatch.setattr(version_cache, "fetch_latest", fetch)
    monkeypatch.setattr(version_cache, "PRIME_TIMEOUT", 0.3)
    cache.set_for_test("1.0.0", time.time(), version_cache.SOURCE_FILE)

    with caplog.at_level(logging.WARNING, logger="bugbox"):
        start = time.monotonic()
        result = version_cache.prime()
        elapsed = time.monotonic() - start
    try:
        assert fetch.entered.wait(timeout=5), "the prime worker never started"
        assert result == "1.0.0"
        assert cache.get() == "1.0.0"
        assert cache.source() == version_cache.SOURCE_FILE
        # Back at the named bound, with a generous tolerance for a loaded box.
        assert elapsed < version_cache.PRIME_TIMEOUT + 1.0
        assert any("still in flight" in r.getMessage()
                   for r in caplog.records
                   if r.levelno == logging.WARNING), caplog.text

        assert len(workers) == 1
        assert workers[0].daemon is True
        assert workers[0].is_alive()

        # The timed-out prime keeps the shared claim: a stale read must defer
        # instead of starting a second, concurrent fetch.
        built = _record_threads(monkeypatch)
        cache.set_for_test("1.0.0",
                           time.time() - version_cache.VERSION_TTL - 1,
                           version_cache.SOURCE_FILE)
        assert version_cache.latest_version() == "1.0.0"
        assert built == []
        assert fetch.calls == 1
    finally:
        # Release the blocked fetch so it completes instead of leaking, then
        # let the worker finish: no non-daemon thread survives it.
        fetch.release.set()
        workers[0].join(timeout=5)

    assert not workers[0].is_alive()
    assert not any(t.name == "bugbox-version-prime"
                   for t in threading.enumerate())
    # The late result lands in the cache and restarts the TTL clock.
    assert cache.snapshot() == ("5.5.5", version_cache.SOURCE_NETWORK)


def test_a_timed_out_prime_still_persists_when_the_fetch_finishes(
        tmp_path, monkeypatch):
    """After the bound expires, a late fetch result updates and persists."""
    c = _cache(tmp_path, default="0.0.1")
    monkeypatch.setattr(version_cache, "VERSIONS", c)
    fetch = _GatedFetch(result="6.6.6")
    monkeypatch.setattr(version_cache, "fetch_latest", fetch)
    monkeypatch.setattr(version_cache, "PRIME_TIMEOUT", 0.2)

    assert version_cache.prime() == "0.0.1"
    assert fetch.entered.wait(timeout=5), "the prime worker never started"
    assert c.get() == "0.0.1"
    assert c.source() == version_cache.SOURCE_DEFAULT
    # Nothing has been persisted yet: the fetch is still in flight.
    assert not c.path.exists()

    fetch.release.set()
    _join_named("bugbox-version-prime")
    assert c.get() == "6.6.6"
    assert c.source() == version_cache.SOURCE_NETWORK
    assert c.path.read_text(encoding="utf-8") == "6.6.6"


def _join_named(name, timeout=5):
    """Join the one named worker thread, if it is still around."""
    for t in threading.enumerate():
        if t.name == name and t is not threading.current_thread():
            t.join(timeout)
            assert not t.is_alive(), f"{name} outlived the test"


def test_a_lazy_read_defers_while_the_prime_fetch_is_in_flight(
        cache, monkeypatch, caplog):
    fetch = _GatedFetch(result="5.5.5")
    worker = _timed_out_prime(cache, monkeypatch, caplog, fetch)
    try:
        built = _record_threads(monkeypatch)
        cache.set_for_test("1.0.0",
                           time.time() - version_cache.VERSION_TTL - 1,
                           version_cache.SOURCE_FILE)
        # The stale read still answers, but must not start a second fetch.
        assert version_cache.latest_version() == "1.0.0"
        assert built == []
        assert fetch.calls == 1
    finally:
        fetch.release.set()
        worker.join(timeout=5)
    assert not worker.is_alive()


def test_a_lazy_read_refreshes_again_after_the_in_flight_prime_succeeds(
        cache, monkeypatch, caplog):
    fetch = _GatedFetch(result="5.5.5")
    worker = _timed_out_prime(cache, monkeypatch, caplog, fetch)
    fetch.release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert cache.snapshot() == ("5.5.5", version_cache.SOURCE_NETWORK)

    # The claim is released, so a later stale read can start a refresh again.
    built = _record_threads(monkeypatch)
    cache.set_for_test("5.5.5",
                       time.time() - version_cache.VERSION_TTL - 1,
                       version_cache.SOURCE_NETWORK)
    assert version_cache.latest_version() == "5.5.5"
    assert len(built) == 1
    assert built[0].target is version_cache._refresh


def test_a_lazy_read_refreshes_again_after_the_in_flight_prime_fails(
        cache, monkeypatch, caplog):
    fetch = _GatedFetch(result=None)
    worker = _timed_out_prime(cache, monkeypatch, caplog, fetch)
    fetch.release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    # A failed fetch keeps the last known value and its source.
    assert cache.snapshot() == ("1.0.0", version_cache.SOURCE_FILE)

    built = _record_threads(monkeypatch)
    cache.set_for_test("1.0.0",
                       time.time() - version_cache.VERSION_TTL - 1,
                       version_cache.SOURCE_FILE)
    assert version_cache.latest_version() == "1.0.0"
    assert len(built) == 1
    assert built[0].target is version_cache._refresh


def test_the_prime_defers_to_a_refresh_that_is_already_in_flight(
        cache, monkeypatch, caplog):
    """A request that got in first owns the claim: prime starts no second fetch."""
    fetch = _GatedFetch(result="4.4.4")
    monkeypatch.setattr(version_cache, "fetch_latest", fetch)
    workers = _capture_workers(monkeypatch)
    cache.set_for_test("1.0.0", time.time() - version_cache.VERSION_TTL - 1,
                       version_cache.SOURCE_FILE)

    # The request arrives first and starts the lazy refresh.
    assert version_cache.latest_version() == "1.0.0"
    try:
        assert fetch.entered.wait(timeout=5), "the lazy worker never started"
        assert fetch.calls == 1
        assert len(workers) == 1

        # Startup then runs while that fetch is still in flight: it must not
        # start a second one and must report the value the cache holds.
        with caplog.at_level(logging.WARNING, logger="bugbox"):
            assert version_cache.prime() == "1.0.0"
        assert fetch.calls == 1
        assert len(workers) == 1
        assert any("already in flight" in r.getMessage()
                   for r in caplog.records), caplog.text
    finally:
        fetch.release.set()
        workers[0].join(timeout=5)
    assert not workers[0].is_alive()
    assert cache.get() == "4.4.4"


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

# The startup fetch is stubbed: importing the module must never reach the
# network, and prime() is what a real startup runs.
version_cache.fetch_latest = lambda: None
version_cache.prime()

value, source = version_cache.VERSIONS.snapshot()
print(json.dumps({
    "default": version_cache.DEFAULT_VERSION,
    "default_source": version_cache.DEFAULT_SOURCE,
    "current": value,
    "source": source,
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
    assert out["source"] == version_cache.SOURCE_DEFAULT


def test_overlay_version_is_the_first_start_default(tmp_path):
    """The override seeds the value and is named as its source, not the
    built-in default (the startup fetch fails in the child)."""
    out = _run_child(tmp_path, {"BGBOX_OVERLAY_VERSION": " 9.9.9 "})
    assert out["default"] == "9.9.9"
    assert out["current"] == "9.9.9"
    assert out["default_source"] == version_cache.SOURCE_ENV_OVERRIDE
    assert out["source"] == version_cache.SOURCE_ENV_OVERRIDE
    assert out["source"] != version_cache.SOURCE_DEFAULT


def test_persisted_tag_wins_over_the_environment_on_restart(tmp_path):
    (tmp_path / CACHE_FILENAME).write_text("1.2.3", encoding="utf-8")
    out = _run_child(tmp_path, {"BGBOX_OVERLAY_VERSION": "9.9.9"})
    assert out["current"] == "1.2.3"
    assert out["source"] == version_cache.SOURCE_FILE


def test_persisted_tag_is_shown_when_the_environment_is_unset(tmp_path):
    (tmp_path / CACHE_FILENAME).write_text("1.2.3", encoding="utf-8")
    out = _run_child(tmp_path, {"BGBOX_OVERLAY_VERSION": None})
    assert out["current"] == "1.2.3"
    assert out["default"] == FALLBACK
    assert out["source"] == version_cache.SOURCE_FILE


def test_import_with_a_non_utf8_persisted_file_does_not_raise(tmp_path):
    """The regression: this used to abort application import at startup.

    _run_child imports version_cache for real and asserts a zero exit code,
    so a UnicodeDecodeError escaping cache construction fails this test.
    """
    (tmp_path / CACHE_FILENAME).write_bytes(b"\xff\xfe\x00\x00")
    out = _run_child(tmp_path, {"BGBOX_OVERLAY_VERSION": None})
    assert out["current"] == FALLBACK
    assert out["source"] == version_cache.SOURCE_DEFAULT
