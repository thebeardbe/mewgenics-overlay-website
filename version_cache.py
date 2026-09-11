"""Latest overlay release tag: primed at startup, cached, persisted on disk.

The landing page shows the newest overlay release number next to the
download buttons. GitHub is the source of truth, but a page load must never
wait on it, so the tag is cached in memory and refreshed by a background
thread once the cached value is stale.

Startup primes that cache once through prime(): the background refresh only
starts when a request arrives, so without the prime the first page load
after a restart rendered the built-in fallback (or a stale persisted tag)
before the fetch had finished. Priming is best-effort and bounded: the
fetch runs on a daemon thread that startup waits for at most PRIME_TIMEOUT
seconds, a bound that must also cover DNS name resolution, and startup
continues with whatever the cache already held when that wait expires. A
tag fetched during the prime is persisted like any other successful fetch.
The prime and the lazy refresh share one in-flight claim, so at most one
fetch runs at a time: a fetch still running when the startup wait expires
keeps the claim, and the first request defers instead of starting a
second, concurrent fetch.

The cache also persists the last tag that was fetched successfully to a
small text file inside the data directory. That directory is the mounted
volume, so the first page load after a restart shows the last known release
instead of the built-in fallback. Reading or writing that file is
best-effort: a failure is logged and ignored, and the page keeps rendering
whatever value the cache already holds.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import urllib.request
from pathlib import Path

import store

logger = logging.getLogger("bugbox")

VERSION_URL = ("https://api.github.com/repos/thebeardbe/"
               "mewgenics-breeding-overlay/releases/latest")
# Shown only on a first start, before anything has been fetched. Bump it to
# the current overlay release on every change to this repository, so a brand
# new deployment never advertises an old release.
_FALLBACK_VERSION = "0.2.2"
# Where the currently held tag came from, named in the startup log line.
SOURCE_NETWORK = "the network fetch"
SOURCE_FILE = "the persisted version file"
SOURCE_DEFAULT = "the built-in default"
# Kept apart from SOURCE_DEFAULT: an operator who set the environment
# variable must not read a startup line claiming the built-in default
# supplied the tag.
SOURCE_ENV_OVERRIDE = "the BGBOX_OVERLAY_VERSION override"
# BGBOX_OVERLAY_VERSION is optional and an unfilled .env line leaves it
# empty, so whitespace means "unset" rather than "show nothing".
_ENV_OVERRIDE = os.environ.get("BGBOX_OVERLAY_VERSION", "").strip()
DEFAULT_VERSION = _ENV_OVERRIDE or _FALLBACK_VERSION
# The seed value's provenance, so a cache with no persisted file labels its
# held tag correctly.
DEFAULT_SOURCE = SOURCE_ENV_OVERRIDE if _ENV_OVERRIDE else SOURCE_DEFAULT
VERSION_TTL = 300.0
# One short line of text, beside bugbox.db in the data directory.
CACHE_FILENAME = "overlay-version.txt"
_TAG_RE = re.compile(r"\d+\.\d+\.\d+")
_FETCH_TIMEOUT = 4.0
# Wall-clock bound for the startup prime's wait on its fetch thread. This
# must include DNS name resolution, which urllib's timeout does not cover,
# so it is deliberately larger than _FETCH_TIMEOUT: a black-holed resolver
# would otherwise stall startup well past the intended few seconds.
PRIME_TIMEOUT = 8.0
_HTTP_HEADERS = {"User-Agent": "bugbox-landing",
                 "Accept": "application/vnd.github+json"}


def _plausible(tag: str) -> bool:
    """True for a release tag shaped like '0.1.46' (a leading v is dropped)."""
    return bool(_TAG_RE.fullmatch(tag))


def _read_cached(path: Path) -> str | None:
    """The persisted tag, or None when there is nothing usable on disk."""
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        # Genuinely first start: no file yet, not a failure.
        logger.debug("no persisted overlay version at %s yet", path)
        return None
    except UnicodeDecodeError as exc:
        # Bytes that are not UTF-8 (a truncated or binary file) cannot hold
        # a tag, and this runs at import time, so it must never raise.
        logger.warning("persisted overlay version at %s is not valid UTF-8, "
                       "so it is unusable: %s", path, exc)
        return None
    except OSError as exc:
        logger.warning("overlay version file unreadable at %s: %s", path, exc)
        return None
    if not _plausible(text):
        logger.warning("persisted overlay version at %s holds %r, which is "
                       "not a version; falling back to the seed value",
                       path, text[:64])
        return None
    return text


def _write_cached(path: Path, version: str) -> None:
    """Persist *version* via a temp file plus rename, so a crash cannot leave
    a partially written tag behind."""
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(version)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        logger.warning("could not persist overlay version to %s: %s",
                       path, exc)


class VersionCache:
    """Owned cache for the latest overlay release tag (one instance app-wide).

    *path* is injectable so a caller can point the cache at a temporary
    location instead of the real data directory.
    """

    def __init__(self, default: str, path: Path | str | None = None,
                 default_source: str = SOURCE_DEFAULT) -> None:
        """*default_source* labels *default*, so an environment override is
        distinguishable from the compiled-in fallback."""
        self.path = Path(path) if path is not None else (
            Path(store.DATA_DIR) / CACHE_FILENAME)
        cached = _read_cached(self.path)
        self._version = cached or default
        self._source = SOURCE_FILE if cached else default_source
        self._ts = 0.0
        # The single in-flight refresh claim, taken by both the startup
        # prime and the lazy refresh: the id of the fetch worker that owns
        # it, or None when no fetch is running.
        self._claim_id: int | None = None
        self._next_claim_id = 0
        self._lock = threading.Lock()

    def get(self) -> str:
        with self._lock:
            return self._version

    def source(self) -> str:
        """Where the held tag came from: one of the SOURCE_* phrases."""
        with self._lock:
            return self._source

    def snapshot(self) -> tuple[str, str]:
        """The held tag and its source, read in one lock acquisition.

        Reading the two separately can pair a tag with the source of the
        tag it replaced when a fetch finishes in between, so a caller that
        reports both uses this snapshot instead.
        """
        with self._lock:
            return self._version, self._source

    def _take_claim(self) -> int | None:
        """Take the single refresh claim, or None when it is already held.

        Callers must hold the lock. The returned id identifies the owner:
        only the worker that passes it back to finish_refresh() releases
        the claim.
        """
        if self._claim_id is not None:
            return None
        self._next_claim_id += 1
        self._claim_id = self._next_claim_id
        return self._claim_id

    def begin_refresh(self, ttl: float) -> int | None:
        """Claim the refresh slot for a background refresh of a stale tag.

        Returns the claim id to hand to the fetch worker, or None when a
        refresh is already in flight (so the caller defers instead of
        starting a duplicate fetch) or the held tag is still fresh. The
        worker releases the claim through finish_refresh(claim_id, ...).
        """
        with self._lock:
            if time.time() - self._ts <= ttl:
                return None
            return self._take_claim()

    def claim_prime(self) -> int | None:
        """Claim the refresh slot for the startup prime.

        Unlike begin_refresh() this ignores the time-to-live: the prime
        resolves the tag before the first request whatever the cache
        already holds. Returns None when a refresh is already in flight, in
        which case the prime must not start a second fetch.
        """
        with self._lock:
            return self._take_claim()

    def finish_refresh(self, claim_id: int,
                       version: str | None = None) -> None:
        """Release the claim that *claim_id* owns and persist a fetched tag.

        *version* is None when the fetch failed; the last known value is
        kept, never the built-in default. A claim that is no longer held,
        or held by another worker, is left alone: only the worker that took
        a claim releases it.
        """
        with self._lock:
            if self._claim_id != claim_id:
                logger.warning("ignoring finish of version refresh claim "
                               "%s, which is not held (current claim: %s)",
                               claim_id, self._claim_id)
                return
            self._claim_id = None
            if version:
                self._version = version
                self._source = SOURCE_NETWORK
                self._ts = time.time()
        if version:
            _write_cached(self.path, version)

    def set_for_test(self, version: str, ts: float,
                     source: str = SOURCE_NETWORK) -> None:
        """Swap the held tag, its timestamp and its source label.

        Used for controlled scenarios. The label moves with the value,
        otherwise a swapped tag keeps reporting the source of the value it
        replaced; *source* defaults to SOURCE_NETWORK, the label of a
        freshly fetched tag.
        """
        with self._lock:
            self._version = version
            self._ts = ts
            self._source = source


VERSIONS = VersionCache(DEFAULT_VERSION, default_source=DEFAULT_SOURCE)


def fetch_latest() -> str | None:
    """Fetch the newest overlay release tag (e.g. '0.1.46'); best-effort.

    Returns None on any failure so the caller keeps the last known value.
    """
    logger.debug("refreshing overlay version from GitHub")
    try:
        req = urllib.request.Request(VERSION_URL, headers=_HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        tag = str(data.get("tag_name") or "").lstrip("v")
        if _plausible(tag):
            logger.debug("overlay version refreshed: %s", tag)
            return tag
        logger.warning("GitHub reported an unusable release tag: %r",
                       tag[:64])
    except Exception as exc:
        logger.warning("overlay version refresh failed: %s", exc)
    return None


def _refresh(claim_id: int) -> None:
    """Fetch the tag and release *claim_id*, whether that fetch succeeds,
    fails or raises."""
    try:
        VERSIONS.finish_refresh(claim_id, fetch_latest())
    except Exception:
        logger.exception("version refresh thread failed")
        VERSIONS.finish_refresh(claim_id)


def _start_refresh(claim_id: int, name: str) -> threading.Thread | None:
    """Start the fetch worker that owns *claim_id*.

    Returns None when the worker could not be built or started, having
    released the claim on the worker's behalf: a claim that no fetch will
    ever release would lock out every later refresh.
    """
    try:
        worker = threading.Thread(target=_refresh, args=(claim_id,),
                                  name=name, daemon=True)
        worker.start()
    except Exception:
        logger.exception("could not start the %s thread; releasing its "
                         "refresh claim", name)
        VERSIONS.finish_refresh(claim_id)
        return None
    return worker


def prime() -> str:
    """Resolve the overlay version once, before the first request is served.

    Called from the app's startup hook. The fetch runs on a daemon thread
    that this function waits for at most PRIME_TIMEOUT seconds, a bound that
    also covers DNS name resolution. When the fetch is still running at that
    point a warning is logged, the value the cache already holds is
    returned and startup continues; the fetch is left to finish and persist
    in the background. Fetch failures are logged inside fetch_latest() and
    startup continues with the value read from disk, the environment
    override or the compiled-in fallback.

    The prime takes the same in-flight claim as the lazy background
    refresh, so a fetch that outruns the wait keeps its claim and the first
    request defers instead of starting a second, concurrent fetch. That
    claim is released once the fetch finishes or fails, so a failed prime
    never locks out a later refresh. A successful fetch restarts the TTL
    clock, which keeps the lazy background refresh idle until the tag is
    stale.

    Logs exactly one INFO line naming the resolved version and its source,
    taken as one snapshot so the pair cannot mix values from two fetches; in
    the timeout case it is preceded by one WARNING. Returns the version the
    cache now holds. Never raises.
    """
    claim_id = VERSIONS.claim_prime()
    worker: threading.Thread | None = None
    if claim_id is None:
        logger.warning("a version refresh was already in flight when the "
                       "cache was primed; continuing with the current "
                       "value")
    else:
        worker = _start_refresh(claim_id, "bugbox-version-prime")
    if worker is not None:
        try:
            worker.join(PRIME_TIMEOUT)
        except Exception:
            logger.exception("could not wait for the startup overlay "
                             "version fetch; continuing with the current "
                             "value")
    if worker is not None and worker.is_alive():
        logger.warning("startup overlay version fetch is still in flight "
                       "after %.1f s (name resolution included); continuing "
                       "with the current value", PRIME_TIMEOUT)
    version, source = VERSIONS.snapshot()
    logger.info("overlay version %s resolved from %s", version, source)
    return version


def latest_version() -> str:
    """Cached overlay version; refreshes in the background when stale."""
    claim_id = VERSIONS.begin_refresh(VERSION_TTL)
    if claim_id is not None:
        _start_refresh(claim_id, "bugbox-version")
    return VERSIONS.get()
