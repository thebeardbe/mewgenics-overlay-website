"""Latest overlay release tag: fetched lazily, cached, persisted on disk.

The landing page shows the newest overlay release number next to the
download buttons. GitHub is the source of truth, but a page load must never
wait on it, so the tag is cached in memory and refreshed by a background
thread once the cached value is stale.

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
# Shown only on a first start, before anything has been fetched.
_FALLBACK_VERSION = "0.1.46"
# BGBOX_OVERLAY_VERSION is optional and an unfilled .env line leaves it
# empty, so whitespace means "unset" rather than "show nothing".
DEFAULT_VERSION = (os.environ.get("BGBOX_OVERLAY_VERSION", "").strip()
                   or _FALLBACK_VERSION)
VERSION_TTL = 300.0
# One short line of text, beside bugbox.db in the data directory.
CACHE_FILENAME = "overlay-version.txt"
_TAG_RE = re.compile(r"\d+\.\d+\.\d+")
_FETCH_TIMEOUT = 4.0
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
    except OSError as exc:
        logger.warning("overlay version file unreadable at %s: %s", path, exc)
        return None
    if not _plausible(text):
        logger.warning("persisted overlay version at %s holds %r, which is "
                       "not a version; using the default", path, text[:64])
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

    def __init__(self, default: str, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else (
            Path(store.DATA_DIR) / CACHE_FILENAME)
        self._version = _read_cached(self.path) or default
        self._ts = 0.0
        self._refreshing = False
        self._lock = threading.Lock()

    def get(self) -> str:
        with self._lock:
            return self._version

    def begin_refresh(self, ttl: float) -> bool:
        """True when a background refresh should start (atomic claim)."""
        with self._lock:
            if self._refreshing or time.time() - self._ts <= ttl:
                return False
            self._refreshing = True
            return True

    def finish_refresh(self, version: str | None = None) -> None:
        """Close a refresh and persist a tag that was fetched successfully.

        *version* is None when the fetch failed; the last known value is
        kept, never the built-in default.
        """
        with self._lock:
            self._refreshing = False
            if version:
                self._version = version
                self._ts = time.time()
        if version:
            _write_cached(self.path, version)

    def set_for_test(self, version: str, ts: float) -> None:
        with self._lock:
            self._version = version
            self._ts = ts


VERSIONS = VersionCache(DEFAULT_VERSION)


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


def _refresh() -> None:
    try:
        VERSIONS.finish_refresh(fetch_latest())
    except Exception:
        logger.exception("version refresh thread failed")
        VERSIONS.finish_refresh()


def latest_version() -> str:
    """Cached overlay version; refreshes in the background when stale."""
    if VERSIONS.begin_refresh(VERSION_TTL):
        threading.Thread(target=_refresh, name="bugbox-version",
                         daemon=True).start()
    return VERSIONS.get()
