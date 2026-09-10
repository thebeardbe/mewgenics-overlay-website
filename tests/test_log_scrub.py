"""The rotating log file is scrubbed by one formatter; the console is not.

Derived from app.py: the file handler installs a `_ScrubFormatter` and no
filter. The formatter scrubs the fully rendered line, which is the only place
that holds the substituted arguments and the traceback together, so it covers
a secret passed as a logging argument (record.args) and a secret inside an
exception message, and it leaves the shared LogRecord alone, so the console
handler still prints the original line.

The handler and the formatter are built at import time from BGBOX_LOG_FILE, so
importing `app` here would leak a file handler into every other test module.
This module therefore runs the real import plus the real 500 path in a fresh
interpreter and asserts on the bytes that interpreter wrote to the log file,
which keeps the module-level logging configuration fully isolated.

Run (see tests/test_bugbox.py for the environment):

    BGBOX_ADMIN_PASS=test-pass BGBOX_COOKIE_KEY=test-key python -m pytest tests/ -q
"""

import os
import re
import subprocess
import sys
import tempfile

import pytest

# Both secrets pass the scrubber's >= 6 char floor; the exception message and
# the normal log line carry SECRET so the test watches one known value.
SECRET = "trace-secret-4f2c9a"
COOKIE_KEY = "cookie-key-9zz"
KEPT_VALUE = "kept-value-77"
NORMAL_MARKER = "normal-line-marker"
PARAM_LINE_MARKER = "param-line-marker"
PARAM_EXC_MARKER = "param-exc-marker"
DOUBLE_LINE_MARKER = "double-line-marker"
REDACTION = "[redacted]"

# A formatted record starts with the formatter's %(asctime)s; a traceback is
# appended to the same record, so this splits records, not text lines.
_RECORD_START = re.compile(r"(?=^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
                           re.MULTILINE)


def _record(text, marker):
    """The one record (formatted line plus any traceback) mentioning *marker*."""
    matches = [rec for rec in _RECORD_START.split(text) if marker in rec]
    assert len(matches) == 1, matches
    return matches[0]


# Runs in its own interpreter: BGBOX_LOG_FILE is set in the environment before
# the import, so app.py wires up the RotatingFileHandler + scrub formatter.
_CHILD = """
import logging
import os

import app as bugbox_app
from fastapi.testclient import TestClient

SECRET = os.environ["BGBOX_ADMIN_PASS"]
KEPT = os.environ["BGBOX_KEPT_VALUE"]


def boom():
    raise RuntimeError("secret inside the exception: " + SECRET)


bugbox_app.latest_version = boom
client = TestClient(bugbox_app.app, raise_server_exceptions=False)
resp = client.get("/", headers={"Accept": "text/html"})
if resp.status_code != 500:
    raise SystemExit("expected the 500 handler, got %s" % resp.status_code)

# The other documented guarantee: a secret passed as a logging argument. The
# non-secret argument must survive scrubbing.
logging.getLogger("bugbox").warning("normal-line-marker %s", SECRET)
logging.getLogger("bugbox").warning("param-line-marker %s %s", KEPT, SECRET)

# The same secret twice on one line: the formatter's replacing call must scrub
# every occurrence, not just the first.
logging.getLogger("bugbox").warning(
    "double-line-marker before %s and also %s after", SECRET, SECRET)

# The same kind of parameterized call, but with a traceback attached.
try:
    raise RuntimeError("param-exc failure")
except RuntimeError:
    logging.getLogger("bugbox").error("param-exc-marker %s %s", KEPT, SECRET,
                                      exc_info=True)

for _h in logging.getLogger("bugbox").handlers:
    _h.flush()
with open(os.environ["BGBOX_LOG_FILE"], encoding="utf-8") as fh:
    print(fh.read(), end="")
"""


@pytest.fixture(scope="module")
def log_file_text():
    """The log file written by a fresh interpreter with the file log enabled."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmp = tempfile.mkdtemp(prefix="bugbox-logscrub-")
    env = dict(os.environ)
    env.update({
        "BGBOX_LOG_FILE": os.path.join(tmp, "bugbox.log"),
        "BGBOX_DATA": os.path.join(tmp, "data"),
        "BGBOX_ADMIN_PASS": SECRET,
        "BGBOX_COOKIE_KEY": COOKIE_KEY,
        "BGBOX_KEPT_VALUE": KEPT_VALUE,
        "PYTHONPATH": repo_root,
    })
    env.pop("LLM_API_KEY", None)          # no analysis / network in the child
    proc = subprocess.run([sys.executable, "-c", _CHILD], cwd=repo_root,
                          env=env, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert proc.stdout.strip(), "the log file was empty"
    return proc.stdout


def test_secret_never_reaches_the_log_file(log_file_text):
    assert SECRET not in log_file_text


def test_redaction_marker_is_written_to_the_log_file(log_file_text):
    # Scrubbing may not be a silent deletion: the reader must see that a
    # value was removed.
    assert REDACTION in log_file_text


def test_traceback_is_still_written_to_the_log_file(log_file_text):
    # The fix must not amount to dropping the traceback wholesale.
    assert "Traceback (most recent call last)" in log_file_text
    assert "RuntimeError" in log_file_text
    assert "secret inside the exception" in log_file_text


def test_a_normal_logged_line_is_scrubbed_too(log_file_text):
    # The formatter sees the rendered line, so a secret that only ever lived in
    # record.args is still replaced. The old filter cleared the arguments
    # instead, leaving the bare "%s" and no marker, which this pins down.
    lines = [line for line in log_file_text.splitlines()
             if NORMAL_MARKER in line]
    assert len(lines) == 1, lines
    assert SECRET not in lines[0]
    assert REDACTION in lines[0]
    assert "%s" not in lines[0]


def test_a_secret_twice_on_one_line_is_fully_scrubbed(log_file_text):
    # replace() handles every occurrence, so a line that repeats the secret
    # must leave no copy behind and keep the text around it intact.
    lines = [line for line in log_file_text.splitlines()
             if DOUBLE_LINE_MARKER in line]
    assert len(lines) == 1, lines
    line = lines[0]
    assert line.count(REDACTION) == 2
    assert SECRET not in line
    assert "before" in line and "and also" in line and "after" in line
    assert "%s" not in line


def test_parameterized_line_keeps_its_values(log_file_text):
    # Regression: a scrub that patches the message template (or drops the
    # arguments) must not eat the values that merely accompanied the secret.
    record = _record(log_file_text, PARAM_LINE_MARKER)
    assert KEPT_VALUE in record
    assert REDACTION in record
    assert "%s" not in record
    assert SECRET not in record


def test_parameterized_exception_keeps_its_values(log_file_text):
    # Same call shape, with a traceback: the line and the traceback are one
    # record and must be scrubbed together.
    record = _record(log_file_text, PARAM_EXC_MARKER)
    assert "Traceback (most recent call last)" in record
    assert KEPT_VALUE in record
    assert REDACTION in record
    assert "%s" not in record
    assert SECRET not in record
