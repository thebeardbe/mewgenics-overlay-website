"""Configuration contract between .env.example, compose.yaml and the Dockerfile.

The bug this check exists for: ``compose.yaml`` hardcoded
``BGBOX_ADMIN_USER: admin`` while ``.env.example`` documented it as
configurable, and nothing compared the two, so editing ``.env`` had no effect.

Four rules are enforced, each against the repository's own files:

1. every variable documented in ``.env.example`` is forwarded by
   ``compose.yaml`` (an undocumented-but-forwarded variable is fine; the
   reverse is drift);
2. a documented variable in ``compose.yaml`` is an interpolation
   (``${VAR...}``) of itself, never a literal;
3. every variable a root Python module reads from the environment is either
   forwarded by ``compose.yaml`` or set by a Dockerfile ``ENV``;
4. every root ``.py`` module the app imports appears on a Dockerfile ``COPY``
   line (a new module that is imported but not copied builds an image that
   cannot start).

No YAML dependency is used (the project pins only fastapi, uvicorn,
python-multipart and jinja2); a small explicit reader locates the single
``environment:`` block.

Each rule has a companion test proving it rejects the state that preceded this
change (``git show 9376d1d:compose.yaml`` for rules 1 and 2, the old inline
environment read in ``app.py`` for rule 3, and the old ``COPY`` line for rule
4).

Run (see tests/test_bugbox.py for the environment):

    BGBOX_ADMIN_USER=admin BGBOX_ADMIN_PASS=test-pass \
        BGBOX_COOKIE_KEY=test-key python -m pytest tests/ -q
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


# ── explicit readers (no YAML) ─────────────────────────────────────────────
_ENV_LINE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=")
_COMPOSE_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):(?:\s*(.*))?$")
_INTERPOLATION = re.compile(
    r"^\$\{([A-Za-z_][A-Za-z0-9_]*)(?::[-?][^}]*)?\}$")
_ENV_READ = re.compile(
    r"os\.environ(?:\.get)?[\(\[]\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']")
_IMPORT = re.compile(
    r"^\s*(?:from\s+([A-Za-z_][A-Za-z0-9_]*)\s+import"
    r"|import\s+([A-Za-z_][A-Za-z0-9_]*))", re.MULTILINE)


def documented_variables(env_example_text):
    """The variable names an .env-style file documents, in file order."""
    return [match.group(1)
            for line in env_example_text.splitlines()
            if (match := _ENV_LINE.match(line))]


def _strip_trailing_comment(value):
    """Drop an unquoted ``# ...`` tail (the compose file annotates values)."""
    quote = ""
    for index, char in enumerate(value):
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "#":
            return value[:index].strip()
    return value.strip()


def compose_environment(compose_text):
    """{VAR: raw value} for the single ``environment:`` block in compose.yaml."""
    lines = compose_text.splitlines()
    found = {}
    for index, line in enumerate(lines):
        if line.strip() != "environment:":
            continue
        base_indent = len(line) - len(line.lstrip())
        for follow in lines[index + 1:]:
            if not follow.strip() or follow.strip().startswith("#"):
                continue
            indent = len(follow) - len(follow.lstrip())
            if indent <= base_indent:
                break
            match = _COMPOSE_KEY.match(follow.strip())
            if match:
                found[match.group(1)] = _strip_trailing_comment(
                    match.group(2) or "")
    return found


def interpolation_name(value):
    """The variable a compose value interpolates, or None for a literal."""
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    match = _INTERPOLATION.match(text)
    return match.group(1) if match else None


def dockerfile_env(dockerfile_text):
    """Variable names set by a Dockerfile ``ENV`` instruction."""
    names = set()
    for line in dockerfile_text.splitlines():
        stripped = line.strip()
        if not stripped.upper().startswith("ENV "):
            continue
        for token in stripped[4:].split():
            if "=" in token:
                names.add(token.split("=", 1)[0])
    return names


def dockerfile_copied(dockerfile_text):
    """The source paths named by Dockerfile ``COPY`` instructions."""
    copied = set()
    for line in dockerfile_text.splitlines():
        stripped = line.strip()
        if not stripped.upper().startswith("COPY "):
            continue
        parts = [p for p in stripped.split()[1:] if not p.startswith("--")]
        if len(parts) >= 2:
            copied.update(parts[:-1])     # the last argument is the target
    return copied


def environment_reads(sources):
    """{variable: file} for every os.environ read in root module *sources*."""
    reads = {}
    for name, text in sources.items():
        for match in _ENV_READ.finditer(text):
            reads.setdefault(match.group(1), name)
    return reads


def local_imports(sources):
    """Root ``*.py`` files imported by any root module in *sources*."""
    modules = {name[:-3] for name in sources if name.endswith(".py")}
    imported = set()
    for text in sources.values():
        for match in _IMPORT.finditer(text):
            module = match.group(1) or match.group(2)
            if module in modules:
                imported.add(module + ".py")
    return imported


def find_violations(*, sources, compose_text, env_example_text,
                    dockerfile_text):
    """Every configuration-contract violation, as readable strings."""
    problems = []
    compose_env = compose_environment(compose_text)
    docker_env = dockerfile_env(dockerfile_text)
    copied = dockerfile_copied(dockerfile_text)

    for name in documented_variables(env_example_text):
        if name not in compose_env:
            problems.append(
                f"{name}: documented in .env.example but not forwarded by "
                "compose.yaml")
            continue
        reference = interpolation_name(compose_env[name])
        if reference is None:
            problems.append(
                f"{name}: compose.yaml sets it to the literal "
                f"{compose_env[name]!r} instead of an interpolation")
        elif reference != name:
            problems.append(
                f"{name}: compose.yaml interpolates {reference} instead")

    for name in sorted(environment_reads(sources)):
        if name not in compose_env and name not in docker_env:
            problems.append(
                f"{name}: read from the environment but neither forwarded by "
                "compose.yaml nor set by a Dockerfile ENV")

    for module in sorted(local_imports(sources)):
        if module not in copied:
            problems.append(
                f"{module}: imported by the app but missing from the "
                "Dockerfile COPY line")

    return problems


def _root_sources():
    return {path.name: path.read_text(encoding="utf-8")
            for path in sorted(ROOT.glob("*.py"))}


def _current_files():
    return {
        "sources": _root_sources(),
        "compose_text": (ROOT / "compose.yaml").read_text(encoding="utf-8"),
        "env_example_text": (ROOT / ".env.example").read_text(encoding="utf-8"),
        "dockerfile_text": (ROOT / "Dockerfile").read_text(encoding="utf-8"),
    }


# The previous compose.yaml, exactly as committed (git show
# 9376d1d:compose.yaml). It hardcoded BGBOX_ADMIN_USER and did not forward
# BGBOX_OVERLAY_VERSION.
_PREVIOUS_COMPOSE = """services:
  bugbox:
    build: .
    container_name: bugbox
    restart: unless-stopped
    networks:
      - proxy-network
    environment:
      # Admin login
      BGBOX_ADMIN_USER: admin
      BGBOX_ADMIN_PASS: "${BGBOX_ADMIN_PASS:?set in .env}"
      BGBOX_COOKIE_KEY: "${BGBOX_COOKIE_KEY:?set in .env}"
      BGBOX_COOKIE_SECURE: "${BGBOX_COOKIE_SECURE:-0}"
      # Deployment options documented in .env.example.
      BGBOX_HTTPS: "${BGBOX_HTTPS:-}"            # HSTS when the proxy terminates TLS
      BGBOX_ADMIN_NAME: "${BGBOX_ADMIN_NAME:-}"  # owner display name (also on /admin/people)
      BGBOX_ORIGINS: "${BGBOX_ORIGINS:-}"        # allowed POST origins for the CSRF origin gate
      BGBOX_LOG_FILE: "${BGBOX_LOG_FILE:-}"      # rotating log file path (secrets scrubbed)
      BGBOX_ANALYTICS_SCRIPT: "${BGBOX_ANALYTICS_SCRIPT:-}"  # Umami script URL (off when empty)
      BGBOX_ANALYTICS_ID: "${BGBOX_ANALYTICS_ID:-}"          # Umami website id (off when empty)
      # Optional GitHub developer sign-in (see README / .env.example).
      GITHUB_CLIENT_ID: "${GITHUB_CLIENT_ID:-}"
      GITHUB_CLIENT_SECRET: "${GITHUB_CLIENT_SECRET:-}"
      GITHUB_REDIRECT_URI: "${GITHUB_REDIRECT_URI:-}"
      LLM_BASE_URL: "${LLM_BASE_URL:-https://api.openai.com/v1}"
      LLM_API_KEY: "${LLM_API_KEY:-}"
      LLM_MODEL: "${LLM_MODEL:-gpt-4o-mini}"
    volumes:
      - bugbox-data:/data
    ports:
      - "127.0.0.1:8200:8000"

networks:
  proxy-network:
    external: true

volumes:
  bugbox-data:
"""

# The previous Dockerfile COPY line (git show 9376d1d:Dockerfile): it predates
# version_cache.py.
_PREVIOUS_COPY_LINE = ("COPY app.py admin_api.py api_utils.py auth.py "
                       "error_pages.py llm.py store.py seed_demo.py ./")

# The previous environment read (git show 9376d1d:app.py): the overlay version
# default came straight from the environment inside app.py, before
# version_cache.py owned it.
_PREVIOUS_VERSION_READ = (
    '_DEFAULT_VERSION = os.environ.get("BGBOX_OVERLAY_VERSION", "0.1.46")\n')


# ── the repository passes all four rules ───────────────────────────────────
def test_repository_satisfies_the_configuration_contract():
    assert find_violations(**_current_files()) == []


def test_every_documented_variable_is_forwarded():
    files = _current_files()
    documented = set(documented_variables(files["env_example_text"]))
    forwarded = set(compose_environment(files["compose_text"]))
    assert documented <= forwarded, documented - forwarded


def test_every_environment_read_is_reachable():
    files = _current_files()
    reachable = (set(compose_environment(files["compose_text"]))
                 | dockerfile_env(files["dockerfile_text"]))
    assert set(environment_reads(files["sources"])) <= reachable


def test_every_imported_module_is_copied_into_the_image():
    files = _current_files()
    assert local_imports(files["sources"]) <= dockerfile_copied(
        files["dockerfile_text"])


# ── rule 1: documented but not forwarded ───────────────────────────────────
def test_rule_one_rejects_the_previous_compose_state():
    files = _current_files()
    problems = find_violations(sources=files["sources"],
                               compose_text=_PREVIOUS_COMPOSE,
                               env_example_text=files["env_example_text"],
                               dockerfile_text=files["dockerfile_text"])
    assert any(p.startswith("BGBOX_OVERLAY_VERSION:")
               and "not forwarded" in p for p in problems), problems


# ── rule 2: a literal instead of an interpolation ──────────────────────────
def test_rule_two_rejects_the_previous_compose_state():
    files = _current_files()
    problems = find_violations(sources=files["sources"],
                               compose_text=_PREVIOUS_COMPOSE,
                               env_example_text=files["env_example_text"],
                               dockerfile_text=files["dockerfile_text"])
    # This is the exact bug: BGBOX_ADMIN_USER was hardcoded to admin.
    assert any(p.startswith("BGBOX_ADMIN_USER:")
               and "literal" in p for p in problems), problems


def test_rule_two_rejects_an_interpolation_of_a_different_variable():
    files = _current_files()
    compose = files["compose_text"].replace(
        'BGBOX_ADMIN_USER: "${BGBOX_ADMIN_USER:?set in .env}"',
        'BGBOX_ADMIN_USER: "${SOMETHING_ELSE:-admin}"')
    problems = find_violations(sources=files["sources"], compose_text=compose,
                               env_example_text=files["env_example_text"],
                               dockerfile_text=files["dockerfile_text"])
    assert any(p.startswith("BGBOX_ADMIN_USER:")
               and "interpolates SOMETHING_ELSE" in p for p in problems), \
        problems


# ── rule 3: an environment read nothing forwards ───────────────────────────
def test_rule_three_rejects_an_unforwarded_environment_read():
    files = _current_files()
    sources = dict(files["sources"])
    # Reproduce the read that lived inside app.py before version_cache.py.
    sources["legacy_version_read.py"] = _PREVIOUS_VERSION_READ
    problems = find_violations(sources=sources,
                               compose_text=_PREVIOUS_COMPOSE,
                               env_example_text=files["env_example_text"],
                               dockerfile_text=files["dockerfile_text"])
    assert any(p.startswith("BGBOX_OVERLAY_VERSION:")
               and "read from the environment" in p for p in problems), problems


# ── rule 4: an imported module missing from COPY ───────────────────────────
def test_rule_four_rejects_the_previous_dockerfile():
    files = _current_files()
    current = files["dockerfile_text"]
    previous = current.replace(
        "COPY app.py admin_api.py api_utils.py auth.py error_pages.py llm.py "
        "store.py seed_demo.py version_cache.py ./", _PREVIOUS_COPY_LINE)
    assert "version_cache.py" not in previous
    problems = find_violations(sources=files["sources"],
                               compose_text=files["compose_text"],
                               env_example_text=files["env_example_text"],
                               dockerfile_text=previous)
    assert any(p.startswith("version_cache.py:")
               and "COPY" in p for p in problems), problems


def test_rule_four_rejects_a_module_added_but_not_copied():
    files = _current_files()
    sources = dict(files["sources"])
    sources["brand_new.py"] = "import store\n"
    sources["app.py"] = "import brand_new\n" + sources["app.py"]
    problems = find_violations(sources=sources,
                               compose_text=files["compose_text"],
                               env_example_text=files["env_example_text"],
                               dockerfile_text=files["dockerfile_text"])
    assert any(p.startswith("brand_new.py:") and "COPY" in p
               for p in problems), problems


# ── the readers themselves ─────────────────────────────────────────────────
def test_compose_reader_stops_at_the_end_of_the_environment_block():
    env = compose_environment("""services:
  bugbox:
    environment:
      BGBOX_A: "${BGBOX_A:-}"
    volumes:
      - data:/data
networks:
  BGBOX_NOT_ENV: nope
""")
    assert env == {"BGBOX_A": '"${BGBOX_A:-}"'}


def test_compose_reader_strips_trailing_comments_and_quotes():
    env = compose_environment("""services:
  bugbox:
    environment:
      BGBOX_A: "${BGBOX_A:-}"   # a note
      BGBOX_B: "${BGBOX_B:?set in .env}"
      BGBOX_C: literal # not interpolated
""")
    assert env["BGBOX_A"] == '"${BGBOX_A:-}"'
    assert env["BGBOX_B"] == '"${BGBOX_B:?set in .env}"'
    assert env["BGBOX_C"] == "literal"


def test_interpolation_name_recognises_defaults_and_required_forms():
    assert interpolation_name('"${BGBOX_A:-0}"') == "BGBOX_A"
    assert interpolation_name("'${BGBOX_A:?set in .env}'") == "BGBOX_A"
    assert interpolation_name('"${LLM_BASE_URL:-https://api.openai.com/v1}"') \
        == "LLM_BASE_URL"
    assert interpolation_name("admin") is None
    assert interpolation_name('"${}"') is None


def test_documented_variables_ignores_comments_and_blank_lines():
    text = ("# BGBOX_NOPE=\n"
            "BGBOX_A=\n"
            "\n"
            "  # indented comment\n"
            "export BGBOX_B=1\n")
    assert documented_variables(text) == ["BGBOX_A", "BGBOX_B"]


def test_dockerfile_readers_find_env_and_copy_sources():
    text = ("FROM python:3.12-slim\n"
            "COPY requirements.txt .\n"
            "COPY app.py store.py ./\n"
            "COPY templates ./templates\n"
            "ENV BGBOX_DATA=/data\n")
    assert dockerfile_env(text) == {"BGBOX_DATA"}
    assert dockerfile_copied(text) == {"requirements.txt", "app.py", "store.py",
                                       "templates"}


def test_environment_reads_finds_both_forms_and_ignores_other_names():
    reads = environment_reads({
        "a.py": 'X = os.environ.get("BGBOX_ONE", "")\n'
                'Y = os.environ["BGBOX_TWO"]\n'
                'Z = os.environ.get("PATH")\n',
        "b.py": 'A = os.environ.get("BGBOX_ONE", "again")\n',
    })
    assert set(reads) == {"BGBOX_ONE", "BGBOX_TWO", "PATH"}
    assert reads["BGBOX_ONE"] == "a.py"       # first sighting wins


def test_local_imports_finds_root_modules_and_ignores_third_party():
    sources = {
        "app.py": "import os\nimport store\nfrom api_utils import x\n"
                  "from fastapi import FastAPI\n",
        "store.py": "import sqlite3\n",
        "auth.py": "import store\n",
        "api_utils.py": "from fastapi.responses import JSONResponse\n",
    }
    assert local_imports(sources) == {"store.py", "api_utils.py"}
