"""LLM triage for bug reports.

Provider-agnostic: talks to any OpenAI-compatible /chat/completions endpoint.
Point it at OpenAI, Groq, Mistral, or a local Ollama (http://ollama:11434/v1)
via environment variables. If no key is configured, analysis is skipped and
reports stay readable in the admin UI.

The prompt asks the model to classify severity, category, dupe-candidates
(against recent report titles) and to sketch a likely cause from the log.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request

BASE_URL = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
API_KEY = os.environ.get("LLM_API_KEY", "")
MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")

_CATEGORIES = ["parser", "save", "crash", "ui", "breeding", "donations", "other"]
_SEVERITIES = ["low", "medium", "high", "critical"]
# Model output is attacker-influenceable via the report body (prompt
# injection), so everything it returns is treated as untrusted data:
# bounded lengths, strict enum checks, dupe_ids reduced to safe id strings.
_DUPE_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,16}$")


def available() -> bool:
    return bool(API_KEY)


def analyze(report: dict, recent: list[dict]) -> dict:
    if not available():
        return {"note": "LLM not configured — no analysis."}
    recent_titles = "\n".join(
        f"- #{r['id']} [{r['status']}] {r['title']}"
        for r in recent[:15]
    ) or "(none)"
    system = (
        "You triage bug reports for 'Mewgenics Breeding Overlay', a read-only "
        "companion tool that parses Mewgenics save files to rank breeding "
        "partners. Reply with ONE JSON object and nothing else: "
        '{"severity":"low|medium|high|critical",'
        '"category":"parser|save|crash|ui|breeding|donations|other",'
        '"summary":"one sentence",'
        '"dupe_ids":["<existing ids this is likely a duplicate of>"],'
        '"likely_cause":"short hypothesis for a developer",'
        '"needs_reply":true|false,"reply_draft":"<short user-facing reply or empty>"}'
    )
    user = (
        f"APP VERSION: {report.get('app_version') or '?'}\n"
        f"GAME PATCH: {report.get('game_patch') or '?'}\n"
        f"TITLE: {report.get('title')}\n"
        f"DETAILS: {report.get('body')}\n"
        f"LOG:\n{(report.get('log') or '')[:6000]}\n\n"
        f"RECENT REPORTS TO CHECK FOR DUPLICATES:\n{recent_titles}"
    )
    payload = {
        "model": MODEL,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"
    try:
        req = urllib.request.Request(
            f"{BASE_URL}/chat/completions",
            data=json.dumps(payload).encode(),
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read())
        content = data["choices"][0]["message"]["content"]
        parsed = _extract_json(content)
        parsed = _clean(parsed)
        parsed["model"] = MODEL
        return parsed
    except Exception as exc:  # never let analysis break the report
        return {"error": f"analysis failed: {exc}", "severity": "medium"}


def _clean(parsed: dict) -> dict:
    """Normalise a model response into safe, bounded analysis fields.

    The model is asked to reply with one JSON object, but report bodies are
    attacker-controlled: a malicious report can try to steer the output (e.g.
    HTML payloads inside dupe_ids) so the fields are coerced exactly like any
    other untrusted data before they are stored / rendered.
    """
    if not isinstance(parsed, dict):
        return {}
    out: dict = {}
    sev = str(parsed.get("severity", "medium") or "medium").lower()
    out["severity"] = sev if sev in _SEVERITIES else "medium"
    cat = str(parsed.get("category", "other") or "other").lower()
    out["category"] = cat if cat in _CATEGORIES else "other"
    for key, maxlen in (("summary", 500), ("likely_cause", 800),
                        ("reply_draft", 500)):
        val = parsed.get(key)
        out[key] = (str(val)[:maxlen] if isinstance(val, (str, int, float))
                    else "")
    out["needs_reply"] = bool(parsed.get("needs_reply"))
    ids = parsed.get("dupe_ids")
    dupes: list[str] = []
    if isinstance(ids, list):
        for i in ids:
            if isinstance(i, (str, int)) and len(dupes) < 5:
                s = str(i).strip()
                if s and _DUPE_ID_RE.match(s):
                    dupes.append(s)
    out["dupe_ids"] = dupes
    return out


def _extract_json(content: str) -> dict:
    content = content.strip()
    m = re.search(r"\{.*\}", content, re.DOTALL)
    if m:
        content = m.group(0)
    try:
        out = json.loads(content)
    except ValueError:
        return {}
    return out if isinstance(out, dict) else {}
