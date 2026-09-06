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
        parsed.setdefault("severity", "medium")
        if parsed.get("category") not in _CATEGORIES:
            parsed["category"] = "other"
        if parsed.get("severity") not in _SEVERITIES:
            parsed["severity"] = "medium"
        parsed.setdefault("dupe_ids", [])
        parsed["model"] = MODEL
        return parsed
    except Exception as exc:  # never let analysis break the report
        return {"error": f"analysis failed: {exc}", "severity": "medium"}


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
