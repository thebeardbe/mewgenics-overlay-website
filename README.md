# Bugbox — self-hosted bug intake with LLM triage

A tiny FastAPI service for your VPS that collects bug reports from the
Mewgenics Breeding Overlay and uses an **LLM to triage them** (severity,
category, duplicate detection, likely cause). Reporters need **no account** —
they open a link, paste, and submit. You read the triaged queue in a
password-protected admin UI.

Players reach it two ways:

1. **Browser form** — the “Report a problem” button in the overlay's About
   box opens `https://<your-domain>/report`.
2. **Direct JSON POST** — the overlay can POST straight to `/api/report`
   with `{title, body, log, app_version, game_patch}`.

## Deploy on your Ubuntu + Docker + Nginx Proxy Manager

```bash
cd bugbox
cp .env.example .env        # set BGBOX_ADMIN_PASS, BGBOX_COOKIE_KEY,
                            # LLM_API_KEY (or leave empty to disable analysis)
docker compose up -d --build
```

The container listens on `127.0.0.1:8200` only — never expose it directly.

In **Nginx Proxy Manager** create a Proxy Host:

| field | value |
|---|---|
| Domain Names | `bugs.yourdomain.com` |
| Scheme / Forward Hostname / Port | `http` · `127.0.0.1` · `8200` |
| Websockets Support | on (optional) |
| SSL | request a Let's Encrypt cert (on) |

## LLM provider

Any **OpenAI-compatible** endpoint works — set via `.env`:

- OpenAI: `LLM_BASE_URL=https://api.openai.com/v1`, key + `gpt-4o-mini`
- Groq/Mistral/etc: same shape, their base URL + key
- Ollama on the VPS host: `LLM_BASE_URL=http://host.docker.internal:11434/v1`
  (model e.g. `llama3.1`), no key needed — leave `LLM_API_KEY` empty but set
  `LLM_BASE_URL`/`LLM_MODEL`.

If `LLM_API_KEY` is empty *and* no local endpoint is set, analysis is skipped
and reports still land in the admin queue.

## What the LLM adds to each report

```json
{ "severity": "high", "category": "parser",
  "summary": "Risk shows 0% for a mother+kitten pair",
  "dupe_ids": ["a1b2c3d4e5f6"], "likely_cause": "...",
  "needs_reply": true, "reply_draft": "..." }
```

- Duplicate detection compares against the 15 most recent reports.
- Admin UI lists every report with its tags, log tail, and one-click
  status moves (triaged / fixed / duplicate / wontfix / delete).

## API summary

| Route | Purpose |
|---|---|
| `GET /report` | public form |
| `POST /submit` | form handler (redirects to thanks) |
| `POST /api/report` | JSON intake (overlay) |
| `GET /admin` | admin UI (login) |
| `GET /api/tickets[?status=]` | list reports (auth) |
| `POST /api/tickets/{id}/status` | set status (auth) |
| `POST /api/tickets/{id}/delete` | delete (auth) |

Data lives in a SQLite volume (`bugbox-data`); back it up with the rest of
your server.
