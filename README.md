# Bugbox — self-hosted website + bug intake with LLM triage


A tiny FastAPI service for your VPS that collects bug reports from the
Mewgenics Breeding Overlay and triages them (severity,
category, duplicate detection, likely cause). Reporters need **no account** —
they open a link, paste, and submit. The developer reads the queue in a
password-protected admin UI with **multi-user access**: one local `owner`
account plus optional GitHub developer sign-ins that must be approved by the
owner on the People page before they gain access.

Players reach it two ways:

1. **Browser form** — the “Report a problem” button in the overlay's About
   box opens `https://<your-domain>/report`.
2. **Direct JSON POST** — the overlay can POST straight to `/api/report`
   with `{title, body, log, app_version, game_patch}`.

## Deploy on your Ubuntu + Docker + Nginx Proxy Manager

Two prerequisites must hold before the first `docker compose up`. Both are
already satisfied on a host where other sites are running behind Nginx Proxy
Manager and that proxy's network is itself named `proxy-network`, so only
such a host can skip straight to the deploy step. A proxy bridge under any
other name still needs the steps below, starting with the network name.

1. **The shared network exists.** Create it only when it is missing, so a
   genuine failure (the Docker daemon being down, a permission problem) still
   surfaces:

   ```bash
   docker network inspect proxy-network >/dev/null 2>&1 \
     || docker network create proxy-network
   ```

2. **The reverse proxy container is attached to that network.** Otherwise the
   proxy cannot resolve the container by name and the proxy host fails. Attach
   the Nginx Proxy Manager container to that network:

   ```bash
   docker network connect proxy-network <npm-container-name>
   ```

   This attach does not persist. Recreating the Nginx Proxy Manager container
   (a `--force-recreate`, or a `down` and `up` on its own stack) drops it, and
   the name `bugbox` then stops resolving for the proxy, so the proxy host
   fails with no obvious cause. Repeat the command after any such recreation,
   or declare `proxy-network` as `external` in Nginx Proxy Manager's own
   compose file so its container rejoins the network on every start.

Then deploy:

```bash
cd bugbox
cp .env.example .env        # set BGBOX_ADMIN_PASS, BGBOX_COOKIE_KEY,
                            # LLM_API_KEY (or leave empty to disable analysis)
                            # and BGBOX_COOKIE_SECURE=1 plus BGBOX_HTTPS=1
                            # (HSTS) if served over https
docker compose up -d --build
```

The container is reached two ways, neither of which needs a public port:

- **Over the shared Docker network** as `http://bugbox:8000`. This is how the
  reverse proxy should reach it.
- **On the host loopback** as `http://127.0.0.1:8200`, handy for a `curl`
  smoke test and for a proxy that runs directly on the host.

**Admin access (multi-user):** the login page always offers the local owner
account (`BGBOX_ADMIN_USER` / `BGBOX_ADMIN_PASS`). To add developers, create a
[GitHub OAuth App](https://github.com/settings/developers) whose callback URL
is `https://<your-domain>/auth/github/callback`, then set `GITHUB_CLIENT_ID` /
`GITHUB_CLIENT_SECRET` (and `GITHUB_REDIRECT_URI` if the callback is not
auto-detected). Anyone who signs in with GitHub lands as **pending** and stays
locked until you approve them on the **People** page (`/admin/people`, owner
only), where you can also pre-approve a GitHub login, revoke access (signs the
user out immediately) or remove a user entirely. The owner account itself
cannot be removed or demoted.

**Built-in hardening:** report/login endpoints are per-IP rate limited
(10/min reports, 5/min logins), request bodies are capped at 400 KB, report
fields are truncated and type-coerced before storage, admin cookies are
constant-time verified (httponly + lax; set `BGBOX_COOKIE_SECURE=1` under
https), the admin page escapes every rendered field (LLM output included),
and every response gets nosniff/DENY/no-referrer headers. Self-hosted
analytics is optional and off by default; enabling it adds the analytics
origin to the content security policy of the pages that render the tag (the
landing page, the report form and the thanks page) and of no other path,
never `/admin` or `/login`. Handled 4xx and 5xx errors get a friendly error
page in a browser (from `error_pages.py`),
while requests to `/api/` and clients that send `Accept: application/json`
keep their previous JSON or plain-text bodies. A small test suite
lives in `tests/` (`python -m pytest tests/ -q`).

In **Nginx Proxy Manager** create a Proxy Host:

| field | value |
|---|---|
| Domain Names | `bugs.yourdomain.com` |
| Scheme / Forward Hostname / Port | `http` · `bugbox` · `8000` |
| Websockets Support | on (optional) |
| SSL | request a Let's Encrypt cert (on) |

If your proxy runs directly on the host instead of in a container, forward to
`127.0.0.1` port `8200` instead.

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

## Data retention

- Sessions expire server-side after 30 days and are pruned by a
  maintenance sweep; stale rate-limit buckets are swept too.
- Reports (and their activity timelines) are kept indefinitely by
  design: this is a small self-hosted tool and the history is the
  point. Delete a report from the admin UI if you want it gone.

## API summary

| Route | Purpose |
|---|---|
| `GET /report` | public form |
| `POST /submit` | form handler (redirects to thanks) |
| `POST /api/report` | JSON intake (overlay) |
| `GET /admin` | admin UI (login) |
| `GET /admin/people` | People page (owner) |
| `GET /login/github` · `GET /auth/github/callback` | GitHub developer sign-in |
| `GET /api/users` · `POST /api/users/github` | list users / pre-approve (owner) |
| `POST /api/users/{id}/status` · `POST /api/users/{id}/delete` | approve, deny, revoke, remove (owner) |
| `GET /api/tickets[?status=]` | list reports (auth) |
| `POST /api/tickets/{id}/status` | set status (auth) |
| `POST /api/tickets/{id}/delete` | delete (auth) |

Data lives in a SQLite volume (`bugbox-data`); back it up with the rest of
your server.

**Demo data:** `python seed_demo.py` seeds ~20 realistic tickets in every status so
you can preview the admin UI. It refuses to run when reports already exist
(`--force` wipes and reseeds; inside the container:
`docker compose exec bugbox python seed_demo.py --force`).
