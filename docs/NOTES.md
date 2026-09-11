# Bugbox / Landing — pending follow-ups

Status log while setting up the site. ✅ = implemented & pushed.

## ✅ 1. Search box + related-ticket jump break on `#` ids

Fixed in admin.html: the search normaliser now trims and treats a leading `#`
as an id prefix (`#demo02` → matches id `demo02`), so the related-ticket chips
and manual `#id` typing both resolve. Placeholder text updated to advertise
`#ids`. (Jump currently filters the list rather than scroll-highlighting the
card — the "focus ticket" polish can come with the public-thread work.)

## ✅ 2. Sidebar menu structure and sizing

Reworked: primary **🎫 Tickets** (larger) is a collapsible group whose
sub-items (All / Open / Triaged / Fixed / Won't fix / Duplicates) are nested
and indented; **👥 People** is a primary item shown only to the owner; live
counts kept on every sub-item; Account row stays at the bottom.

## 3. Public follow-up thread per ticket (GitHub-issues style)

Players should be able to keep engaging with their report the way GitHub
issues work:

- Each report gets a public page where the reporter can add follow-up
  comments with extra info, and where interested people can follow the bug
  and be notified when it changes state (open/triaged/fixed/...).
- Access model TBD: unguessable per-ticket token/link (no accounts for
  players), commenter name optional, no sign-up.
- **Save files must be stripped**: any save/log paste that got attached to a
  report must not appear in the public thread in full. Decide the rule
  (drop attached saves entirely; only show hand-typed comments; keep the
  original full body/log admin-only) and apply it on the public side.
- Admins reply from the admin UI; replies appear in the public thread.

## 4. AI-drafted replies for duplicate / non-issue reports

Extend the triage pipeline so the model also prepares ready-to-send replies
for the common "no action needed" buckets, so the owner only reviews and
sends:

- Duplicates: acknowledge, state which main ticket it was folded into (link
  to the related ticket), thank for the report.
- Non-issues / wontfix: short, kind explanation (already have
  `reply_draft` + `needs_reply` in analysis; make drafts more specific per
  category and prefill status transitions).
- Needs_reply replies flow into the public follow-up thread (item 3) for a
  quick human review + send.

## ✅ 5. Admin couldn't edit the tags on a ticket

Triage assigns severity + category tags, but there was no way to correct
them. Added:

- `POST /api/tickets/{rid}/tags` (auth; validates against the allowed
  severity/category lists; merges into the analysis JSON and keeps the
  `category` column in sync) — `store.set_tags()`.
- Per-ticket **Tags:** bar in the admin card with Severity + Category
  dropdowns and a 💾 Save button (live "saved ✓" feedback), wired through
  the existing delegation handler.

## ✅ 6. Append-only activity timeline (prep for public threads)

Every action on a ticket is now recorded on an **append-only activity log**,
so a ticket reads as an ordered audit trail (and later, a public thread):

- New `activity` JSON column (auto-migrated; legacy `comments` entries are
  folded in on upgrade). Reports start with a `created` event.
- All mutations log events with actor/role/seq/ts: **status** changes,
  **tags** edits (old → new), **links** (recorded on *both* tickets, in the
  timeline), **comments**, and **comment_removed**.
- Nothing is erased: "deleting" a comment flags the original entry
  (`deleted`, `deleted_by`, `deleted_ts`) and appends a `comment_removed`
  event. Seq numbers are strictly increasing.
- Admin UI shows a per-ticket **🧾 Activity** section (icon per event kind,
  actor · role · time, text/body) with a comment textarea.

This replaces the earlier separate "comments" design (#5/#6 loose ends) and
is the schema the public follow-up threads (item 3) will expose — the
privacy-rule decision there is still open (keep full body/log admin-only,
share only typed comments + event texts publicly).

## ✅ 8. Timeline actors resolve from user ids (no baked-in names)

Events store the acting user's **id** (plus their login as a stable
fallback), never the display name. Names are resolved at read time against
`users.display_name`, so a rename in People is reflected retroactively on
every event that user made — the log stays append-only and immutable.

Machine actions are typed, not named: `actor_type` is `user`, `auto`
(auto-triage 🤖 badge), `system` or `player`; the UI can therefore show a
clear "auto"/system treatment instead of a person's name.

## ✅ 9. SQL hardening: no SELECT *, hot/cold split

- **Every query now lists explicit columns** (`_COLS_RPT_LITE/_FULL`, `_USR`,
  `_USR_AUTH`, `_USR_JOIN`). No wildcard selects anywhere in store.py —
  guarded by a test. `password_hash` is only ever selected by the login
  verify path; user APIs/list store reads never load it.
- **Hot/cold split**: `/api/tickets` (list) no longer fetches `body`/`log` —
  those heavy columns come only from the new `GET /api/tickets/{id}` detail
  endpoint, and the admin UI loads them lazily when a card is expanded.
  `store.exists()` gives cheap existence probes so 404 checks never drag a
  full row.

## ✅ 10. Hardening round 2 (headers, CSRF, containers, logging)

- **CSP split**: auth'd pages (admin/people/login) now load CSS/JS from
  /static and get a strict CSP with no `unsafe-inline`; public pages keep a
  baseline CSP. All responses get X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy (camera/mic/geo/payment/usb off),
  X-Robots-Tag noindex, and HSTS when BGBOX_HTTPS=1.
- **CSRF origin gate**: state-changing POST/PUT/PATCH/DELETE requests with a
  cross-origin `Origin` are rejected 403 (same-origin by default;
  BGBOX_ORIGINS allow-list optional).
- **Startup warnings** for short/placeholder BGBOX_ADMIN_PASS (>=12 chars).
  A missing or empty BGBOX_ADMIN_USER / BGBOX_ADMIN_PASS is now fatal: the
  container logs the error and exits with code 2 instead of starting with a
  disabled login. Failed logins warn with the caller address and are answered
  with the attempts left, or the retry countdown once the 5/min per-IP login
  limit is reached.
- **Docker runs as an unprivileged user** (uid 10001), not root.
- **Log hardening**: optional rotating log (BGBOX_LOG_FILE) with secrets
  scrubbed from records.
- Static assets: templates no longer inline CSS/JS on auth pages
  (strict-CSP requirement); tests cover headers, CSP split, CSRF gate,
  static serving, and no-inline invariants.

## Not currently planned

- Automated notification delivery (email/push) is out of scope until the
  follow-up/thread model is settled.

## Open follow-ups (not started)

Nothing below is done. These are decisions and fixes still to make, recorded
so they are not lost.

1. **`_client_ip()` trusts the `X-Forwarded-For` header.** The helper in
   app.py returns the first comma-separated value of that header whenever it
   is present, with no check that the request actually came from a proxy that
   sets it. Any caller can therefore send a made-up address and get a fresh
   key for the report and login rate-limit buckets, or fill buckets for
   someone else's address. The login feedback countdown is only as
   trustworthy as this: the "attempts left" and retry seconds shown on
   /login come from a bucket keyed by that same spoofable address, so a
   caller who rotates it never sees a countdown, and one who picks someone
   else's address can burn their budget. Decide the trust model: read the
   header only behind a configured trusted proxy, fall back to
   `request.client.host` otherwise, and settle which end of a forwarded chain
   is trusted.

2. **`BGBOX_ORIGINS` accepted format is undocumented and unvalidated.** The
   value is split on commas and whitespace, lowercased, and each entry is
   compared to `urlsplit(Origin).netloc`, so an entry has to be a bare
   `host[:port]` with no scheme and no path. A full origin such as
   `https://bugs.example.com` parses fine but can never match an Origin, and
   the gate then rejects the request with no warning. Decide the accepted
   format (bare netloc, or full origins that get normalised), document it in
   `.env.example` and the README, and validate it at startup with a warning
   for entries that cannot match.

3. **Console output is not scrubbed.** `_ScrubFormatter` is attached only to
   the optional rotating file handler, so secrets still reach stdout and
   stderr (the container log) through tracebacks and log arguments. The
   comment in app.py and the note in `.env.example` both say so. Decide
   whether to scrub the console handler too, or accept the console as a
   trusted sink and keep the warning prominent in the deploy docs.

4. **No error pages for 400 and 422.** `error_pages.QUOTES` already carries a
   400 row, but no browser-facing route renders it: every 400 in the app is
   on a JSON or API path. A 422 from request validation has no row and no
   handler, so a browser gets FastAPI's default JSON body. Decide the copy
   for 422, route both codes through `_error_response`, and keep the JSON
   shapes unchanged.

5. **The 500 page copy promises that nothing was lost.** The quote says
   "Nothing you sent was lost", while the comment above the table says the
   500 explanation must not promise that data was saved. A crash can happen
   before the report is stored, so the line is not always true. Rewrite it
   so it makes no guarantee, or show it only where saving is known to have
   happened.

6. **`app.py` is over the size budget.** It is 946 lines, past the 600-line
   warning and close to the 1000-line hard limit in the global guidelines.
   The overlay-version cache, its GitHub fetch and its persistence were the
   most recent extraction (now `version_cache.py`), and the startup lifespan
   hook that primes that cache was added in app.py; moving it out is part of
   this item when the cache extraction finishes. The next extraction should
   follow the same shape: pick one concern (the hardening middleware and
   security headers, the error-page wiring, or the report routes) and move
   it out before adding more to the file.

7. **Stray `_t2.py` at the repository root.** A 20-line one-off patch script
   is tracked in git next to the application modules, left over from an
   earlier editing session, and nothing imports it. Confirm it is obsolete
   and remove it, or move it to a scratch location that is not tracked.

8. **Live host settings are still open.** On the running host `BGBOX_HTTPS`
   is `0`, so HSTS is off. HTTP/2 is disabled on the Nginx Proxy Manager
   proxy host, and Force SSL is enabled but does not redirect HTTP to HTTPS.
   Decide and apply: set `BGBOX_HTTPS=1` in the app environment, enable
   HTTP/2 on the proxy host, and fix the redirect, then verify each from
   outside the host.
