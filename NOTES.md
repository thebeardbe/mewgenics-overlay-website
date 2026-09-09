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

## Not currently planned

- Automated notification delivery (email/push) is out of scope until the
  follow-up/thread model is settled.
