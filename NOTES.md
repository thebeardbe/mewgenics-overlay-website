# Bugbox / Landing — pending follow-ups

Logged while testing the admin UI. Nothing here is implemented yet; we return
to these items in a later session. Each entry captures the ask and the notes
we already know about the problem.

## 1. Search box + related-ticket jump break on `#` ids

The ticket ids are bare (e.g. `demo02`), but the related-ticket chips set the
search box to `#demo02`. The search filter then finds nothing because the
searchable text never contains the `#` prefix, and typing a `#` in the box
generally doesn't behave like a user expects.

What to fix later:

- Normalise the query: trim, and treat a leading `#` as an id prefix (strip
  or match `#id` against the bare id) so `#demo02` resolves.
- The data-goto jump should probably route through a real "focus ticket"
  action (highlight + scroll) instead of abusing the search box.
- Add tests for `#`-prefixed search and for chip navigation.

## 2. Sidebar menu structure and sizing

Current sidebar is flat and the entries feel small.

Wanted:

- `Tickets` and `People` should be primary (larger) nav items.
- The report state filters (All / Open / Triaged / Fixed / Won't fix /
  Duplicates) should become sub-items under a `Tickets` parent (e.g.
  collapsible group or nested indentation), not separate top-level items.
- Keep live counts, and the People item only for the owner.

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

## Not currently planned

- Automated notification delivery (email/push) is out of scope until the
  follow-up/thread model is settled.
