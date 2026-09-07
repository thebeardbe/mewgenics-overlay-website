"""Seed Bugbox with ~20 demo tickets in every state (for UI review).

Refuses to touch a database that already contains reports unless --force is
given. Run it locally or inside the container:

    BGBOX_DATA=/path python seed_demo.py            # empty DB only
    BGBOX_DATA=/path python seed_demo.py --force    # wipe + reseed

Inside the deployed container:

    docker compose exec bugbox python seed_demo.py --force
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from store import DB_PATH, DATA_DIR, init  # noqa: E402

# (title, category, status, severity, name, age_days, body, log, app_version,
#  game_patch, dupe_of, summary, likely_cause)
_DEMO = [
    ("Risk column shows 0% for a mother+kitten pair", "breeding", "open",
     "high", "Catmom87", 0,
     "Focused Mom, she has kittens in the house. Risk shows 0.0% but the pair is family.",
     "pair: L'Via x Meeko\nrisk_pct=0.00\ncoi=0.00\nfamily=sibling", "0.1.46", "1.1",
     [], "Risk is 0 for a direct-family pair that should never breed.",
     "Family detection did not map the kitten's parent pointer; check parse_save pedigree."),
    ("Save not found on Linux after patch", "save", "open", "medium",
     "ArchCat", 1,
     "After the latest game patch the overlay says no save found. It worked yesterday.",
     "discovery: no save under ~/.steam or XDG", "0.1.46", "1.1",
     [], "Auto-detection misses the save after the patch.",
     "The patch may have changed the save path or profile folder name."),
    ("Crashes when switching to the Donations tab", "crash", "open",
     "critical", "Tinkerbell", 1,
     "Overlay closes instantly when I click the Donations tab with a big roster.",
     "FATAL: donation_report O(n^2) froze UI, process killed", "0.1.44", "1.1",
     [], "Hard crash opening Donations on a large save.",
     "Donation keeper scan runs on the UI thread; large rosters freeze it."),
    ("Expected 7s disagrees with the in-game roll", "breeding", "triaged",
     "medium", "LuckyPaws", 2,
     "It says 2.4 expected 7s but I rolled three 7s twice in a row. Small sample, I know.",
     "pair STR 7x7 DEX 7x6 ...", "0.1.46", "1.1",
     [], "Reported expectation vs observed rolls.",
     "Statistical variance; needs a bigger sample before calling it a bug."),
    ("Donation tab shows Tink with 0 qualifying kittens", "donations",
     "triaged", "low", "Jasper", 2,
     "I have newborn kittens but Tink shows none. Age 1 required? They are age 1.",
     "tink candidates: []\nroster: 21 cats", "0.1.46", "1.1",
     [], "Tink always empty despite 1-day kittens.",
     "Suspect age parsing after day rollover; verify creation_day mapping."),
    ("Wrong parents shown in the family tree", "parser", "triaged",
     "high", "BreederBob", 3,
     "Family tree lists the wrong father for one kitten after a cat was sold.",
     "kitten 902 parents: 301, 404", "0.1.45", "1.1",
     [], "Pedigree shows wrong parent for a kitten.",
     "Parent UID resolution may collide after a cat is removed from the save."),
    ("Theme switch loses the pinned list", "ui", "triaged", "medium",
     "NoirFan", 3,
     "After toggling the theme my pinned cats still show pinned, but the donations tab changes order.",
     "pin store: 4 uids", "0.1.46", "1.1",
     [], "Theme switch reorders donation candidates.",
     "Donation refresh re-sorts; pinned sorting tie broken inconsistently."),
    ("Compatibility shows 0.000 for two bi cats of the same sex", "breeding",
     "fixed", "medium", "Arcade", 4,
     "Two bi females show compat 0. They should be able to attempt (gay-stray chance).",
     "compat 0.000; both sexuality_raw 0.5", "0.1.46", "1.1",
     [], "Same-sex bi pair shows no compatibility.",
     "Fixed in v0.1.46: same-sex pairs now show the gay-stray mating line."),
    ("Risk cap text says >=12% red but column turns red at 12.1", "ui",
     "fixed", "low", "Pixel", 4,
     "Header says red above 12%, 12.0 is amber, 12.1 red. Off-by-one in the tooltip copy.",
     "risk_color thresholds 5/12", "0.1.45", "1.1",
     [], "Boundary mismatch between tooltip text and colour logic.",
     "Copy updated to match the actual thresholds."),
    ("Nightly chance capped at 95% is confusing when comfort is huge", "ui",
     "fixed", "low", "Miso", 5,
     "The >=95% label is fine but the tooltip still explains it as a percentage.",
     "", "0.1.44", "1.1",
     [], "Tooltip wording for the saturation cap.",
     "Reworded the tooltip; behaviour is intended."),
    ("Outside house label for unroomed cats confuses new players", "ui",
     "wontfix", "low", "Gato", 5,
     "Why do cats in the house show 'Outside house'? Sounds like a bug.",
     "", "0.1.43", "1.1",
     [], "Label confusion.",
     "Intentional: unroomed house cats stand outside rooms; tooltip explains."),
    ("Can you add a light theme?", "ui", "wontfix", "low", "Sunny", 6,
     "The overlay is very dark. Add a light theme please.",
     "", "0.1.30", "1.0",
     [], "Feature request.",
     "Already shipped: the theme toggle offers Noir Bright (light)."),
    ("Ban risk question", "other", "wontfix", "low", "Worried", 6,
     "Will this tool get me banned? I saw it watches the save file.",
     "", "0.1.30", "1.0",
     [], "Cheating/ban question.",
     "Not a bug; FAQ covers it. Reads only, like a text editor."),
    ("Duplicate: Save not found on Linux", "save", "duplicate", "medium",
     "ArchCat", 7,
     "No save found again after restarting Steam.",
     "", "0.1.46", "1.1",
     ["abc123def456"], "Duplicate of the earlier Linux discovery report.",
     "Same as existing report; keep the original open."),
    ("Duplicate: Tink shows 0 kittens", "donations", "duplicate", "low",
     "Jasper", 8,
     "Still zero kittens for Tink even after a day rollover.",
     "", "0.1.46", "1.1",
     ["456def789abc"], "Same root cause as the Tink report.",
     "Duplicated; tracking in the original ticket."),
    ("Random crash on startup with no save present", "crash", "duplicate",
     "high", "Boot", 8,
     "Crashes immediately when launched without a save file.",
     "traceback in overlay.log", "0.1.42", "1.1",
     ["789abc123def"], "Already reported for v0.1.42.",
     "Fixed in a later release; closing as duplicate."),
    ("Expected avg uses total stats not base", "parser", "open",
     "medium", "StatsGuy", 9,
     "The partner table shows numbers that match total stats sometimes.",
     "", "0.1.46", "1.1",
     [], "Possible use of total instead of base stats.",
     "Verify Cat.base_stats path used in pair projection."),
    ("Night chance above 100% for very high compat", "breeding", "open",
     "high", "Peak", 10,
     "With a huge Comfort room the per-night line exceeds 100% in the model.",
     "roll=1.03; night=1.06", "0.1.46", "1.1",
     [], "Chance can exceed 100 before the display cap.",
     "Clamp per-roll at 1.0 before squaring; display already caps at 95."),
    ("Gay-stray note missing in blocked rows", "breeding", "open",
     "low", "Fae", 11,
     "Blocked same-sex rows say 'cannot breed' but never mention gay strays.",
     "", "0.1.46", "1.1",
     [], "Blocked-row reason omits the 1.1 gay-stray outcome.",
     "Add the gay-stray note to same-sex blocked reasons."),
    ("Overlay steals focus from the game on Windows", "ui", "open",
     "medium", "WinCat", 12,
     "After clicking a partner row the game loses focus and stays click-through.",
     "focus events around row select", "0.1.46", "1.1",
     [], "Focus handling after row selection on Windows.",
     "Look at changeEvent/deactivate path; maybe re-engage only via hotkey."),
]

STATUS_ORDER = ["open", "triaged", "fixed", "wontfix", "duplicate"]
SEVERITIES = ["low", "medium", "high", "critical"]
CATEGORIES = ["parser", "save", "crash", "ui", "breeding", "donations", "other"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--force", action="store_true",
                    help="wipe existing reports before seeding")
    args = ap.parse_args()

    init()
    conn = sqlite3.connect(DB_PATH)
    existing = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    if existing and not args.force:
        print(f"bugbox.db already has {existing} report(s); refusing to seed. "
              "Use --force to wipe and reseed.")
        conn.close()
        return 1

    if args.force:
        conn.execute("DELETE FROM reports")
        print("wiped existing reports")

    now = time.time()
    for i, (title, cat, status, sev, name, age_days, body, log,
            app_version, game_patch, dupes, summary, cause) in enumerate(_DEMO):
        created = now - age_days * 86400 - (len(_DEMO) - i) * 7
        analysis = {
            "severity": sev,
            "category": cat,
            "summary": summary,
            "dupe_ids": dupes,
            "likely_cause": cause,
            "needs_reply": status == "open",
            "reply_draft": "",
            "model": "demo-seed",
        }
        conn.execute(
            """
            INSERT INTO reports (id, created, status, category, name, contact,
                                 title, body, log, app_version, game_patch,
                                 analysis)
            VALUES (?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?)
            """,
            (f"demo{i + 1:02d}", created, status, cat, name, title, body,
             log, app_version, game_patch,
             json.dumps(analysis, ensure_ascii=False)),
        )
    conn.commit()
    counts = {s: conn.execute(
        "SELECT COUNT(*) FROM reports WHERE status = ?", (s,)).fetchone()[0]
        for s in STATUS_ORDER}
    conn.close()
    print(f"seeded {len(_DEMO)} demo tickets -> {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
