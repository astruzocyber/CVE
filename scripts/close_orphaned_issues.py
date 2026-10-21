#!/usr/bin/env python3
"""
scripts/close_orphaned_issues.py

Closes open `vulnerability-alert` issues that no longer correspond to anything
on the dashboard, plus exact duplicates.

Why: the dashboard keeps every alert it ever accepted (there is no age-based
retention), so an alert disappears from docs/data/alerts.json only when the
pipeline proves it was a false match (prune_loose_phrase_matches /
revalidate_affected_pairs: e.g. a "php/php" pair whose NVD CPEs name a
WordPress plugin) or when a human suppresses it. Suppressions already close
their issue (close_suppressed_issues.py); false-match removals did not, so 55
issues (34 php/php, 14 nginx, 5 openssl, ...) stayed open with nothing behind
them (audit 2026-10-21). One CVE also had two open issues (#2181 KEV, #2377 NVD)
from before the KEV/NVD twin dedupe.

Safety rails (a truncated or broken alerts.json must never mass-close issues):
  - does nothing if alerts.json is missing, unparsable or holds < MIN_BOARD alerts
  - closes at most MAX_CLOSE issues per run (the rest wait for the next run)
  - skips IDs in config/suppressions.yaml (close_suppressed_issues.py owns them)
  - skips issues whose title carries no CVE/GHSA ID (digests etc.)
  - duplicates: keeps the OLDEST open issue for an ID, closes the newer ones
"""

import json
import os
import re
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

from aggregate import load_suppressions  # noqa: E402
from close_suppressed_issues import GITHUB_API, _api_request, fetch_open_vuln_issues  # noqa: E402

ALERTS_PATH = os.path.join(REPO_ROOT, "docs", "data", "alerts.json")
MIN_BOARD = int(os.environ.get("ORPHAN_MIN_BOARD", "1000"))
MAX_CLOSE = int(os.environ.get("ORPHAN_MAX_CLOSE", "50"))
ID_RE = re.compile(r"(?<![A-Za-z0-9-])(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})(?![A-Za-z0-9-])",
                   re.IGNORECASE)


def board_ids(alerts):
    ids = set()
    for a in alerts:
        for x in [a.get("cve_id")] + list(a.get("aliases") or []):
            if x:
                ids.add(str(x).upper())
    return ids


def plan_closures(issues, ids, suppressed=(), min_board=MIN_BOARD, max_close=MAX_CLOSE):
    """Return [(number, kind, id, keep_number_or_None)], kind in {orphan, duplicate}."""
    if len(ids) < min_board:
        return []
    suppressed = {s.upper() for s in suppressed}
    first = {}
    plan = []
    for issue in sorted(issues, key=lambda i: i.get("number", 0)):
        if "pull_request" in issue:
            continue
        found = [m.upper() for m in ID_RE.findall(issue.get("title", ""))]
        if not found or any(f in suppressed for f in found):
            continue
        key = found[0]
        if key in first:
            plan.append((issue["number"], "duplicate", key, first[key]))
            continue
        first[key] = issue["number"]
        if not any(f in ids for f in found):
            plan.append((issue["number"], "orphan", key, None))
    return plan[:max_close]


def comment_for(kind, cid, keep):
    if kind == "duplicate":
        return (f"Closing as a duplicate of #{keep}, which tracks the same `{cid}`. "
                f"Both were opened before the KEV/NVD twin records were merged.")
    return (f"Auto-closing: `{cid}` is no longer on the dashboard. A later pipeline check "
            f"re-read its NVD record and found it does not match any watchlist keyword, product "
            f"or KEV entry (for example, the product data names a different vendor than the one "
            f"in this title), so it was removed as a false match.\n\n"
            f"If NVD changes the record so it does match, it comes back to the dashboard on its own.")


def main():
    token = os.environ.get("GH_ISSUE_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        print("ERROR: GITHUB_TOKEN and GITHUB_REPOSITORY env vars are required", file=sys.stderr)
        sys.exit(1)
    try:
        with open(ALERTS_PATH) as f:
            alerts = json.load(f)
    except (OSError, ValueError) as e:
        print(f"alerts.json unreadable ({e}); not closing anything.")
        return
    ids = board_ids(alerts if isinstance(alerts, list) else [])
    if len(ids) < MIN_BOARD:
        print(f"Only {len(ids)} board IDs (< {MIN_BOARD}); refusing to close orphans.")
        return
    issues = fetch_open_vuln_issues(repo, token)
    plan = plan_closures(issues, ids, load_suppressions().keys())
    closed = 0
    for number, kind, cid, keep in plan:
        _api_request(f"{GITHUB_API}/repos/{repo}/issues/{number}/comments", token, method="POST",
                     payload={"body": comment_for(kind, cid, keep)})
        ok = _api_request(f"{GITHUB_API}/repos/{repo}/issues/{number}", token, method="PATCH",
                          payload={"state": "closed", "state_reason": "not_planned"})
        if ok is not None:
            closed += 1
            print(f"  Closed #{number} ({cid}, {kind})")
        time.sleep(1.5)
    print(f"Closed {closed} orphaned/duplicate issue(s) of {len(issues)} open (cap {MAX_CLOSE}/run).")


if __name__ == "__main__":
    main()
