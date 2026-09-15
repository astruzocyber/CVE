#!/usr/bin/env python3
"""
scripts/close_suppressed_issues.py

Closes the loop on config/suppressions.yaml: when a human analyst adds a CVE/GHSA
ID to the suppression list (accepted risk / not applicable), the corresponding
GitHub Issue (opened earlier by notify_github_issues.py) previously stayed open
forever with no automated signal -- the analyst had to remember to go close it
by hand, or it just sat open indefinitely, silently degrading the issue tracker
into an inaccurate view of "what's still actionable".

This script is the mirror-image of the aggregation pipeline's suppression
filter: it reads the exact same config/suppressions.yaml (via aggregate.py's
own load_suppressions(), imported directly -- no duplicated parsing/expiry
logic to drift out of sync), then finds any OPEN issue labeled
`vulnerability-alert` whose title contains one of the active (non-expired)
suppressed IDs, and closes it with an explanatory comment citing the
suppression reason. It is read-then-close only:
  - Never opens, edits, or deletes an issue's title/body.
  - Never touches an issue that doesn't match an active suppression by ID.
  - Idempotent: only acts on issues currently in the `open` state, so re-runs
    are no-ops for already-closed issues.
  - Fail-soft: if suppressions.yaml is empty/missing, or the Issues API call
    fails after retries, it exits 0 having closed nothing rather than raising
    and failing the whole aggregation run over a non-critical cleanup step.

Run after notify_github_issues.py in the same job -- it works off the live
GitHub Issues API state, not any local file, so ordering relative to the data
commit doesn't matter.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

from aggregate import load_suppressions  # noqa: E402

GITHUB_API = "https://api.github.com"


def _api_request(url, token, method="GET", payload=None):
    """Shared GET/PATCH/POST helper with the same 3-attempt 429/5xx backoff
    used throughout aggregate.py and notify_github_issues.py."""
    data = json.dumps(payload).encode() if payload is not None else None
    for attempt in range(3):
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read()
                return json.loads(body.decode()) if body else None
        except urllib.error.HTTPError as e:
            if e.code == 429 or e.code >= 500:
                wait = 5 * (attempt + 1)
                print(f"  HTTP {e.code} on {method} {url}, retrying in {wait}s "
                      f"(attempt {attempt + 1}/3)...", file=sys.stderr)
                time.sleep(wait)
                continue
            body_text = ""
            try:
                body_text = e.read().decode()[:300]
            except Exception:
                pass
            print(f"  ERROR {method} {url}: HTTP {e.code} {body_text}", file=sys.stderr)
            return None
    print(f"  ERROR {method} {url} failed after 3 attempts.", file=sys.stderr)
    return None


def fetch_open_vuln_issues(repo, token):
    """Paginate repos/{repo}/issues?state=open&labels=vulnerability-alert.
    Bounded to a sane number of pages (20 x 100 = 2000 issues) as a defensive
    ceiling -- this project has never come close to that volume."""
    issues = []
    for page in range(1, 21):
        url = (f"{GITHUB_API}/repos/{repo}/issues"
               f"?state=open&labels=vulnerability-alert&per_page=100&page={page}")
        data = _api_request(url, token)
        if not data:
            break
        issues.extend(data)
        if len(data) < 100:
            break
    return issues


def close_issue(repo, token, issue_number, reason, sid):
    comment_body = (
        f"Auto-closing: `{sid}` was added to `config/suppressions.yaml` "
        f"(accepted risk / not applicable) by a human analyst.\n\n"
        f"**Reason:** {reason or '(no reason recorded)'}\n\n"
        f"If this suppression expires or is removed, this CVE/advisory will "
        f"automatically re-enter triage as a new alert on a future run."
    )
    comment_ok = _api_request(
        f"{GITHUB_API}/repos/{repo}/issues/{issue_number}/comments",
        token, method="POST", payload={"body": comment_body},
    )
    close_ok = _api_request(
        f"{GITHUB_API}/repos/{repo}/issues/{issue_number}",
        token, method="PATCH", payload={"state": "closed", "state_reason": "not_planned"},
    )
    if close_ok is not None:
        print(f"  Closed issue #{issue_number} ({sid}) -- {reason or 'no reason recorded'}")
        return True
    if comment_ok is None:
        print(f"  WARNING: failed to comment on issue #{issue_number} ({sid})", file=sys.stderr)
    print(f"  ERROR: failed to close issue #{issue_number} ({sid})", file=sys.stderr)
    return False


def main():
    token = os.environ.get("GH_ISSUE_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        print("ERROR: GITHUB_TOKEN and GITHUB_REPOSITORY env vars are required", file=sys.stderr)
        sys.exit(1)

    suppressions = load_suppressions()
    if not suppressions:
        print("No active suppressions -- nothing to close.")
        return

    open_issues = fetch_open_vuln_issues(repo, token)
    if not open_issues:
        print("No open vulnerability-alert issues found.")
        return

    closed_count = 0
    for issue in open_issues:
        title = issue.get("title", "")
        number = issue.get("number")
        # Title format is "[VULN ALERT] <CVE_ID>...", so a direct substring
        # match against each active suppression ID is precise: CVE/GHSA IDs
        # are unique tokens unlikely to collide as accidental substrings of
        # unrelated titles, and this only ever *closes* (never creates/edits
        # content), so a false-negative (miss) is the safe failure mode, not
        # a false-positive.
        for sid, meta in suppressions.items():
            if sid in title:
                if close_issue(repo, token, number, meta.get("reason", ""), sid):
                    closed_count += 1
                break

    print(f"Closed {closed_count} issue(s) for newly-suppressed alert(s) "
          f"out of {len(open_issues)} open vulnerability-alert issue(s) checked.")


if __name__ == "__main__":
    main()
