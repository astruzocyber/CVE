#!/usr/bin/env python3
"""
scripts/notify_github_issues.py

Reads docs/data/new_alerts.json (produced by scripts/aggregate.py in the same job) and
opens one GitHub Issue per new alert, with a risk-based priority label and a triage
checklist. Uses the built-in GITHUB_TOKEN -- no extra secret needed for this channel.

Idempotent by design: it only ever reads docs/data/new_alerts.json, which aggregate.py
already filtered down to alerts not present in docs/data/seen_ids.json. If this script
fails partway, the alerts are already marked "seen" so they won't be re-issued next run
-- that's an accepted tradeoff to avoid duplicate issues at the cost of possibly missing
a notification on rare failure (visible in the Action run logs either way).
"""
import http.client
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEW_ALERTS_PATH = os.path.join(REPO_ROOT, "docs", "data", "new_alerts.json")
GITHUB_API = "https://api.github.com"
ESCALATIONS_PATH = os.path.join(REPO_ROOT, "docs", "data", "escalations.json")
# GitHub's secondary rate limit on content creation is roughly 80 requests/min
# and 500/hour; a burst of 341 issues tripped it. Cap per run, pace each call,
# and roll the overflow into ONE digest issue so nothing is silently dropped.
MAX_ISSUES_PER_RUN = int(os.environ.get("MAX_ISSUES_PER_RUN") or 40)
ISSUE_PACING_S = float(os.environ.get("ISSUE_PACING_S") or 2.0)


def load_new_alerts():
    if not os.path.exists(NEW_ALERTS_PATH):
        return []
    with open(NEW_ALERTS_PATH, "r") as f:
        return json.load(f)


def severity_label(cvss):
    if cvss is None:
        return "severity-unknown"
    if cvss >= 9.0:
        return "severity-critical"
    if cvss >= 7.0:
        return "severity-high"
    if cvss >= 4.0:
        return "severity-medium"
    return "severity-low"


def priority_label(risk_score):
    """Priority is driven by the composite risk score (CVSS+EPSS+KEV), not raw CVSS
    alone -- a CVSS 7.0 CVE that is actively exploited (KEV) and has high EPSS should
    outrank a theoretical CVSS 9.8 nobody is exploiting. This is what a working triage
    queue should optimize for."""
    if risk_score is None:
        return "priority-unknown"
    if risk_score >= 75:
        return "priority-p0-urgent"
    if risk_score >= 50:
        return "priority-p1-high"
    if risk_score >= 25:
        return "priority-p2-medium"
    return "priority-p3-low"


# Upstream text (NVD/GHSA descriptions often credit researchers as "@handle")
# is pasted into issues on a PUBLIC repo, where GitHub renders "@handle" as a
# user mention and notifies that stranger. A zero-width space after the "@"
# stops the mention while the text still reads the same. Emails (a@b.com) are
# left alone: GitHub never mentions there and the lookbehind skips them.
_MENTION_RE = re.compile(r"(?<![A-Za-z0-9_`])@(?=[A-Za-z0-9])")
# Same problem for issue references: kernel oops traces ("Not tainted 6.8.6 #1",
# "[#1] SMP") and version strings ("5.5.2 #147") made GitHub link to OUR repo's
# unrelated issues #1/#147 and post "mentioned this issue" on them (issue #1
# collected 14 such cross-references). Covers "#123", "GH-123" and
# "owner/repo#123"; URL fragments ("/page#1", "&#35;") are left alone.
_ISSUE_REF_RE = re.compile(r"(?<![\w&/#])(#|GH-)(?=\d)")
_REPO_REF_RE = re.compile(r"(?<![\w./:@-])([\w.-]+/[\w.-]+#)(?=\d)")


def no_mention(text):
    if not isinstance(text, str):
        return text
    text = _MENTION_RE.sub("@\u200b", text)
    text = _REPO_REF_RE.sub("\\1\u200b", text)
    return _ISSUE_REF_RE.sub("\\1\u200b", text)


def issue_title(alert):
    cve_id = alert.get("cve_id", "UNKNOWN")
    kev_tag = " [KEV]" if alert.get("kev") else ""
    ransomware_tag = " [RANSOMWARE]" if alert.get("kev_ransomware_use") else ""
    risk = alert.get("risk_score")
    risk_tag = f" (risk {risk})" if risk is not None else ""
    return no_mention(f"[VULN ALERT] {cve_id}{kev_tag}{ransomware_tag}{risk_tag} - {what_matched(alert)}")


def what_matched(alert, limit=120):
    """Why the alert is on the board, for issue titles and the digest: the
    watchlist vendor/product pairs, else the matched keywords. The source name
    ('nvd') is only a last resort: it is not an affected product."""
    pairs = ", ".join(alert.get("affected") or [])
    if pairs:
        return pairs[:limit]
    kws = ", ".join(str(k) for k in (alert.get("matched_keywords") or []))
    if kws:
        return f"keyword: {kws}"[:limit]
    return str(alert.get("source") or "unknown")


STANDARD_RISK_METHOD = "35% CVSS + 40% EPSS + 25% KEV bonus"


def risk_method(alert):
    """How THIS alert's risk score was computed. When NVD/FIRST has not
    published CVSS or EPSS yet (common on the day a CVE is new, i.e. exactly
    when its issue is opened), aggregate.composite_risk_score redistributes
    that weight onto the known components; the fixed 35/40/25 text then gave
    a formula that does not produce the number shown (issue #2086: risk 51.3,
    while 35% of CVSS 8.8 is 30.8). Use the alert's own breakdown instead."""
    b = alert.get("risk_score_breakdown")
    if not isinstance(b, dict) or not b.get("weight_redistributed"):
        return STANDARD_RISK_METHOD
    missing = [n for n, k in (("CVSS", "cvss_raw"), ("EPSS", "epss_raw")) if b.get(k) is None]
    parts = [b.get(k) for k, raw in (("cvss_weight", "cvss_raw"), ("epss_weight", "epss_raw"))
             if b.get(raw) is not None and b.get(k)]
    if b.get("kev_weight"):
        parts.append(b["kev_weight"])
    if not missing or not parts:
        return STANDARD_RISK_METHOD
    return (f"{' and '.join(missing)} not published yet, so the weight is redistributed: "
            + " + ".join(str(p) for p in parts))


def build_issue_body(alert):
    return no_mention(_issue_body(alert))


def _issue_body(alert):
    kev_line = "Yes (CISA Known Exploited Vulnerabilities catalog)" if alert.get("kev") else "No"
    epss = alert.get("epss_score")
    epss_line = f"{epss:.2%}" if isinstance(epss, (int, float)) else "unknown"
    affected = ", ".join(alert.get("affected", [])) or "n/a"
    keywords = ", ".join(alert.get("matched_keywords", [])) or "n/a"
    dependabot_url = alert.get("dependabot_url")
    risk = alert.get("risk_score")

    lines = [
        f"**CVE:** {alert.get('cve_id', 'unknown')}",
        f"**Composite risk score:** {risk if risk is not None else 'n/a'}/100 "
        f"({risk_method(alert)} -- see dashboard footer for methodology)",
        f"**Source:** {alert.get('source', 'unknown')}",
        f"**CVSS score:** {alert.get('cvss_score', 'n/a')} ({alert.get('cvss_version', 'n/a')})",
        f"**EPSS score:** {epss_line}",
        f"**In CISA KEV:** {kev_line}",
    ]
    if alert.get("kev"):
        lines.append(f"**KEV remediation due date:** {alert.get('kev_due_date', 'n/a')}")
        if alert.get("kev_ransomware_use"):
            lines.append("**Known ransomware campaign use:** YES -- treat as urgent")
        if alert.get("kev_required_action"):
            lines.append(f"**CISA required action:** {alert.get('kev_required_action')}")
    lines += [
        f"**Affected vendor/product:** {affected}",
        f"**Matched keywords:** {keywords}",
        f"**Published:** {alert.get('published', 'n/a')}",
    ]
    if dependabot_url:
        lines.append(f"**Advisory/alert link:** {dependabot_url}")
    lines += [
        "",
        "**Description:**",
        alert.get("description", "(no description)"),
        "",
        "---",
        "### Triage checklist",
        "- [ ] Confirm this affects our actual deployed stack/version",
        "- [ ] Check for available patch / upgrade path",
        "- [ ] Assess exploitability in our environment (network exposure, auth required, etc.)",
        "- [ ] Patch or mitigate",
        "- [ ] If not applicable, add to config/suppressions.yaml with a reason + expiry "
        "rather than just closing this issue, so it does not silently resurface as a "
        "false \"new\" alert",
        "- [ ] Close this issue once resolved",
    ]
    return "\n".join(lines)


def retry_wait(headers, attempt, cap=120):
    """Seconds to wait before retrying: Retry-After, else x-ratelimit-reset when
    the primary quota is exhausted, else exponential backoff. Capped so a run
    never hangs."""
    headers = headers or {}
    ra = headers.get("Retry-After")
    if ra and str(ra).strip().isdigit():
        return min(int(ra), cap)
    if str(headers.get("x-ratelimit-remaining", "")).strip() == "0":
        reset = str(headers.get("x-ratelimit-reset", "")).strip()
        if reset.isdigit():
            return max(1, min(int(reset) - int(time.time()), cap))
    return min(15 * (2 ** attempt), cap)


def split_for_cap(alerts, cap=MAX_ISSUES_PER_RUN):
    """(individual, overflow). Alerts on the environment board (Escalate/Work)
    always go first, then by risk score, so the cap only ever drops the least
    relevant ones into the digest."""
    board = _board_tiers()
    def key(a):
        tier = board.get(f"cve:{a.get('cve_id')}")
        return ({"escalate": 0, "work": 1}.get(tier, 2), -(a.get("risk_score") or 0))
    ordered = sorted(alerts, key=key)
    return ordered[:cap], ordered[cap:]


def _board_tiers():
    try:
        with open(ESCALATIONS_PATH, encoding="utf-8") as fh:
            items = json.load(fh).get("items") or []
        out = {}
        for it in items:
            out[it.get("key")] = it.get("tier")
            for cid in it.get("cve_ids") or []:   # bundled CVEs keep their tier
                out.setdefault(f"cve:{cid}", it.get("tier"))
        return out
    except (OSError, ValueError, AttributeError):
        return {}


def build_digest_body(overflow):
    lines = [f"{len(overflow)} additional new alert(s) this run were above the per-run issue cap "
             f"({MAX_ISSUES_PER_RUN}). They are all on the dashboard; listed here so none is lost.", "",
             "| CVE | CVSS | Risk | KEV | Affected / keyword |", "|---|---|---|---|---|"]
    for a in overflow[:300]:
        aff = what_matched(a, limit=80).replace("|", "/")
        lines.append(f"| {a.get('cve_id')} | {a.get('cvss_score')} | {a.get('risk_score')} | "
                     f"{'yes' if a.get('kev') else ''} | {aff} |")
    if len(overflow) > 300:
        lines.append(f"\n…and {len(overflow) - 300} more (see the dashboard).")
    return no_mention("\n".join(lines))


def create_issue(repo, token, title, body, labels):
    """Create a GitHub Issue with retry/backoff on 429/5xx, mirroring the same
    3-attempt exponential-backoff pattern used throughout scripts/aggregate.py
    for CISA KEV/NVD/EPSS/Dependabot/GHSA. Without this, a transient rate-limit
    or 5xx from the Issues API would silently drop a vulnerability notification
    for the rest of the run with no retry -- the exact failure mode already
    fixed for every data-fetch call, but previously left unaddressed here."""
    url = f"{GITHUB_API}/repos/{repo}/issues"
    payload = json.dumps({"title": title, "body": body, "labels": labels}).encode()
    last_err = None
    for attempt in range(4):
        req = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                print(f"  Created issue #{data.get('number')}: {title}")
                return True
        except urllib.error.HTTPError as e:
            last_err = e
            body_text = ""
            try:
                body_text = e.read().decode()
            except Exception:
                pass
            secondary = e.code == 403 and ("secondary rate limit" in body_text.lower()
                                           or "abuse" in body_text.lower()
                                           or (e.headers or {}).get("Retry-After"))
            if e.code == 429 or e.code >= 500 or secondary:
                wait = retry_wait(e.headers, attempt)
                print(f"  Issue creation HTTP {e.code} for {title}, retrying in {wait}s "
                      f"(attempt {attempt + 1}/4)...", file=sys.stderr)
                time.sleep(wait)
                continue
            print(f"  ERROR creating issue for {title}: HTTP {e.code} {body_text[:300]}", file=sys.stderr)
            return False
        except (OSError, http.client.HTTPException) as e:
            # Timeout / reset / DNS failure. Uncaught, this ended main() and every
            # later alert of the run lost its issue for good (seen_ids is already
            # committed). Retry like a 5xx; if the POST did land, the duplicate
            # closer folds the twin.
            last_err = e
            wait = retry_wait(None, attempt)
            print(f"  Issue creation network error for {title} ({type(e).__name__}: {e}), "
                  f"retrying in {wait}s (attempt {attempt + 1}/4)...", file=sys.stderr)
            time.sleep(wait)
            continue
    print(f"  ERROR creating issue for {title} after 4 attempts: {last_err}", file=sys.stderr)
    return False


def main():
    token = os.environ.get("GH_ISSUE_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        print("ERROR: GITHUB_TOKEN and GITHUB_REPOSITORY env vars are required", file=sys.stderr)
        sys.exit(1)

    alerts = load_new_alerts()
    if not alerts:
        print("No new alerts to notify.")
        return

    # Highest composite risk first, so if the run is interrupted partway, the most
    # urgent issues were the ones already created.
    # Environment-board items first, then highest risk, so if the run is
    # interrupted (or capped) the most urgent issues are the ones created.
    alerts, overflow = split_for_cap(alerts)

    print(f"Opening {len(alerts)} GitHub issue(s) for new alerts"
          f"{f' (+1 digest for {len(overflow)} more)' if overflow else ''}...")
    board = _board_tiers()
    failures = 0
    for i, alert in enumerate(alerts):
        if i:
            time.sleep(ISSUE_PACING_S)
        cve_id = alert.get("cve_id", "UNKNOWN")
        title = issue_title(alert)
        body = build_issue_body(alert)
        labels = ["vulnerability-alert", severity_label(alert.get("cvss_score")),
                   priority_label(alert.get("risk_score"))]
        if alert.get("kev"):
            labels.append("kev")
        if alert.get("kev_ransomware_use"):
            labels.append("ransomware")
        tier = board.get(f"cve:{cve_id}")
        if tier:
            labels.append(f"env-{tier}")   # env-escalate / env-work: in our estate
        if not create_issue(repo, token, title, body, labels):
            failures += 1
            if failures >= 5:
                print("  Too many consecutive issue failures -- stopping; alerts remain on the dashboard.",
                      file=sys.stderr)
                return
        else:
            failures = 0
    if overflow:
        time.sleep(ISSUE_PACING_S)
        create_issue(repo, token, f"[VULN DIGEST] {len(overflow)} more new alert(s) this run",
                     build_digest_body(overflow), ["vulnerability-alert", "digest"])


if __name__ == "__main__":
    main()
