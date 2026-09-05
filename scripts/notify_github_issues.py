#!/usr/bin/env python3
"""
scripts/notify_github_issues.py

Reads data/new_alerts.json (produced by scripts/aggregate.py in the same job) and opens
one GitHub Issue per new alert, with a triage checklist. Uses the built-in
GITHUB_TOKEN (via GH_REPO_TOKEN env, typically secrets.GITHUB_TOKEN in the workflow --
no extra secret needed for this channel).

Idempotent by design: it only ever reads data/new_alerts.json, which aggregate.py
already filtered down to alerts not present in data/seen_ids.json. If this script fails
partway, the alerts are already marked "seen" so they won't be re-issued next run --
that's an accepted tradeoff to avoid duplicate issues at the cost of possibly missing a
notification on rare failure (visible in the Action run logs either way).
"""
import json
import os
import sys
import urllib.request
import urllib.error

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEW_ALERTS_PATH = os.path.join(REPO_ROOT, "docs", "data", "new_alerts.json")
GITHUB_API = "https://api.github.com"


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


def build_issue_body(alert):
    kev_line = "Yes (CISA Known Exploited Vulnerabilities catalog)" if alert.get("kev") else "No"
    epss = alert.get("epss_score")
    epss_line = f"{epss:.2%}" if isinstance(epss, (int, float)) else "unknown"
    affected = ", ".join(alert.get("affected", [])) or "n/a"
    keywords = ", ".join(alert.get("matched_keywords", [])) or "n/a"
    dependabot_url = alert.get("dependabot_url")

    lines = [
        f"**CVE:** {alert.get('cve_id', 'unknown')}",
        f"**Source:** {alert.get('source', 'unknown')}",
        f"**CVSS score:** {alert.get('cvss_score', 'n/a')} ({alert.get('cvss_version', 'n/a')})",
        f"**EPSS score:** {epss_line}",
        f"**In CISA KEV:** {kev_line}",
        f"**Affected vendor/product:** {affected}",
        f"**Matched keywords:** {keywords}",
        f"**Published:** {alert.get('published', 'n/a')}",
    ]
    if dependabot_url:
        lines.append(f"**Dependabot alert:** {dependabot_url}")
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
        "- [ ] Close this issue once resolved",
    ]
    return "\n".join(lines)


def create_issue(repo, token, title, body, labels):
    url = f"{GITHUB_API}/repos/{repo}/issues"
    payload = json.dumps({"title": title, "body": body, "labels": labels}).encode()
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
        body_text = ""
        try:
            body_text = e.read().decode()
        except Exception:
            pass
        print(f"  ERROR creating issue for {title}: HTTP {e.code} {body_text[:300]}", file=sys.stderr)
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

    print(f"Opening {len(alerts)} GitHub issue(s) for new alerts...")
    for alert in alerts:
        cve_id = alert.get("cve_id", "UNKNOWN")
        kev_tag = " [KEV]" if alert.get("kev") else ""
        title = f"[VULN ALERT] {cve_id}{kev_tag} - {', '.join(alert.get('affected', [])) or alert.get('source')}"
        body = build_issue_body(alert)
        labels = ["vulnerability-alert", severity_label(alert.get("cvss_score"))]
        if alert.get("kev"):
            labels.append("kev")
        create_issue(repo, token, title, body, labels)


if __name__ == "__main__":
    main()
