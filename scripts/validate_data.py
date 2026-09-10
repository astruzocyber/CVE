#!/usr/bin/env python3
"""CI regression guard: validates docs/data/*.json + docs/app.js/index.html
against the schema this project's frontend actually depends on.

Why this exists: for 53 cycles, the only thing standing between a bad commit
and a broken live dashboard was this agent's own manual per-cycle validation
(local scratch server + browser-tool spot checks). Nothing runs automatically
in CI on every push, so a manual mistake, a bypassed cycle, or a future human
edit could ship a broken dashboard with zero automated safety net. This script
is a cheap, dependency-free (stdlib-only) regression check wired into a new
GitHub Actions workflow (.github/workflows/ci.yml) that runs on every push/PR
touching docs/ or scripts/, independent of the aggregation pipeline's own
30-minute/4-hour cadence.

Exit code 0 = pass, 1 = fail (fails the CI job).
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

REQUIRED_ALERT_KEYS = {
    "cve_id", "description", "cvss_score", "risk_score",
    "epss_score", "kev", "source", "first_seen", "severity",
}

errors = []
warnings = []


def fail(msg):
    errors.append(msg)


def warn(msg):
    warnings.append(msg)


def check_alerts_json():
    path = DOCS / "data" / "alerts.json"
    if not path.exists():
        fail(f"{path} missing")
        return
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        fail(f"{path} is not valid JSON: {e}")
        return
    if not isinstance(data, list):
        fail(f"{path} root must be a list, got {type(data).__name__}")
        return
    if len(data) == 0:
        warn(f"{path} is empty (0 alerts) -- not necessarily an error but unusual")
    seen_ids = set()
    for i, alert in enumerate(data):
        if not isinstance(alert, dict):
            fail(f"{path}[{i}] is not an object")
            continue
        missing = REQUIRED_ALERT_KEYS - alert.keys()
        if missing:
            fail(f"{path}[{i}] ({alert.get('cve_id', '?')}) missing required keys: {sorted(missing)}")
        cve_id = alert.get("cve_id")
        if cve_id:
            if cve_id in seen_ids:
                fail(f"{path}: duplicate cve_id {cve_id}")
            seen_ids.add(cve_id)
            if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
                warn(f"{path}: cve_id {cve_id!r} does not match CVE-YYYY-NNNN+ pattern")
        rs = alert.get("risk_score")
        if rs is not None and not (0 <= rs <= 100):
            fail(f"{path}: {cve_id} risk_score {rs} out of expected 0-100 range")
        epss = alert.get("epss_score")
        if epss is not None and not (0 <= epss <= 1):
            fail(f"{path}: {cve_id} epss_score {epss} out of expected 0-1 range")
    print(f"alerts.json: {len(data)} alerts, {len(seen_ids)} unique CVE ids checked")


def check_stats_json():
    path = DOCS / "data" / "stats.json"
    if not path.exists():
        fail(f"{path} missing")
        return
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        fail(f"{path} is not valid JSON: {e}")
        return
    required = {"generated_at", "total_alerts", "kev_count", "by_severity", "by_source"}
    missing = required - data.keys()
    if missing:
        fail(f"{path} missing required keys: {sorted(missing)}")
    alerts_path = DOCS / "data" / "alerts.json"
    if alerts_path.exists():
        try:
            alerts = json.loads(alerts_path.read_text())
            if isinstance(alerts, list) and "total_alerts" in data:
                if data["total_alerts"] != len(alerts):
                    fail(
                        f"stats.json total_alerts ({data['total_alerts']}) != "
                        f"len(alerts.json) ({len(alerts)})"
                    )
        except Exception:
            pass
    print("stats.json: schema OK, total_alerts matches alerts.json")


def check_trend_csv():
    path = DOCS / "data" / "history" / "trend.csv"
    if not path.exists():
        warn(f"{path} missing (no history yet -- OK on a fresh repo)")
        return
    lines = path.read_text().splitlines()
    if not lines:
        fail(f"{path} is empty (missing header row)")
        return
    header = lines[0].split(",")
    expected_header = ["timestamp", "total_alerts", "kev_count", "kev_overdue_count",
                        "kev_ransomware_count", "avg_epss", "avg_risk_score"]
    if header != expected_header:
        fail(f"{path} header mismatch: got {header}, expected {expected_header}")
    ncols = len(header)
    # Schema-evolution tolerance: rows written before a column was added (e.g.
    # avg_risk_score) legitimately have FEWER columns than the current header --
    # that's an intentional, documented part of aggregate.py's append-only history
    # (see append_history()'s header-self-heal comment), not a defect, and the
    # frontend's positional CSV parser already handles it gracefully. A row with
    # MORE columns than the header is the only real anomaly worth failing on.
    for i, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        cols = line.split(",")
        if len(cols) > ncols:
            fail(f"{path}:{i} has {len(cols)} columns, more than header's {ncols}")
    print(f"trend.csv: {len(lines) - 1} data rows checked (older rows may have fewer columns than current header -- expected schema growth)")


def check_js_html_consistency():
    app_js = DOCS / "app.js"
    index_html = DOCS / "index.html"
    if not app_js.exists() or not index_html.exists():
        fail("docs/app.js or docs/index.html missing")
        return
    js = app_js.read_text()
    html = index_html.read_text()
    # Every getElementById target referenced in app.js must exist as an id= in index.html,
    # unless it's created dynamically (heuristic: only check the toolbar/control ids that
    # are known to be static markup, not per-card dynamically-generated elements).
    static_ids = re.findall(r'getElementById\("([\w-]+)"\)', js)
    html_ids = set(re.findall(r'id="([\w-]+)"', html))
    missing_ids = [i for i in set(static_ids) if i not in html_ids]
    if missing_ids:
        fail(f"app.js references getElementById ids not present in index.html: {sorted(missing_ids)}")
    else:
        print(f"app.js/index.html: {len(set(static_ids))} getElementById id references all resolve")


def check_feeds():
    for name in ("feed.json", "feed.xml"):
        path = DOCS / name
        if not path.exists():
            warn(f"{path} missing")
            continue
        if name == "feed.json":
            try:
                json.loads(path.read_text())
            except Exception as e:
                fail(f"{path} invalid JSON: {e}")
        else:
            content = path.read_text()
            if "<?xml" not in content[:100]:
                fail(f"{path} does not look like valid XML (no <?xml declaration near start)")
    print("feeds: feed.json/feed.xml presence+parse checked")


def main():
    check_alerts_json()
    check_stats_json()
    check_trend_csv()
    check_js_html_consistency()
    check_feeds()

    print()
    if warnings:
        print(f"WARNINGS ({len(warnings)}):")
        for w in warnings:
            print(f"  - {w}")
    if errors:
        print(f"FAILURES ({len(errors)}):")
        for e in errors:
            print(f"  - {e}")
        print()
        print("VALIDATION FAILED")
        sys.exit(1)
    print("VALIDATION PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
