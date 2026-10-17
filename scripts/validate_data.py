#!/usr/bin/env python3
"""CI regression guard: validates docs/data/*.json + frontend JS (docs/js/*.js)/index.html
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
sys.path.insert(0, str(ROOT / "scripts"))

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
    # Cross-check that the two breakdown maps this dashboard's trend chart and
    # UI pills are built from (by_severity since cycle 67's critical/high trend
    # lines, by_source since cycle 15/66's clickable pills) actually partition
    # every alert -- i.e. their value sums equal total_alerts. compute_stats()
    # buckets every alert into exactly one severity bucket ("unknown" included)
    # and one source bucket by construction, so any mismatch here would mean a
    # real bug silently dropped/double-counted alerts during aggregation
    # (e.g. a future refactor introducing an early `continue` or a KeyError
    # swallowed by a broad except) -- previously this could only have been
    # caught by a human eyeballing stats.json against alerts.json, which never
    # happened in 67 prior cycles. Cheap, stdlib-only, no false positives on
    # legitimately-partial/older data since it only fires on an actual mismatch.
    if "total_alerts" in data:
        total = data["total_alerts"]
        by_sev = data.get("by_severity")
        if isinstance(by_sev, dict):
            sev_sum = sum(v for v in by_sev.values() if isinstance(v, (int, float)))
            if sev_sum != total:
                fail(
                    f"{path}: sum(by_severity.values()) ({sev_sum}) != total_alerts ({total}) "
                    "-- every alert should fall into exactly one severity bucket"
                )
        by_src = data.get("by_source")
        if isinstance(by_src, dict):
            src_sum = sum(v for v in by_src.values() if isinstance(v, (int, float)))
            if src_sum != total:
                fail(
                    f"{path}: sum(by_source.values()) ({src_sum}) != total_alerts ({total}) "
                    "-- every alert should fall into exactly one source bucket"
                )
    print("stats.json: schema OK, total_alerts matches alerts.json, by_severity/by_source partition checks OK")


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
    # Source-of-truth: import aggregate.py's own HISTORY_CSV_HEADER constant
    # instead of hardcoding a duplicate list here. Cycle 67 introduced a
    # `critical_count`/`high_count` schema extension and this exact hardcoded
    # duplicate silently went stale (still expected the pre-extension 7-column
    # header) even though append_history()'s own doc-comment describes header
    # upgrades as an intentional, expected form of schema evolution --
    # importing the real constant means this check can never drift from the
    # actual writer again.
    from aggregate import HISTORY_CSV_HEADER
    expected_header = HISTORY_CSV_HEADER.split(",")
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


def _frontend_js_sources():
    """Frontend JS: the ES modules under docs/js/ plus a legacy docs/app.js if present."""
    sources = sorted((DOCS / "js").glob("*.js")) if (DOCS / "js").is_dir() else []
    legacy = DOCS / "app.js"
    if legacy.exists():
        sources.append(legacy)
    return sources


def check_js_html_consistency():
    sources = _frontend_js_sources()
    index_html = DOCS / "index.html"
    if not sources or not index_html.exists():
        fail("frontend JS (docs/js/*.js or docs/app.js) or docs/index.html missing")
        return
    js = "\n".join(p.read_text() for p in sources)
    html = index_html.read_text()
    # Every literal id looked up by the frontend (byId("x") helper or
    # document.getElementById("x")) must exist as an id= in index.html.
    # Per-card ids are built from template strings, so they never match.
    static_ids = re.findall(r'(?:getElementById|\bbyId)\("([\w-]+)"\)', js)
    html_ids = set(re.findall(r'id="([\w-]+)"', html))
    missing_ids = [i for i in set(static_ids) if i not in html_ids]
    if missing_ids:
        fail(f"frontend JS references element ids not present in index.html: {sorted(missing_ids)}")
    else:
        print(f"frontend JS/index.html: {len(set(static_ids))} element id references across {len(sources)} file(s) all resolve")


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


def check_alerts_schema_json():
    """Validates docs/data/alerts.json against the published JSON Schema at
    docs/data/alerts.schema.json (added as a documented, versionable data
    contract for third-party consumers of the public API). Uses the
    `jsonschema` package when available (already a transitive dependency in
    this environment); falls back to a warn-only skip if it isn't installed
    anywhere validate_data.py runs, so this never becomes a hard CI
    dependency requirement -- consistent with the zero-cost/stdlib-first
    posture of the rest of this pipeline."""
    schema_path = DOCS / "data" / "alerts.schema.json"
    alerts_path = DOCS / "data" / "alerts.json"
    if not schema_path.exists():
        warn(f"{schema_path} missing -- skipping schema validation")
        return
    try:
        schema = json.loads(schema_path.read_text())
    except Exception as e:
        fail(f"{schema_path} is not valid JSON: {e}")
        return
    if not alerts_path.exists():
        return  # already reported by check_alerts_json()
    try:
        alerts = json.loads(alerts_path.read_text())
    except Exception:
        return  # already reported by check_alerts_json()
    try:
        import jsonschema
    except ImportError:
        warn("jsonschema package not installed -- skipped alerts.schema.json validation (non-fatal, CI still enforces REQUIRED_ALERT_KEYS/type checks above)")
        return
    validator = jsonschema.Draft7Validator(schema)
    schema_errors = sorted(validator.iter_errors(alerts), key=lambda e: list(e.path))
    if schema_errors:
        for e in schema_errors[:20]:
            loc = "/".join(str(p) for p in e.path) or "(root)"
            fail(f"alerts.schema.json violation at {loc}: {e.message}")
        if len(schema_errors) > 20:
            fail(f"...and {len(schema_errors) - 20} more alerts.schema.json violations")
    else:
        print(f"alerts.schema.json: {len(alerts)} alerts validated against published JSON Schema, 0 violations")


def check_intel_json():
    """docs/data/intel.json (threat-intel board, scripts/fetch_intel.py).
    Optional file: absent is a warning, malformed is a failure."""
    path = DOCS / "data" / "intel.json"
    if not path.exists():
        warn("intel.json missing (threat-intel board will stay hidden)")
        return
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        fail(f"intel.json is not valid JSON: {e}")
        return
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        fail("intel.json must be an object with an 'items' list")
        return
    labels = data.get("category_labels") or {}
    required = {"id", "title", "link", "source", "categories", "watch_matches", "cve_ids", "score", "priority"}
    seen = set()
    for n, it in enumerate(data["items"]):
        where = f"intel.json items[{n}]"
        if not isinstance(it, dict):
            fail(f"{where} is not an object")
            continue
        missing = required - set(it)
        if missing:
            fail(f"{where} missing keys {sorted(missing)}")
            continue
        if it["id"] in seen:
            fail(f"{where} duplicate id {it['id']}")
        seen.add(it["id"])
        if not str(it["link"]).startswith(("https://", "http://")):
            fail(f"{where} link is not http(s)")
        if it["priority"] not in ("high", "medium", "low"):
            fail(f"{where} bad priority {it['priority']!r}")
        for c in it["categories"]:
            if c not in labels:
                fail(f"{where} category {c!r} has no label")
        for cid in it["cve_ids"]:
            if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cid):
                fail(f"{where} malformed CVE id {cid!r}")
        # Anti-hallucination guard: every CVE id must appear verbatim in the item text.
        text = f"{it['title']} {it.get('summary', '')}".upper()
        for cid in it["cve_ids"]:
            if cid.upper() not in text:
                fail(f"{where} CVE {cid} not present in its own title/summary")
    print(f"intel.json: {len(data['items'])} items checked")


def check_escalations_json():
    """docs/data/escalations.json (Escalate-now board, scripts/escalate.py).
    Optional: absent is a warning, malformed is a failure. Every item must carry
    an 'In your estate' reason quoting the literal term that matched."""
    path = DOCS / "data" / "escalations.json"
    if not path.exists():
        warn("escalations.json missing (Escalate-now board will stay hidden)")
        return
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        fail(f"escalations.json is not valid JSON: {e}")
        return
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        fail("escalations.json must be an object with an 'items' list")
        return
    asset_names = {a.get("name") for a in data.get("assets") or []}
    seen = set()
    for n, it in enumerate(data["items"]):
        where = f"escalations.json items[{n}]"
        if not isinstance(it, dict):
            fail(f"{where} is not an object")
            continue
        missing = {"key", "kind", "ref", "title", "tier", "assets", "criticality", "reasons"} - set(it)
        if missing:
            fail(f"{where} missing keys {sorted(missing)}")
            continue
        if it["key"] in seen:
            fail(f"{where} duplicate key {it['key']}")
        seen.add(it["key"])
        if it["tier"] not in ("escalate", "work"):
            fail(f"{where} bad tier {it['tier']!r}")
        if it["kind"] not in ("cve", "intel", "bundle"):
            fail(f"{where} bad kind {it['kind']!r}")
        if it["kind"] == "bundle" and not (isinstance(it.get("cve_ids"), list) and it["cve_ids"]):
            fail(f"{where} bundle without cve_ids (members would be lost)")
        if it["kind"] == "bundle" and it["tier"] != "work":
            fail(f"{where} bundle must be WORK tier (escalations are never bundled)")
        if "triage" in it and (not isinstance(it["triage"], dict) or not it["triage"].get("status")):
            fail(f"{where} malformed triage block")
        if not it["assets"] or not set(it["assets"]) <= asset_names:
            fail(f"{where} assets not in the environment profile")
        if not it["reasons"] or not str(it["reasons"][0]).startswith("In your estate:"):
            fail(f"{where} has no estate-match reason")
    print(f"escalations.json: {len(data['items'])} items checked")


TRIAGE_OK = {"acknowledged", "in_progress", "escalated", "resolved", "false_positive", "accepted_risk"}


def check_triage_yaml(path=None):
    """config/triage.yaml is hand-edited in the GitHub web UI, so a typo must
    fail CI loudly instead of silently dropping the team's triage."""
    path = path or (ROOT / "config" / "triage.yaml")
    if not Path(path).exists():
        warn("config/triage.yaml missing (shared triage disabled)")
        return
    try:
        import yaml
    except ImportError:
        warn("PyYAML not installed -- triage.yaml not checked")
        return
    try:
        cfg = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        fail(f"triage.yaml is not valid YAML: {e}")
        return
    entries = cfg.get("entries") if isinstance(cfg, dict) else None
    if entries is None:
        entries = {}
    if not isinstance(entries, dict):
        fail("triage.yaml 'entries' must be a mapping of key -> {status, ...}")
        return
    key_re = re.compile(r"^(cve:CVE-\d{4}-\d{4,}|intel:[0-9a-f]{16}|bundle:[a-z0-9-]+:\d{4}-\d{2}-\d{2})$")
    for key, v in entries.items():
        if not key_re.match(str(key)):
            fail(f"triage.yaml key {key!r} is not cve:CVE-…, intel:<16 hex> or bundle:<asset>:<date>")
        if not isinstance(v, dict) or str(v.get("status", "")).strip().lower() not in TRIAGE_OK:
            fail(f"triage.yaml {key!r}: status must be one of {sorted(TRIAGE_OK)}")
    print(f"triage.yaml: {len(entries)} entries checked")


def main():
    check_alerts_json()
    check_alerts_schema_json()
    check_stats_json()
    check_trend_csv()
    check_js_html_consistency()
    check_feeds()
    check_intel_json()
    check_escalations_json()
    check_triage_yaml()

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
