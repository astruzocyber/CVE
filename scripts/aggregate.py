#!/usr/bin/env python3
"""
scripts/aggregate.py

Pulls vulnerability intel from CISA KEV, NVD, FIRST.org EPSS, and GitHub Dependabot
Alerts, filters against config/watchlist.yaml, deduplicates against data/seen_ids.json,
and writes:
  - data/alerts.json      cumulative list of ALL matched alerts (dashboard reads this)
  - data/seen_ids.json    set of unique keys already surfaced (persists across runs)
  - data/new_alerts.json  only the alerts that are NEW this run (notify step reads this;
                           not meant to be committed, see .gitignore)

Environment variables (all optional except where noted):
  NVD_API_KEY            NVD API key (raises rate limit 5->50 req/30s). If unset, the
                          script runs unauthenticated and paces itself accordingly.
  GH_DEPENDABOT_TOKEN    PAT with security_events read scope, needed only if
                          dependabot_repos is non-empty in watchlist.yaml.
  LOOKBACK_DAYS          How many days back to query NVD for published/modified CVEs.
                          Default 8 (covers scheduler downtime/failures with margin).

Design notes / assumptions (flagged per project brief instructions):
  - NVD's CVE API does not accept a vendor+product pair directly without a well-formed
    CPE URI. Rather than guess CPE strings, we use `keywordSearch` with "<vendor> <product>"
    which searches CVE descriptions/titles. This is broader than a strict CPE match but
    avoids silently fabricating CPE URIs that might not exist. Same technique for keywords.
  - Dependabot alerts are already scoped to repos the user explicitly listed, so we do NOT
    re-apply the vendor/product/keyword filter to them -- only the CVSS floor and the
    require_kev_or_high_epss switch, consistent with "filters results against the watchlist".
  - EPSS API allows batched lookups: https://api.first.org/data/v1/epss?cve=A,B,C
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. pip install -r requirements.txt", file=sys.stderr)
    raise

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WATCHLIST_PATH = os.path.join(REPO_ROOT, "config", "watchlist.yaml")
# Data lives under docs/data so GitHub Pages (serving from /docs) can fetch it directly
# via a relative path, with no separate copy/sync step needed.
DATA_DIR = os.path.join(REPO_ROOT, "docs", "data")
ALERTS_PATH = os.path.join(DATA_DIR, "alerts.json")
SEEN_PATH = os.path.join(DATA_DIR, "seen_ids.json")
NEW_ALERTS_PATH = os.path.join(DATA_DIR, "new_alerts.json")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
GITHUB_API = "https://api.github.com"

USER_AGENT = "cve-kev-dependabot-dashboard/1.0 (+github actions)"


def http_get_json(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def load_watchlist():
    with open(WATCHLIST_PATH, "r") as f:
        wl = yaml.safe_load(f)
    wl.setdefault("cvss_minimum", 7.0)
    wl.setdefault("vendors_products", [])
    wl.setdefault("keywords", [])
    wl.setdefault("dependabot_repos", [])
    wl.setdefault("require_kev_or_high_epss", False)
    wl.setdefault("epss_high_threshold", 0.5)
    return wl


def load_json_file(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return default
    return default


def save_json_file(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=False)
        f.write("\n")


# ---------------------------------------------------------------------------
# 1. CISA KEV
# ---------------------------------------------------------------------------
def fetch_kev():
    print("Fetching CISA KEV catalog...")
    try:
        data = http_get_json(KEV_URL)
        vulns = data.get("vulnerabilities", [])
        kev_map = {v["cveID"]: v for v in vulns if "cveID" in v}
        print(f"  KEV catalog: {len(kev_map)} entries")
        return kev_map
    except Exception as e:
        print(f"  WARNING: failed to fetch KEV catalog: {e}", file=sys.stderr)
        return {}


# ---------------------------------------------------------------------------
# 2. NVD
# ---------------------------------------------------------------------------
def nvd_query(params, api_key=None):
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    url = NVD_URL + "?" + urllib.parse.urlencode(params)
    for attempt in range(3):
        try:
            return http_get_json(url, headers=headers, timeout=45)
        except urllib.error.HTTPError as e:
            if e.code == 403 or e.code == 429:
                wait = 6 * (attempt + 1)
                print(f"  NVD rate-limited/forbidden (HTTP {e.code}), backing off {wait}s...")
                time.sleep(wait)
                continue
            print(f"  NVD HTTP error {e.code}: {e.reason}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"  NVD request failed: {e}", file=sys.stderr)
            time.sleep(3)
    return None


def extract_cvss(nvd_cve):
    metrics = nvd_cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            score = cvss_data.get("baseScore")
            if score is not None:
                return float(score), key.replace("cvssMetric", "CVSS ")
    return None, None


def extract_description(nvd_cve):
    for d in nvd_cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def fetch_nvd_candidates(watchlist, api_key):
    lookback_days = int(os.environ.get("LOOKBACK_DAYS", "8"))
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=lookback_days)
    date_fmt = "%Y-%m-%dT%H:%M:%S.000"

    search_terms = []
    for vp in watchlist["vendors_products"]:
        vendor = vp.get("vendor", "")
        product = vp.get("product", "")
        term = f"{vendor} {product}".strip()
        if term:
            search_terms.append(("vendor_product", term, vendor, product))
    for kw in watchlist["keywords"]:
        search_terms.append(("keyword", kw, None, None))

    candidates = {}
    delay = 0.7 if api_key else 6.5  # stay under 50/30s (key) or 5/30s (no key)

    print(f"Querying NVD for {len(search_terms)} search terms (lookback {lookback_days}d)...")
    for kind, term, vendor, product in search_terms:
        params = {
            "keywordSearch": term,
            "lastModStartDate": start.strftime(date_fmt),
            "lastModEndDate": end.strftime(date_fmt),
            "resultsPerPage": 200,
        }
        result = nvd_query(params, api_key)
        time.sleep(delay)
        if not result:
            continue
        vulns = result.get("vulnerabilities", [])
        for v in vulns:
            cve = v.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            score, cvss_version = extract_cvss(cve)
            entry = candidates.setdefault(cve_id, {
                "cve_id": cve_id,
                "description": extract_description(cve),
                "cvss_score": score,
                "cvss_version": cvss_version,
                "published": cve.get("published"),
                "matched_vendor_product": [],
                "matched_keywords": [],
                "source": "nvd",
            })
            if kind == "vendor_product":
                pair = f"{vendor}/{product}"
                if pair not in entry["matched_vendor_product"]:
                    entry["matched_vendor_product"].append(pair)
            else:
                if term not in entry["matched_keywords"]:
                    entry["matched_keywords"].append(term)
    print(f"  NVD candidates (pre-filter): {len(candidates)}")
    return candidates


# ---------------------------------------------------------------------------
# 3. EPSS
# ---------------------------------------------------------------------------
def fetch_epss(cve_ids):
    epss_scores = {}
    batch_size = 100
    ids = list(cve_ids)
    print(f"Querying EPSS for {len(ids)} CVEs...")
    for i in range(0, len(ids), batch_size):
        batch = ids[i:i + batch_size]
        url = EPSS_URL + "?" + urllib.parse.urlencode({"cve": ",".join(batch)})
        try:
            data = http_get_json(url, timeout=30)
            for item in data.get("data", []):
                cve = item.get("cve")
                if cve:
                    epss_scores[cve] = {
                        "epss": float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0)),
                    }
        except Exception as e:
            print(f"  WARNING: EPSS batch failed: {e}", file=sys.stderr)
        time.sleep(0.5)
    return epss_scores


# ---------------------------------------------------------------------------
# 4. GitHub Dependabot Alerts
# ---------------------------------------------------------------------------
def fetch_dependabot_alerts(repos, token):
    if not repos:
        return []
    if not token:
        print("  WARNING: dependabot_repos configured but GH_DEPENDABOT_TOKEN not set; skipping.",
              file=sys.stderr)
        return []

    results = []
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    for repo in repos:
        print(f"Querying Dependabot alerts for {repo}...")
        page = 1
        while True:
            url = f"{GITHUB_API}/repos/{repo}/dependabot/alerts?state=open&per_page=100&page={page}"
            try:
                data = http_get_json(url, headers=headers, timeout=30)
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read().decode()
                except Exception:
                    pass
                print(f"  WARNING: Dependabot API HTTP {e.code} for {repo}: {body[:300]}",
                      file=sys.stderr)
                break
            except Exception as e:
                print(f"  WARNING: Dependabot API failed for {repo}: {e}", file=sys.stderr)
                break
            if not data:
                break
            for alert in data:
                advisory = alert.get("security_advisory", {}) or {}
                cve_id = advisory.get("cve_id") or advisory.get("ghsa_id")
                cvss = (advisory.get("cvss") or {}).get("score")
                pkg = (alert.get("dependency") or {}).get("package", {}) or {}
                results.append({
                    "cve_id": cve_id,
                    "description": advisory.get("summary", ""),
                    "cvss_score": float(cvss) if cvss is not None else None,
                    "cvss_version": "GHSA CVSS",
                    "published": advisory.get("published_at"),
                    "matched_vendor_product": [pkg.get("name", "unknown")],
                    "matched_keywords": [],
                    "source": f"dependabot:{repo}",
                    "dependabot_url": alert.get("html_url"),
                    "severity": advisory.get("severity"),
                })
            if len(data) < 100:
                break
            page += 1
            time.sleep(0.3)
    print(f"  Dependabot candidates: {len(results)}")
    return results


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------
def passes_filters(entry, watchlist, kev_map, epss_map):
    cve_id = entry["cve_id"]
    cvss = entry.get("cvss_score")
    in_kev = cve_id in kev_map
    epss_info = epss_map.get(cve_id, {})
    epss_score = epss_info.get("epss")

    # A CVE with no parseable CVSS score cannot be verified against the floor -- exclude it
    # rather than let it through by default (this was silently passing everything before).
    if cvss is None:
        return False
    if cvss < watchlist["cvss_minimum"]:
        return False

    if watchlist["require_kev_or_high_epss"]:
        high_epss = epss_score is not None and epss_score >= watchlist["epss_high_threshold"]
        if not (in_kev or high_epss):
            return False

    return True


def build_final_entry(entry, kev_map, epss_map):
    cve_id = entry["cve_id"]
    in_kev = cve_id in kev_map
    epss_info = epss_map.get(cve_id, {})
    kev_entry = kev_map.get(cve_id, {})
    return {
        "cve_id": cve_id,
        "description": entry.get("description", ""),
        "cvss_score": entry.get("cvss_score"),
        "cvss_version": entry.get("cvss_version"),
        "epss_score": epss_info.get("epss"),
        "epss_percentile": epss_info.get("percentile"),
        "kev": in_kev,
        "kev_date_added": kev_entry.get("dateAdded") if in_kev else None,
        "kev_due_date": kev_entry.get("dueDate") if in_kev else None,
        "affected": entry.get("matched_vendor_product", []),
        "matched_keywords": entry.get("matched_keywords", []),
        "source": entry.get("source"),
        "published": entry.get("published"),
        "severity": entry.get("severity"),
        "dependabot_url": entry.get("dependabot_url"),
        "first_seen": datetime.now(timezone.utc).isoformat(),
    }


def unique_key(entry):
    # A CVE could legitimately show up from multiple sources (NVD watchlist match AND
    # a dependabot alert in a tracked repo) -- key on (cve_id, source) so both surface.
    return f"{entry['cve_id']}::{entry['source']}"


def main():
    nvd_api_key = os.environ.get("NVD_API_KEY", "").strip() or None
    gh_token = os.environ.get("GH_DEPENDABOT_TOKEN", "").strip() or None

    watchlist = load_watchlist()

    kev_map = fetch_kev()
    nvd_candidates = fetch_nvd_candidates(watchlist, nvd_api_key)
    dependabot_candidates = fetch_dependabot_alerts(watchlist["dependabot_repos"], gh_token)

    all_candidates = list(nvd_candidates.values()) + dependabot_candidates
    all_cve_ids = {c["cve_id"] for c in all_candidates if c.get("cve_id") and c["cve_id"].startswith("CVE-")}
    epss_map = fetch_epss(all_cve_ids) if all_cve_ids else {}

    filtered = [c for c in all_candidates if c.get("cve_id") and passes_filters(c, watchlist, kev_map, epss_map)]
    print(f"After filtering: {len(filtered)} matches")

    existing_alerts = load_json_file(ALERTS_PATH, [])
    existing_by_key = {unique_key(a): a for a in existing_alerts}
    seen_ids = set(load_json_file(SEEN_PATH, []))

    new_alerts = []
    for c in filtered:
        key = unique_key(c)
        final = build_final_entry(c, kev_map, epss_map)
        if key not in seen_ids:
            new_alerts.append(final)
            seen_ids.add(key)
            existing_by_key[key] = final
        else:
            # Already known: keep the original first_seen, but refresh scores in case
            # CVSS/EPSS/KEV status changed since we first saw it.
            prior = existing_by_key.get(key, final)
            merged = {**final, "first_seen": prior.get("first_seen", final["first_seen"])}
            existing_by_key[key] = merged

    cumulative = sorted(existing_by_key.values(), key=lambda a: a.get("first_seen", ""), reverse=True)

    save_json_file(ALERTS_PATH, cumulative)
    save_json_file(SEEN_PATH, sorted(seen_ids))
    save_json_file(NEW_ALERTS_PATH, new_alerts)

    print(f"Wrote {len(cumulative)} total alerts to {ALERTS_PATH}")
    print(f"Wrote {len(new_alerts)} NEW alerts to {NEW_ALERTS_PATH}")

    # Emit for GitHub Actions step output
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a") as f:
            f.write(f"new_alert_count={len(new_alerts)}\n")


if __name__ == "__main__":
    main()
