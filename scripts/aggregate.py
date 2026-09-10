#!/usr/bin/env python3
"""
scripts/aggregate.py

Pulls vulnerability intel from CISA KEV, NVD, FIRST.org EPSS, GitHub Security
Advisories (GHSA, covers open-source package ecosystems), and GitHub Dependabot
Alerts, filters against config/watchlist.yaml, deduplicates against
docs/data/seen_ids.json, respects config/suppressions.yaml (accepted-risk list),
computes a composite risk score, and writes:
  - docs/data/alerts.json       cumulative list of ALL matched alerts (dashboard reads this)
  - docs/data/seen_ids.json     set of unique keys already surfaced (persists across runs)
  - docs/data/new_alerts.json   only the alerts that are NEW this run (notify step reads this;
                                 not meant to be committed, see .gitignore)
  - docs/data/stats.json        precomputed summary stats for the dashboard header

Environment variables (all optional except where noted):
  NVD_API_KEY            NVD API key (raises rate limit 5->50 req/30s). If unset, the
                          script runs unauthenticated and paces itself accordingly.
  GH_DEPENDABOT_TOKEN     PAT with security_events read scope, needed only if
                          dependabot_repos is non-empty in watchlist.yaml. Also used
                          (if present) as a bearer token for the GHSA advisories query
                          to raise its rate limit; GHSA works unauthenticated too.
  LOOKBACK_DAYS           How many days back to query NVD for published/modified CVEs.
                          Default 8 (covers scheduler downtime/failures with margin).

Accuracy / schema-drift policy (per project brief: "adapt and note discrepancy rather
than guess"):
  Every external API response is passed through validate_schema() before we read any
  field from it. That function checks the top-level shape we depend on actually exists;
  if the API changed shape underneath us, we print an explicit WARNING naming exactly
  what was expected vs what came back, and treat the response as empty/skipped rather
  than crash or silently fabricate a well-formed result from a malformed one. This is a
  cheap, dependency-free stand-in for full JSON-schema validation, deliberately kept
  inline (no new dependency) since the shapes we care about are small and stable.

Design notes / assumptions (flagged per project brief instructions):
  - NVD's CVE API does not accept a vendor+product pair directly without a well-formed
    CPE URI. Rather than guess CPE strings, we use `keywordSearch` with "<vendor> <product>"
    which searches CVE descriptions/titles. This is broader than a strict CPE match but
    avoids silently fabricating CPE URIs that might not exist. Same technique for keywords.
  - GHSA (GitHub Security Advisories, /advisories REST endpoint) covers open-source
    package ecosystems (npm, PyPI, Go, Maven, etc.) and is often faster than NVD for
    those ecosystems. It is queried via `affects=<package>` for each entry in
    watchlist.yaml's `ghsa_packages` list (package names, NOT vendor/product pairs --
    GHSA's `affects` filter matches actual ecosystem package names). Left empty by
    default; only queried if the user opts in with real package names, to avoid
    guessing what "package" means for a non-package vendor/product like "wordpress".
  - Dependabot alerts are already scoped to repos the user explicitly listed, so we do NOT
    re-apply the vendor/product/keyword filter to them -- only the CVSS floor and the
    require_kev_or_high_epss switch, consistent with "filters results against the watchlist".
  - EPSS API allows batched lookups: https://api.first.org/data/v1/epss?cve=A,B,C
  - Composite risk score (0-100): 35% CVSS (scaled to 100), 40% EPSS (0-1 scaled to 100),
    plus a flat +25 bonus if the CVE is in CISA KEV, capped at 100. Weights EPSS/KEV
    (actual exploitation signal) above raw CVSS (theoretical severity), matching how
    working threat-intel teams triage in practice. Formula is intentionally transparent
    and documented here plus in the dashboard footer, not a black box.
  - Suppression list (config/suppressions.yaml): CVE/GHSA IDs a human has explicitly
    marked as accepted risk / not applicable, each with a reason and optional expiry
    date. Suppressed entries are excluded from new alert generation entirely (they were
    reviewed and dismissed), but re-surface automatically once `expires` passes, so
    "accepted risk" can't silently become "forgotten forever".
"""
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone, date

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. pip install -r requirements.txt", file=sys.stderr)
    raise

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WATCHLIST_PATH = os.path.join(REPO_ROOT, "config", "watchlist.yaml")
SUPPRESSIONS_PATH = os.path.join(REPO_ROOT, "config", "suppressions.yaml")
# Data lives under docs/data so GitHub Pages (serving from /docs) can fetch it directly
# via a relative path, with no separate copy/sync step needed.
DATA_DIR = os.path.join(REPO_ROOT, "docs", "data")
ALERTS_PATH = os.path.join(DATA_DIR, "alerts.json")
SEEN_PATH = os.path.join(DATA_DIR, "seen_ids.json")
NEW_ALERTS_PATH = os.path.join(DATA_DIR, "new_alerts.json")
STATS_PATH = os.path.join(DATA_DIR, "stats.json")
HISTORY_DIR = os.path.join(DATA_DIR, "history")
HISTORY_CSV_PATH = os.path.join(HISTORY_DIR, "trend.csv")
KEV_SNAPSHOT_PATH = os.path.join(DATA_DIR, "kev_snapshot.json")
FEED_JSON_PATH = os.path.join(REPO_ROOT, "docs", "feed.json")
FEED_XML_PATH = os.path.join(REPO_ROOT, "docs", "feed.xml")
SITE_URL = "https://astruzocyber.github.io/CVE/"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
GHSA_URL = "https://api.github.com/advisories"
GITHUB_API = "https://api.github.com"

USER_AGENT = "cve-kev-dependabot-dashboard/2.0 (+github actions)"


# ---------------------------------------------------------------------------
# Schema-drift guard -- accuracy layer used before we trust ANY external
# response. Never silently proceed on a shape we don't recognize.
# ---------------------------------------------------------------------------
def validate_schema(name, obj, required_keys, kind="dict"):
    """Return True if obj matches the minimal expected shape, else print an
    explicit, specific WARNING (expected vs actual) and return False. Callers
    must skip/degrade on False rather than guess at missing fields."""
    if kind == "dict":
        if not isinstance(obj, dict):
            print(f"  SCHEMA WARNING [{name}]: expected a JSON object, got "
                  f"{type(obj).__name__}. Treating as empty.", file=sys.stderr)
            return False
        missing = [k for k in required_keys if k not in obj]
        if missing:
            print(f"  SCHEMA WARNING [{name}]: response is missing expected "
                  f"key(s) {missing} (has keys: {sorted(obj.keys())[:15]}). "
                  f"The upstream API may have changed shape -- treating this "
                  f"response as empty rather than guessing at fields.",
                  file=sys.stderr)
            return False
        return True
    if kind == "list":
        if not isinstance(obj, list):
            print(f"  SCHEMA WARNING [{name}]: expected a JSON array, got "
                  f"{type(obj).__name__}. Treating as empty.", file=sys.stderr)
            return False
        return True
    return True


def http_get_json(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body), resp.headers


def load_watchlist():
    with open(WATCHLIST_PATH, "r") as f:
        wl = yaml.safe_load(f)
    wl.setdefault("cvss_minimum", 7.0)
    wl.setdefault("vendors_products", [])
    wl.setdefault("keywords", [])
    wl.setdefault("dependabot_repos", [])
    wl.setdefault("ghsa_packages", [])
    wl.setdefault("require_kev_or_high_epss", False)
    wl.setdefault("epss_high_threshold", 0.5)
    return wl


def load_suppressions():
    """config/suppressions.yaml is optional. Schema:
    - cve_id: "CVE-2024-12345"   # or ghsa_id
      reason: "Not applicable, we don't run this module"
      expires: "2027-01-01"       # optional; omit for indefinite
    Returns a dict: {id: {"reason": ..., "expires": date-or-None}}, with any
    already-expired entries dropped (so they resurface on the next alert cycle
    rather than being silently suppressed forever).
    """
    if not os.path.exists(SUPPRESSIONS_PATH):
        return {}
    try:
        with open(SUPPRESSIONS_PATH, "r") as f:
            raw = yaml.safe_load(f) or []
    except Exception as e:
        print(f"  WARNING: could not parse config/suppressions.yaml: {e}", file=sys.stderr)
        return {}
    if not isinstance(raw, list):
        print("  WARNING: config/suppressions.yaml should be a YAML list; ignoring.",
              file=sys.stderr)
        return {}
    today = datetime.now(timezone.utc).date()
    out = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        sid = item.get("cve_id") or item.get("ghsa_id")
        if not sid:
            continue
        expires_raw = item.get("expires")
        expires = None
        if expires_raw:
            try:
                expires = datetime.strptime(str(expires_raw), "%Y-%m-%d").date()
            except ValueError:
                print(f"  WARNING: suppressions.yaml entry {sid} has an unparseable "
                      f"'expires' date ({expires_raw!r}), ignoring the expiry (treating "
                      f"as indefinite) rather than guessing what was meant.",
                      file=sys.stderr)
        if expires is not None and expires < today:
            continue  # expired -- let it resurface
        out[sid] = {"reason": item.get("reason", ""), "expires": expires_raw}
    return out


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
    """Fetch the CISA KEV catalog with retry/backoff -- a transient failure here
    would otherwise silently zero out KEV status (and the +25 risk-score bonus)
    for every alert in the entire run, so this gets the same resilience pattern
    already used by nvd_query() rather than a single bare attempt."""
    print("Fetching CISA KEV catalog...")
    last_err = None
    for attempt in range(3):
        try:
            data, _ = http_get_json(KEV_URL)
            if not validate_schema("CISA KEV", data, ["vulnerabilities", "catalogVersion"]):
                return {}
            vulns = data.get("vulnerabilities", [])
            if not validate_schema("CISA KEV.vulnerabilities", vulns, [], kind="list"):
                return {}
            kev_map = {}
            for v in vulns:
                if not isinstance(v, dict) or "cveID" not in v:
                    continue
                kev_map[v["cveID"]] = v
            print(f"  KEV catalog: {len(kev_map)} entries")
            return kev_map
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429 or e.code >= 500:
                wait = 5 * (attempt + 1)
                print(f"  KEV fetch HTTP {e.code}, retrying in {wait}s "
                      f"(attempt {attempt + 1}/3)...", file=sys.stderr)
                time.sleep(wait)
                continue
            print(f"  WARNING: failed to fetch KEV catalog: HTTP {e.code} {e.reason}",
                  file=sys.stderr)
            return {}
        except Exception as e:
            last_err = e
            wait = 5 * (attempt + 1)
            print(f"  KEV fetch failed ({e}), retrying in {wait}s "
                  f"(attempt {attempt + 1}/3)...", file=sys.stderr)
            time.sleep(wait)
    print(f"  WARNING: failed to fetch KEV catalog after 3 attempts: {last_err}", file=sys.stderr)
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
            data, _ = http_get_json(url, headers=headers, timeout=45)
            if not validate_schema("NVD response", data, ["vulnerabilities", "totalResults"]):
                return None
            return data
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


# NVD's cvssData already carries the individual CVSS vector components (attack
# vector, attack complexity, privileges required, user interaction) alongside
# baseScore -- this is the same metrics object extract_cvss() reads, just
# pulling additional already-fetched fields instead of only baseScore. These
# answer a distinct triage question from the numeric score alone: a 7.5 that
# needs local access + user interaction is a very different priority from a
# 7.5 that's remote/no-auth/no-interaction, even though both look identical
# as a bare CVSS number. Only implemented for NVD (CVSS v3.1/3.0 schema);
# GHSA/Dependabot advisories expose a raw vector_string in a mixed v3/v4
# format without pre-split fields, so extraction there is left for a future
# cycle rather than risking a mis-parsed field now.
def extract_cvss_vector_components(nvd_cve):
    metrics = nvd_cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0].get("cvssData", {})
            av = cvss_data.get("attackVector")
            ac = cvss_data.get("attackComplexity")
            pr = cvss_data.get("privilegesRequired")
            ui = cvss_data.get("userInteraction")
            if av or ac or pr or ui:
                return {
                    "attack_vector": av,
                    "attack_complexity": ac,
                    "privileges_required": pr,
                    "user_interaction": ui,
                }
    return None


# GHSA/Dependabot advisories expose a raw CVSS `vector_string` (e.g.
# "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H") rather than NVD's pre-split
# component fields. CVSS v3.0/v3.1 uses a fixed, publicly documented metric
# abbreviation scheme (first.org CVSS v3.1 spec) for AV/AC/PR/UI -- the exact
# same four components extract_cvss_vector_components() already pulls from
# NVD -- so parsing it here is following a stable public spec, not guessing.
# CVSS v4.0 vector strings share some letter codes but redefine others (e.g.
# adds AT, and UI values are N/P/A instead of v3's N/R) -- deliberately NOT
# parsed here per the "adapt, never guess" policy; a v4 vector_string is
# recognized by its "CVSS:4.0" prefix and skipped, returning None, rather
# than risking a mis-mapped field.
_CVSS_V3_AV = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}
_CVSS_V3_AC = {"L": "LOW", "H": "HIGH"}
_CVSS_V3_PR = {"N": "NONE", "L": "LOW", "H": "HIGH"}
_CVSS_V3_UI = {"N": "NONE", "R": "REQUIRED"}


def parse_cvss_v3_vector_string(vector_string):
    if not vector_string or not isinstance(vector_string, str):
        return None
    if not (vector_string.startswith("CVSS:3.0") or vector_string.startswith("CVSS:3.1")):
        return None  # v4 or unrecognized format -- do not guess, skip
    parts = {}
    for piece in vector_string.split("/"):
        if ":" in piece:
            k, v = piece.split(":", 1)
            parts[k] = v
    av = _CVSS_V3_AV.get(parts.get("AV"))
    ac = _CVSS_V3_AC.get(parts.get("AC"))
    pr = _CVSS_V3_PR.get(parts.get("PR"))
    ui = _CVSS_V3_UI.get(parts.get("UI"))
    if av or ac or pr or ui:
        return {
            "attack_vector": av,
            "attack_complexity": ac,
            "privileges_required": pr,
            "user_interaction": ui,
        }
    return None


def extract_description(nvd_cve):
    for d in nvd_cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


# NVD's "weaknesses" array can contain non-standard placeholder values like
# "NVD-CWE-Other" or "NVD-CWE-noinfo" (used when NVD analysts haven't mapped
# a real CWE yet) -- these carry no classification value for a viewer, so only
# genuine "CWE-<digits>" identifiers are kept.
_CWE_ID_RE = re.compile(r"^CWE-\d+$")


def extract_cwe_nvd(nvd_cve):
    ids = []
    for w in nvd_cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            val = d.get("value", "")
            if d.get("lang") == "en" and _CWE_ID_RE.match(val) and val not in ids:
                ids.append(val)
    return ids


def extract_cwe_ghsa(advisory_or_alert_dict):
    # Shared shape used by both the GHSA global-advisories API and the
    # Dependabot alerts API's embedded security_advisory object: a "cwes"
    # list of {"cwe_id": "CWE-79", "name": "..."} -- already present in the
    # response we already fetch, just never extracted before now.
    ids = []
    for c in (advisory_or_alert_dict.get("cwes") or []):
        if not isinstance(c, dict):
            continue
        val = c.get("cwe_id", "")
        if _CWE_ID_RE.match(val) and val not in ids:
            ids.append(val)
    return ids


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
                "cvss_vector_components": extract_cvss_vector_components(cve),
                "cwe_ids": extract_cwe_nvd(cve),
                "published": cve.get("published"),
                # NVD's lastModified is already present in every response we fetch
                # (it's how the lookback-window query itself is filtered) but was
                # never propagated into our schema -- it answers a distinct question
                # from "published": whether NVD has revised the record since initial
                # publication (rescored CVSS, corrected CWE, edited description),
                # which "published" alone can never reveal for an old CVE.
                "nvd_last_modified": cve.get("lastModified"),
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
        # Retry with backoff on transient failures -- a single dropped batch would
        # otherwise silently leave every CVE in it with epss_score=None (40% of the
        # composite risk score), same resilience pattern as nvd_query()/fetch_kev().
        for attempt in range(3):
            try:
                data, _ = http_get_json(url, timeout=30)
                if not validate_schema("EPSS response", data, ["data"]):
                    break
                for item in data.get("data", []):
                    cve = item.get("cve")
                    if cve:
                        epss_scores[cve] = {
                            "epss": float(item.get("epss", 0)),
                            "percentile": float(item.get("percentile", 0)),
                        }
                break
            except Exception as e:
                if attempt < 2:
                    wait = 5 * (attempt + 1)
                    print(f"  WARNING: EPSS batch failed ({e}), retrying in {wait}s "
                          f"(attempt {attempt + 1}/3)...", file=sys.stderr)
                    time.sleep(wait)
                else:
                    print(f"  WARNING: EPSS batch failed after 3 attempts: {e}", file=sys.stderr)
        time.sleep(0.5)
    return epss_scores


# ---------------------------------------------------------------------------
# 4. GitHub Dependabot Alerts (per named repo the user configured)
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
        # NOTE: this endpoint does NOT support the classic ?page=N offset param
        # (confirmed live: GitHub returns HTTP 400 "Pagination using the `page`
        # parameter is not supported"). It uses RFC 5988 Link-header pagination
        # instead, so we follow rel="next" URLs until exhausted.
        url = f"{GITHUB_API}/repos/{repo}/dependabot/alerts?state=open&per_page=100"
        while url:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
            # Retry with backoff on transient failures (429/5xx/network) -- same
            # resilience pattern as fetch_kev()/nvd_query()/fetch_epss(). Without
            # this, a single transient blip on any page mid-pagination silently
            # truncates or drops this repo's Dependabot alerts for the whole run.
            data = None
            link_header = ""
            page_failed = False
            last_err = None
            for attempt in range(3):
                try:
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        data = json.loads(resp.read().decode())
                        link_header = resp.headers.get("Link", "")
                    break
                except urllib.error.HTTPError as e:
                    last_err = e
                    if e.code == 429 or e.code >= 500:
                        wait = 5 * (attempt + 1)
                        print(f"  Dependabot API HTTP {e.code} for {repo}, retrying in "
                              f"{wait}s (attempt {attempt + 1}/3)...", file=sys.stderr)
                        time.sleep(wait)
                        continue
                    body = ""
                    try:
                        body = e.read().decode()
                    except Exception:
                        pass
                    print(f"  WARNING: Dependabot API HTTP {e.code} for {repo}: {body[:300]}",
                          file=sys.stderr)
                    page_failed = True
                    break
                except Exception as e:
                    last_err = e
                    wait = 5 * (attempt + 1)
                    print(f"  Dependabot API request failed for {repo} ({e}), retrying "
                          f"in {wait}s (attempt {attempt + 1}/3)...", file=sys.stderr)
                    time.sleep(wait)
            else:
                page_failed = True
            if data is None:
                if page_failed and last_err is not None and not isinstance(last_err, urllib.error.HTTPError):
                    print(f"  WARNING: Dependabot API failed for {repo} after 3 attempts: "
                          f"{last_err}", file=sys.stderr)
                break
            if not validate_schema(f"Dependabot alerts[{repo}]", data, [], kind="list"):
                break
            if not data:
                break
            for alert in data:
                if not isinstance(alert, dict):
                    continue
                advisory = alert.get("security_advisory", {}) or {}
                cve_id = advisory.get("cve_id") or advisory.get("ghsa_id")
                cvss = (advisory.get("cvss") or {}).get("score")
                vector_string = (advisory.get("cvss") or {}).get("vector_string")
                pkg = (alert.get("dependency") or {}).get("package", {}) or {}
                results.append({
                    "cve_id": cve_id,
                    "description": advisory.get("summary", ""),
                    "cvss_score": float(cvss) if cvss is not None else None,
                    "cvss_version": "GHSA CVSS",
                    "cvss_vector_components": parse_cvss_v3_vector_string(vector_string),
                    "cwe_ids": extract_cwe_ghsa(advisory),
                    "published": advisory.get("published_at"),
                    "matched_vendor_product": [pkg.get("name", "unknown")],
                    "matched_keywords": [],
                    "source": f"dependabot:{repo}",
                    "dependabot_url": alert.get("html_url"),
                    "severity": advisory.get("severity"),
                })
            # Parse Link header for rel="next", e.g.:
            # <https://api.github.com/...&page=2>; rel="next", <...>; rel="last"
            next_url = None
            for part in link_header.split(","):
                if 'rel="next"' in part:
                    start = part.find("<") + 1
                    end = part.find(">")
                    if start > 0 and end > start:
                        next_url = part[start:end]
                    break
            url = next_url
            if url:
                time.sleep(0.3)
    print(f"  Dependabot candidates: {len(results)}")
    return results


# ---------------------------------------------------------------------------
# 5. GitHub Security Advisories (GHSA) -- open-source ecosystem coverage,
#    queried by exact package name via ?affects=<package>. Schema confirmed
#    live against GitHub's own REST docs (rest/security-advisories/global-advisories)
#    before writing this: https://docs.github.com/en/rest/security-advisories/global-advisories
# ---------------------------------------------------------------------------
def fetch_ghsa_advisories(packages, token=None):
    if not packages:
        return []
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    results = []
    print(f"Querying GHSA advisories for {len(packages)} package(s)...")
    for pkg in packages:
        url = GHSA_URL + "?" + urllib.parse.urlencode({"affects": pkg, "per_page": 100})
        # Retry with backoff on transient failures (429/5xx/network) -- same resilience
        # pattern already used by fetch_kev()/nvd_query()/fetch_epss()/
        # fetch_dependabot_alerts(). Without this, a single transient blip would
        # silently drop this package's GHSA advisories for the whole run with no retry.
        data = None
        last_err = None
        hard_fail = False
        for attempt in range(3):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode())
                break
            except urllib.error.HTTPError as e:
                last_err = e
                if e.code == 429 or e.code >= 500:
                    wait = 5 * (attempt + 1)
                    print(f"  GHSA API HTTP {e.code} for package '{pkg}', retrying in "
                          f"{wait}s (attempt {attempt + 1}/3)...", file=sys.stderr)
                    time.sleep(wait)
                    continue
                body = ""
                try:
                    body = e.read().decode()
                except Exception:
                    pass
                print(f"  WARNING: GHSA API HTTP {e.code} for package '{pkg}': {body[:300]}",
                      file=sys.stderr)
                hard_fail = True
                break
            except Exception as e:
                last_err = e
                wait = 5 * (attempt + 1)
                print(f"  GHSA API request failed for package '{pkg}' ({e}), retrying "
                      f"in {wait}s (attempt {attempt + 1}/3)...", file=sys.stderr)
                time.sleep(wait)
        if data is None:
            if not hard_fail:
                print(f"  WARNING: GHSA API failed for package '{pkg}' after 3 attempts: "
                      f"{last_err}", file=sys.stderr)
            continue
        if not validate_schema(f"GHSA advisories[{pkg}]", data, [], kind="list"):
            continue
        for adv in data:
            if not isinstance(adv, dict):
                continue
            cvss_info = adv.get("cvss") or {}
            score = cvss_info.get("score")
            vector_string = cvss_info.get("vector_string")
            ecosystems = sorted({
                (v.get("package") or {}).get("ecosystem", "unknown")
                for v in (adv.get("vulnerabilities") or []) if isinstance(v, dict)
            })
            results.append({
                "cve_id": adv.get("cve_id") or adv.get("ghsa_id"),
                "description": adv.get("summary", ""),
                "cvss_score": float(score) if score is not None else None,
                "cvss_version": "GHSA CVSS",
                "cvss_vector_components": parse_cvss_v3_vector_string(vector_string),
                "cwe_ids": extract_cwe_ghsa(adv),
                "published": adv.get("published_at"),
                "matched_vendor_product": [f"{pkg} ({'/'.join(ecosystems) or 'ghsa'})"],
                "matched_keywords": [],
                "source": "ghsa",
                "dependabot_url": adv.get("html_url"),
                "severity": adv.get("severity"),
            })
        time.sleep(0.3)
    print(f"  GHSA candidates: {len(results)}")
    return results


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------
def passes_filters(entry, watchlist, kev_map, epss_map, suppressions):
    cve_id = entry["cve_id"]
    if cve_id in suppressions:
        return False
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


def composite_risk_score(cvss, epss_score, in_kev):
    """0-100 composite, weighting real-world exploitation signal (EPSS, KEV)
    above raw theoretical severity (CVSS). Documented in the module docstring
    and the dashboard footer -- never presented as an official/standard score.
    Returns (total, breakdown_dict) so callers can surface the exact components
    that produced the number instead of a black box -- score transparency.

    Missing-data handling: previously a missing CVSS or EPSS score was silently
    treated as 0 (i.e. "definitely not severe" / "definitely won't be
    exploited"), which is a materially different claim than "we don't know" --
    and could artificially deflate risk_score by up to 35 or 40 points for a
    CVE that simply hasn't been scored yet by NVD/FIRST.org (112/445 currently-
    tracked alerts are missing epss_score as of this change). Now, when a
    component's raw input is None, its weight is redistributed proportionally
    across the remaining *available* components (CVSS 35%, EPSS 40%, KEV flat
    25%) rather than counted as zero, so a CVE's score reflects only the
    signal actually known about it. KEV status is a lookup against a fixed
    public catalog, never "unknown" (only True/False), so kev_component
    itself is never missing -- only its share of the weight pool changes.
    """
    have_cvss = cvss is not None
    have_epss = epss_score is not None
    base_weights = {"cvss": 35.0 if have_cvss else 0.0,
                     "epss": 40.0 if have_epss else 0.0,
                     "kev": 25.0}
    available_weight = sum(base_weights.values())
    # available_weight is always >= 25 (kev's weight always counts), so this
    # never divides by zero.
    scale = 100.0 / available_weight

    cvss_component = round((cvss / 10.0) * base_weights["cvss"] * scale, 1) if have_cvss else 0.0
    epss_component = round((epss_score or 0) * base_weights["epss"] * scale, 1) if have_epss else 0.0
    kev_component = round(base_weights["kev"] * scale, 1) if in_kev else 0.0
    total = round(min(100, cvss_component + epss_component + kev_component), 1)
    redistributed = not (have_cvss and have_epss)
    breakdown = {
        "cvss_raw": cvss,
        "cvss_component": cvss_component,
        "cvss_weight": f"{round(base_weights['cvss'] * scale, 1)}% of (CVSS/10)" if have_cvss else "n/a (missing)",
        "epss_raw": epss_score,
        "epss_component": epss_component,
        "epss_weight": f"{round(base_weights['epss'] * scale, 1)}% of EPSS probability" if have_epss else "n/a (missing)",
        "kev_bonus": kev_component,
        "kev_weight": f"flat +{round(base_weights['kev'] * scale, 1)} if in CISA KEV",
        "capped": (cvss_component + epss_component + kev_component) > 100,
        "weight_redistributed": redistributed,
    }
    return total, breakdown


def build_final_entry(entry, kev_map, epss_map):
    cve_id = entry["cve_id"]
    in_kev = cve_id in kev_map
    epss_info = epss_map.get(cve_id, {})
    kev_entry = kev_map.get(cve_id, {})
    cvss = entry.get("cvss_score")
    epss_score = epss_info.get("epss")
    risk_score, risk_breakdown = composite_risk_score(cvss, epss_score, in_kev)
    return {
        "cve_id": cve_id,
        "description": entry.get("description", ""),
        "cvss_score": cvss,
        "cvss_version": entry.get("cvss_version"),
        "cvss_vector_components": entry.get("cvss_vector_components"),
        "cwe_ids": entry.get("cwe_ids", []),
        "epss_score": epss_score,
        "epss_percentile": epss_info.get("percentile"),
        "kev": in_kev,
        "kev_date_added": kev_entry.get("dateAdded") if in_kev else None,
        "kev_due_date": kev_entry.get("dueDate") if in_kev else None,
        "kev_ransomware_use": (kev_entry.get("knownRansomwareCampaignUse") == "Known") if in_kev else False,
        "kev_required_action": kev_entry.get("requiredAction") if in_kev else None,
        "kev_notes": kev_entry.get("notes") if in_kev else None,
        "risk_score": risk_score,
        "risk_score_breakdown": risk_breakdown,
        "risk_score_prev": None,
        "affected": entry.get("matched_vendor_product", []),
        "matched_keywords": entry.get("matched_keywords", []),
        "source": entry.get("source"),
        "published": entry.get("published"),
        "nvd_last_modified": entry.get("nvd_last_modified"),
        "severity": entry.get("severity"),
        "dependabot_url": entry.get("dependabot_url"),
        "first_seen": datetime.now(timezone.utc).isoformat(),
    }


def unique_key(entry):
    # A CVE could legitimately show up from multiple sources (NVD watchlist match AND
    # a dependabot alert in a tracked repo) -- key on (cve_id, source) so both surface.
    return f"{entry['cve_id']}::{entry['source']}"


def compute_stats(alerts):
    total = len(alerts)
    kev_count = sum(1 for a in alerts if a.get("kev"))
    ransomware_count = sum(1 for a in alerts if a.get("kev_ransomware_use"))
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    epss_values = []
    risk_values = []
    by_source = {}
    by_cwe = {}
    by_vendor_product = {}
    for a in alerts:
        cvss = a.get("cvss_score")
        if cvss is None:
            by_severity["unknown"] += 1
        elif cvss >= 9.0:
            by_severity["critical"] += 1
        elif cvss >= 7.0:
            by_severity["high"] += 1
        elif cvss >= 4.0:
            by_severity["medium"] += 1
        else:
            by_severity["low"] += 1
        if isinstance(a.get("epss_score"), (int, float)):
            epss_values.append(a["epss_score"])
        if isinstance(a.get("risk_score"), (int, float)):
            risk_values.append(a["risk_score"])
        src = a.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1
        for cwe in (a.get("cwe_ids") or []):
            by_cwe[cwe] = by_cwe.get(cwe, 0) + 1
        for vp in (a.get("affected") or []):
            by_vendor_product[vp] = by_vendor_product.get(vp, 0) + 1

    # KEV entries with a due date in the past and not yet resolved -- an
    # operationally meaningful "overdue remediation" count (BOD 22-01 style).
    today = datetime.now(timezone.utc).date()
    overdue_kev = 0
    for a in alerts:
        due = a.get("kev_due_date")
        if not due:
            continue
        try:
            due_date = datetime.strptime(due, "%Y-%m-%d").date()
            if due_date < today:
                overdue_kev += 1
        except ValueError:
            continue

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": total,
        "kev_count": kev_count,
        "kev_ransomware_count": ransomware_count,
        "kev_overdue_count": overdue_kev,
        "by_severity": by_severity,
        "by_source": by_source,
        "avg_epss": round(sum(epss_values) / len(epss_values), 4) if epss_values else None,
        # Distinct from avg_epss: the average of the composite risk_score (35% CVSS +
        # 40% EPSS + 25% KEV bonus) across all currently-tracked alerts -- a single
        # number answering "how hot is the whole tracked population right now",
        # which avg_epss alone can't (a population could have low average EPSS but
        # a high average risk_score if many entries are in KEV). Computed the same
        # way as avg_epss (mean of the already-computed risk_score field, no new
        # API calls or dependencies).
        "avg_risk_score": round(sum(risk_values) / len(risk_values), 1) if risk_values else None,
        # Top weakness (CWE) classifications across all currently-tracked alerts,
        # sorted by count descending, capped to the top 10 to keep stats.json small
        # -- a distinct triage axis from severity/source: "what KINDS of bugs are
        # we tracking right now" (e.g. a spike in CWE-79/XSS vs CWE-416/use-after-free
        # says something different than a CVSS or source breakdown ever could).
        # Built from cwe_ids, a field already extracted from NVD/GHSA/Dependabot
        # responses since the CWE-badge cycle -- zero new API calls.
        "by_cwe": dict(sorted(by_cwe.items(), key=lambda kv: kv[1], reverse=True)[:10]),
        # Top vendor/product pairs (from the already-extracted `affected` field,
        # populated from watchlist vendor/product matches and Dependabot package
        # names) across all currently-tracked alerts, sorted by count descending,
        # capped to the top 10 -- a distinct triage axis from severity/source/CWE:
        # "which of OUR actual vendors/products dominate the current alert volume"
        # (e.g. a spike in wordpress/wordpress vs openssl/openssl points triage
        # attention at a very different remediation team). Zero new API calls --
        # built entirely from data already collected each run.
        "by_vendor_product": dict(sorted(by_vendor_product.items(), key=lambda kv: kv[1], reverse=True)[:10]),
    }


# ---------------------------------------------------------------------------
# Historical trend tracking -- appends one row per run to a CSV under
# docs/data/history/trend.csv (committed to the repo, no external DB/service).
# Kept as CSV (not one-JSON-file-per-run) specifically to bound repo growth:
# roughly 6 runs/day * ~90 bytes/row =~ 200KB/year, trivially within GitHub's
# free repo storage and Pages' 1GB soft limit even after several years.
# ---------------------------------------------------------------------------
HISTORY_CSV_HEADER = (
    "timestamp,total_alerts,kev_count,kev_overdue_count,kev_ransomware_count,"
    "avg_epss,avg_risk_score"
)


def append_history(stats):
    os.makedirs(HISTORY_DIR, exist_ok=True)
    is_new = not os.path.exists(HISTORY_CSV_PATH)
    row = [
        stats.get("generated_at", ""),
        str(stats.get("total_alerts", "")),
        str(stats.get("kev_count", "")),
        str(stats.get("kev_overdue_count", "")),
        str(stats.get("kev_ransomware_count", "")),
        "" if stats.get("avg_epss") is None else str(stats["avg_epss"]),
        "" if stats.get("avg_risk_score") is None else str(stats["avg_risk_score"]),
    ]

    # Schema-drift self-heal: when a column (e.g. avg_risk_score) is added to the
    # row schema after trend.csv already exists, the old header line is never
    # rewritten by the original append-only logic below, leaving newer rows with
    # more columns than the committed header claims -- a real, previously-unnoticed
    # data-hygiene bug (harmless to the frontend's positional CSV parser, but wrong
    # for anyone opening the published artifact in a spreadsheet/pandas expecting
    # header-column count to match). If the on-disk header is stale, upgrade just
    # that one line in place; historical data rows are left untouched (older rows
    # legitimately have fewer columns -- that's the schema-evolution record, not
    # an error, per this project's stated "adapt and note discrepancy" policy).
    if not is_new:
        with open(HISTORY_CSV_PATH, "r") as f:
            lines = f.readlines()
        if lines and lines[0].rstrip("\n") != HISTORY_CSV_HEADER:
            old_header = lines[0].rstrip("\n")
            lines[0] = HISTORY_CSV_HEADER + "\n"
            with open(HISTORY_CSV_PATH, "w") as f:
                f.writelines(lines)
            print(
                f"Upgraded stale trend.csv header ({old_header!r} -> "
                f"{HISTORY_CSV_HEADER!r}); historical data rows left untouched."
            )

    with open(HISTORY_CSV_PATH, "a") as f:
        if is_new:
            f.write(HISTORY_CSV_HEADER + "\n")
        f.write(",".join(row) + "\n")
    print(f"Appended trend row to {HISTORY_CSV_PATH}")


# ---------------------------------------------------------------------------
# New-KEV alert feed -- diffs the current KEV catalog against the previous
# run's snapshot (docs/data/kev_snapshot.json) and writes any newly-added CVE
# IDs to a static feed.json + feed.xml (RSS 2.0) that anyone can poll or
# subscribe to with a free reader (no webhook/server infrastructure needed).
# Note: this is ALL KEV additions, not filtered to the watchlist -- it's a
# general "what's new in KEV" feed, distinct from the watchlist-scoped GitHub
# Issues notifications.
# ---------------------------------------------------------------------------
def build_kev_feed(kev_map):
    snapshot_existed = os.path.exists(KEV_SNAPSHOT_PATH)
    prior_ids = set(load_json_file(KEV_SNAPSHOT_PATH, []))
    current_ids = set(kev_map.keys())

    if not snapshot_existed:
        # First run ever: there is no real "prior" baseline, so every KEV
        # entry would otherwise look "new" and flood the feed with 1000+
        # items. Seed the baseline silently instead of alerting on it.
        print(f"KEV feed: no prior snapshot found -- seeding baseline of {len(current_ids)} "
              f"KEV entries without generating feed items.")
        save_json_file(KEV_SNAPSHOT_PATH, sorted(current_ids))
        new_ids = []
    else:
        new_ids = sorted(current_ids - prior_ids)
        if new_ids:
            print(f"KEV feed: {len(new_ids)} newly-added KEV entr{'y' if len(new_ids) == 1 else 'ies'}")
        save_json_file(KEV_SNAPSHOT_PATH, sorted(current_ids))

    existing_feed = load_json_file(FEED_JSON_PATH, {"version": "https://jsonfeed.org/version/1",
                                                       "title": "New CISA KEV Entries", "items": []})
    if not isinstance(existing_feed, dict) or not isinstance(existing_feed.get("items"), list):
        existing_feed = {"version": "https://jsonfeed.org/version/1",
                          "title": "New CISA KEV Entries", "items": []}

    now_iso = datetime.now(timezone.utc).isoformat()
    existing_by_id = {item.get("id"): item for item in existing_feed["items"] if isinstance(item, dict)}
    for cve_id in new_ids:
        kev_entry = kev_map.get(cve_id, {})
        existing_by_id[cve_id] = {
            "id": cve_id,
            "title": f"{cve_id}: {kev_entry.get('vulnerabilityName', 'New KEV entry')}",
            "content_text": kev_entry.get("shortDescription", ""),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "date_published": now_iso,
            "_kev_date_added": kev_entry.get("dateAdded"),
            "_kev_due_date": kev_entry.get("dueDate"),
            "_kev_vendor_project": kev_entry.get("vendorProject"),
            "_kev_product": kev_entry.get("product"),
            "_kev_ransomware_use": kev_entry.get("knownRansomwareCampaignUse") == "Known",
        }
    # Keep the feed bounded (most recent 200 entries by date_published) so the
    # JSON/XML files don't grow unbounded over years of runs.
    all_items = sorted(existing_by_id.values(), key=lambda i: i.get("date_published", ""), reverse=True)[:200]
    existing_feed["items"] = all_items
    existing_feed["home_page_url"] = SITE_URL
    existing_feed["feed_url"] = SITE_URL + "feed.json"
    existing_feed["description"] = "Newly-added CISA Known Exploited Vulnerabilities (all KEV, not watchlist-filtered)."
    save_json_file(FEED_JSON_PATH, existing_feed)

    # RSS 2.0 mirror of the same items for feed readers that prefer XML.
    def esc(s):
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    rss_items = "\n".join(
        f"    <item>\n"
        f"      <title>{esc(item.get('title'))}</title>\n"
        f"      <link>{esc(item.get('url'))}</link>\n"
        f"      <guid isPermaLink=\"false\">{esc(item.get('id'))}</guid>\n"
        f"      <pubDate>{esc(item.get('date_published'))}</pubDate>\n"
        f"      <description>{esc(item.get('content_text'))}</description>\n"
        f"    </item>"
        for item in all_items
    )
    rss = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0"><channel>\n'
        f"  <title>New CISA KEV Entries</title>\n"
        f"  <link>{SITE_URL}</link>\n"
        f"  <description>Newly-added CISA Known Exploited Vulnerabilities.</description>\n"
        f"{rss_items}\n"
        "</channel></rss>\n"
    )
    with open(FEED_XML_PATH, "w") as f:
        f.write(rss)
    print(f"Wrote KEV feed: {len(all_items)} items to {FEED_JSON_PATH} and {FEED_XML_PATH}")


def main():
    nvd_api_key = os.environ.get("NVD_API_KEY", "").strip() or None
    gh_token = os.environ.get("GH_DEPENDABOT_TOKEN", "").strip() or None

    watchlist = load_watchlist()
    suppressions = load_suppressions()
    if suppressions:
        print(f"Loaded {len(suppressions)} active suppression(s) from config/suppressions.yaml")

    kev_map = fetch_kev()
    nvd_candidates = fetch_nvd_candidates(watchlist, nvd_api_key)
    dependabot_candidates = fetch_dependabot_alerts(watchlist["dependabot_repos"], gh_token)
    ghsa_candidates = fetch_ghsa_advisories(watchlist["ghsa_packages"], gh_token)

    all_candidates = list(nvd_candidates.values()) + dependabot_candidates + ghsa_candidates
    all_cve_ids = {c["cve_id"] for c in all_candidates if c.get("cve_id") and c["cve_id"].startswith("CVE-")}

    existing_alerts = load_json_file(ALERTS_PATH, [])
    existing_by_key = {unique_key(a): a for a in existing_alerts}
    seen_ids = set(load_json_file(SEEN_PATH, []))

    # Also refresh EPSS/KEV for CVEs already tracked on the dashboard even if this
    # run's NVD lookback window (default 8 days) or Dependabot/GHSA results didn't
    # resurface them -- otherwise epss_score (40% of risk_score) and kev status would
    # silently freeze forever the moment a CVE ages out of the lookback window, even
    # though EPSS publishes new scores daily and KEV catalog additions are unrelated
    # to when NVD last modified the CVE record.
    all_cve_ids |= {a["cve_id"] for a in existing_alerts
                    if a.get("cve_id", "").startswith("CVE-")}
    epss_map = fetch_epss(all_cve_ids) if all_cve_ids else {}

    filtered = [c for c in all_candidates
                if c.get("cve_id") and passes_filters(c, watchlist, kev_map, epss_map, suppressions)]
    print(f"After filtering: {len(filtered)} matches")

    new_alerts = []
    touched_keys = set()
    for c in filtered:
        key = unique_key(c)
        touched_keys.add(key)
        final = build_final_entry(c, kev_map, epss_map)
        if key not in seen_ids:
            new_alerts.append(final)
            seen_ids.add(key)
            existing_by_key[key] = final
        else:
            # Already known: keep the original first_seen, but refresh scores in case
            # CVSS/EPSS/KEV status changed since we first saw it. Also record the
            # risk_score this alert carried *before* this refresh (risk_score_prev) so
            # the dashboard can show a delta -- otherwise every run silently overwrites
            # risk_score in place (EPSS/KEV refresh, cycle 6) with zero visibility into
            # whether a CVE just got materially more or less urgent since an analyst
            # last looked at it.
            prior = existing_by_key.get(key, final)
            merged = {**final, "first_seen": prior.get("first_seen", final["first_seen"]),
                      "risk_score_prev": prior.get("risk_score")}
            existing_by_key[key] = merged

    # Existing alerts not resurfaced by this run (outside the NVD lookback window,
    # or no longer returned by Dependabot/GHSA) still get their EPSS/KEV/risk_score
    # refreshed in place -- same fields build_final_entry would set, but leaving
    # every other field (description, cvss_score, source, first_seen, affected, ...)
    # untouched since this run has no fresher data for them.
    for key, prior in existing_by_key.items():
        if key in touched_keys:
            continue
        cve_id = prior.get("cve_id", "")
        if not cve_id.startswith("CVE-"):
            continue
        in_kev = cve_id in kev_map
        kev_entry = kev_map.get(cve_id, {})
        epss_info = epss_map.get(cve_id, {})
        epss_score = epss_info.get("epss")
        risk_score, risk_breakdown = composite_risk_score(prior.get("cvss_score"), epss_score, in_kev)
        prior["risk_score_prev"] = prior.get("risk_score")
        prior["epss_score"] = epss_score
        prior["epss_percentile"] = epss_info.get("percentile")
        prior["kev"] = in_kev
        prior["kev_date_added"] = kev_entry.get("dateAdded") if in_kev else None
        prior["kev_due_date"] = kev_entry.get("dueDate") if in_kev else None
        prior["kev_ransomware_use"] = (kev_entry.get("knownRansomwareCampaignUse") == "Known") if in_kev else False
        prior["kev_required_action"] = kev_entry.get("requiredAction") if in_kev else None
        prior["kev_notes"] = kev_entry.get("notes") if in_kev else None
        prior["risk_score"] = risk_score
        prior["risk_score_breakdown"] = risk_breakdown

    # Suppressed entries that were previously alerted should also disappear from the
    # cumulative view going forward (an analyst explicitly accepted the risk) -- but
    # their seen_id stays recorded so they don't silently reappear as "new" the moment
    # the suppression expires; they'll re-enter the normal filter/dedup path instead.
    existing_by_key = {k: v for k, v in existing_by_key.items() if v.get("cve_id") not in suppressions}

    cumulative = sorted(existing_by_key.values(), key=lambda a: a.get("first_seen", ""), reverse=True)
    stats = compute_stats(cumulative)

    save_json_file(ALERTS_PATH, cumulative)
    save_json_file(SEEN_PATH, sorted(seen_ids))
    save_json_file(NEW_ALERTS_PATH, new_alerts)
    save_json_file(STATS_PATH, stats)
    append_history(stats)
    build_kev_feed(kev_map)

    print(f"Wrote {len(cumulative)} total alerts to {ALERTS_PATH}")
    print(f"Wrote {len(new_alerts)} NEW alerts to {NEW_ALERTS_PATH}")
    print(f"Wrote stats to {STATS_PATH}: {stats}")

    # Emit for GitHub Actions step output
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a") as f:
            f.write(f"new_alert_count={len(new_alerts)}\n")


if __name__ == "__main__":
    main()
