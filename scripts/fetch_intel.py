#!/usr/bin/env python3
"""Ingest free public security news / advisory RSS+Atom feeds into
docs/data/intel.json -- the dashboard's "Threat intel" board.

Why this exists: the CVE pipeline (aggregate.py) only sees what NVD, CISA KEV,
GHSA and Dependabot publish. That structurally misses three kinds of intel an
L1 SOC needs:
  * social-engineering campaigns with no CVE at all (e.g. Microsoft Teams
    "IT support" vishing that leads to Quick Assist / RMM installs);
  * vendor operational issues (e.g. a Windows update causing black screens);
  * news that a CVE is exploited *before* CISA adds it to KEV.

Design rules (accuracy over breadth):
  * Nothing is generated or summarised -- every field is copied from the feed
    item (title, link, date, first ~400 chars of its own summary) and every
    tag is a deterministic regex hit that the UI can explain.
  * CVE ids are only those literally present in the item text.
  * A feed that fails is logged and skipped; already-collected items persist
    until they age out, so one bad run never blanks the board.
  * Zero cost: stdlib + PyYAML only, runs inside the existing Actions job.
"""
import hashlib
import html
import json
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEEDS_PATH = os.path.join(REPO_ROOT, "config", "intel_feeds.yaml")
WATCHLIST_PATH = os.path.join(REPO_ROOT, "config", "watchlist.yaml")
INTEL_PATH = os.path.join(REPO_ROOT, "docs", "data", "intel.json")
# Plain UA on purpose: Cloudflare-fronted feeds (cybersecuritynews, gbhackers)
# 403 a UA carrying "compatible;" / a "+https://" contact URL.
USER_AGENT = "Mozilla/5.0 cve-dashboard"
MAX_BYTES = 5 * 1024 * 1024
SUMMARY_CHARS = 400

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)

# Category rules: (key, label, regex). Matched against title + summary.
CATEGORY_RULES = [
    ("exploited", "Actively exploited",
     r"(?<!could be )(?<!can be )(?<!may be )(?<!to be )(?<!if )\bexploited\b|actively exploited|exploited in (?:the wild|attacks)|in[- ]the[- ]wild|zero[- ]days?\b|\b0[- ]?day\b|"
     r"under (?:active )?attack|exploitation (?:attempts|activity)|known exploited|mass[- ]exploit"),
    ("social_engineering", "Social engineering",
     r"phish|vishing|smishing|social[- ]engineer|impersonat|fake (?:it|help ?desk|tech|support|captcha)|"
     r"\bit support\b|help ?desk|tech support scam|quick assist|clickfix|callback scam|"
     r"(?:microsoft )?teams (?:call|message|chat|phish|scam)|via microsoft teams|over microsoft teams|"
     r"mfa fatigue|mfa bombing|consent phish|business email compromise|\bBEC\b|malvertis|"
     r"seo poison|lure|scam"),
    ("vendor_issue", "Vendor / update issue",
     r"black screen|blue screen|\bBSOD\b|crash(?:es|ing)?\b|outage|known issue|bug (?:causing|that|breaks)|"
     r"(?:update|patch) (?:may |could |will )?break|breaks? (?:windows|sign-?in|log-?in|boot|vpn|printing|apps?|outlook|teams)|boot ?loop|fails? to (?:boot|install|start|load)|roll(?:s|ed)? back|"
     r"pull(?:s|ed)? (?:the )?(?:update|patch)|update (?:issue|problem)s?|emergency (?:update|fix)|"
     r"out[- ]of[- ]band|service disruption|degraded"),
    ("patch", "Patch / advisory",
     r"patch tuesday|security update|security advisory|\bpatch(?:es|ed)?\b|\bfix(?:es|ed)?\b .*?(?:flaw|vuln|bug)|"
     r"hotfix|advisory|bulletin"),
    ("identity", "Identity",
     r"\bAD FS\b|\bADFS\b|active directory|\bentra\b|azure ad|\bokta\b|kerberos|\bNTLM\b|single sign-on|"
     r"\bSSO\b|federation|token theft|session (?:hijack|token)|mfa bypass|identity provider|\bSAML\b|OAuth"),
    ("ransomware", "Ransomware", r"ransomware|extortion|data leak site"),
    ("vulnerability", "Vulnerability",
     r"vulnerab|\bflaw\b|\bRCE\b|remote code execution|privilege escalation|security bypass|"
     r"command injection|authentication bypass"),
]
CATEGORY_RES = [(k, l, re.compile(p, re.I)) for k, l, p in CATEGORY_RULES]
CATEGORY_LABELS = {k: l for k, l, _ in CATEGORY_RULES}

WEIGHTS = {"exploited": 40, "social_engineering": 20, "identity": 15, "vendor_issue": 10,
           "ransomware": 10, "patch": 10, "vulnerability": 5}
WATCH_BONUS = 25


def log(msg):
    print(msg, file=sys.stderr if msg.startswith("  WARN") else sys.stdout)


def load_yaml(path, default):
    try:
        with open(path) as f:
            return yaml.safe_load(f) or default
    except FileNotFoundError:
        return default


# Generic watchlist words that would match nearly every article.
_STOP_TERMS = {"server", "client", "api", "core", "web", "app", "cloud", "security", "management",
               "system", "service", "services", "platform", "content management system", "remote"}


def watch_terms(watchlist):
    """Vendor/product/keyword terms from config/watchlist.yaml, normalised.
    Used only to flag relevance ("matches your watchlist"), never to drop items."""
    terms = set()
    for vp in watchlist.get("vendors_products", []) or []:
        if isinstance(vp, dict):
            for key in ("vendor", "product"):
                v = str(vp.get(key) or "").replace("_", " ").strip()
                if v:
                    terms.add(v.lower())
        elif isinstance(vp, str):
            for part in re.split(r"[:/]", vp):
                part = part.replace("_", " ").strip()
                if part:
                    terms.add(part.lower())
    for key in ("keywords", "priority_keywords"):
        for kw in watchlist.get(key, []) or []:
            terms.add(str(kw).lower().strip())
    # SOC stack explicitly called out (email: Avanan/Check Point; perimeter: PAN/Fortinet).
    # "microsoft teams", not bare "teams" (matches every "security teams").
    terms |= {"microsoft", "windows", "microsoft teams", "avanan", "check point", "palo alto", "fortinet",
              "sumo logic", "azure", "office 365", "microsoft 365", "outlook", "exchange"}
    return sorted(t for t in terms if len(t) >= 3 and t not in _STOP_TERMS)


def compile_watch(terms):
    return [(t, re.compile(r"(?<![\w-])" + re.escape(t) + r"(?![\w-])", re.I)) for t in terms]


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("feed larger than 5 MB")
    return data


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def clean_text(s):
    s = html.unescape(_TAG_RE.sub(" ", s or ""))
    s = html.unescape(s)  # double-escaped feeds (&amp;amp;)
    return _WS_RE.sub(" ", s).strip()


def parse_date(s):
    s = (s or "").strip()
    if not s:
        return None
    try:
        d = parsedate_to_datetime(s)
    except (TypeError, ValueError):
        d = None
    if d is None:
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def _local(tag):
    return tag.rsplit("}", 1)[-1].lower()


def _child_text(el, *names):
    for c in el:
        if _local(c.tag) in names:
            if _local(c.tag) == "link" and not (c.text or "").strip():
                href = c.get("href")
                if href and c.get("rel", "alternate") == "alternate":
                    return href
                continue
            return "".join(c.itertext())
    return ""


def _regex_items(text):
    """Fallback for feeds that are not well-formed XML (seen in the wild:
    unescaped '&' in titles). Pull <item>/<entry> blocks with regexes."""
    out = []
    for block in re.findall(r"<(?:item|entry)\b.*?</(?:item|entry)>", text, re.S | re.I):
        def grab(name):
            m = re.search(rf"<{name}\b[^>]*>(.*?)</{name}>", block, re.S | re.I)
            v = m.group(1) if m else ""
            return re.sub(r"^<!\[CDATA\[|\]\]>$", "", v.strip(), flags=re.S)
        link = grab("link")
        if not link:
            m = re.search(r"<link\b[^>]*href=\"([^\"]+)\"", block, re.I)
            link = m.group(1) if m else ""
        out.append({"title": grab("title"), "link": link,
                    "date": grab("pubDate") or grab("published") or grab("updated") or grab("dc:date"),
                    "summary": grab("description") or grab("summary") or grab("content:encoded") or grab("content")})
    return out


def parse_feed(data):
    text = data.decode("utf-8", errors="replace")
    # Refuse DTD/entity declarations outright (billion-laughs / XXE hardening
    # without adding a defusedxml dependency). Real news feeds never need them.
    if re.search(r"<!(?:DOCTYPE|ENTITY)", text[:4096], re.I):
        raise ValueError("feed declares a DTD/entities; refused")
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return _regex_items(text)
    out = []
    for el in root.iter():
        if _local(el.tag) not in ("item", "entry"):
            continue
        out.append({
            "title": _child_text(el, "title"),
            "link": _child_text(el, "link") or _child_text(el, "guid", "id"),
            "date": _child_text(el, "pubdate", "published", "updated", "date"),
            "summary": _child_text(el, "description", "summary", "encoded", "content"),
        })
    return out


def classify(text, watch_res):
    cats = [k for k, _, rx in CATEGORY_RES if rx.search(text)]
    watch = []
    for term, rx in watch_res:
        if rx.search(text) and term not in watch:
            watch.append(term)
    cves = []
    for m in CVE_RE.finditer(text):
        cid = f"CVE-{m.group(1)}-{m.group(2)}"
        if cid not in cves:
            cves.append(cid)
    return cats, watch, cves


def score_item(cats, watch, cves):
    score = sum(WEIGHTS.get(c, 0) for c in cats)
    if watch:
        score += WATCH_BONUS
        # A vendor/update problem or SE campaign on a product we run is
        # directly actionable (e.g. Windows black screen after an update).
        if "vendor_issue" in cats or "social_engineering" in cats:
            score += 15
    if cves:
        score += 5
    return min(score, 100)


def priority_label(score):
    return "high" if score >= 60 else "medium" if score >= 30 else "low"


def item_id(link, title):
    key = (link or "").split("#")[0].rstrip("/").lower() or re.sub(r"\W+", " ", (title or "").lower()).strip()
    return hashlib.sha1(key.encode()).hexdigest()[:16]


def norm_title(t):
    return re.sub(r"[^a-z0-9]+", " ", (t or "").lower()).strip()


def build_item(raw, feed_name, watch_res, now):
    title = clean_text(raw.get("title"))
    link = (raw.get("link") or "").strip()
    if not title or not link.startswith(("https://", "http://")):
        return None
    summary = clean_text(raw.get("summary"))
    if len(summary) > SUMMARY_CHARS:
        summary = summary[:SUMMARY_CHARS].rsplit(" ", 1)[0] + "…"
    published = parse_date(raw.get("date"))
    if published and published > now + timedelta(hours=6):
        published = None  # never trust future-dated items
    cats, watch, cves = classify(f"{title}\n{summary}", watch_res)
    if not cats and not watch and not cves:
        return None
    score = score_item(cats, watch, cves)
    return {
        "id": item_id(link, title),
        "title": title,
        "link": link,
        "source": feed_name,
        "published": published.isoformat() if published else None,
        "summary": summary,
        "categories": cats,
        "watch_matches": watch,
        "cve_ids": cves,
        "score": score,
        "priority": priority_label(score),
    }


def merge(existing, fresh, now, retention_days, max_items):
    """Existing items are kept (and re-classified by the caller); fresh items
    win on id collision. Same story syndicated by several outlets is grouped
    by normalised title so it appears once with `also_reported_by`."""
    by_id = {i["id"]: i for i in existing if isinstance(i, dict) and i.get("id")}
    for i in fresh:
        prev = by_id.get(i["id"])
        i["first_seen"] = (prev or {}).get("first_seen") or now.isoformat()
        by_id[i["id"]] = i
    cutoff = now - timedelta(days=retention_days)

    def when(i):
        d = parse_date(i.get("published") or "") or parse_date(i.get("first_seen") or "")
        return d or now

    kept = [i for i in by_id.values() if when(i) >= cutoff]
    by_title = {}
    for i in sorted(kept, key=when):
        key = norm_title(i["title"])
        if key in by_title:
            first = by_title[key]
            if i["source"] != first["source"] and i["source"] not in first.setdefault("also_reported_by", []):
                first["also_reported_by"].append(i["source"])
            continue
        by_title[key] = i
    out = sorted(by_title.values(), key=lambda i: (when(i), i["score"]), reverse=True)
    return out[:max_items]


def main():
    now = datetime.now(timezone.utc)
    cfg = load_yaml(FEEDS_PATH, {})
    feeds = cfg.get("feeds", [])
    retention = int(cfg.get("retention_days", 30))
    max_items = int(cfg.get("max_items", 600))
    watch_res = compile_watch(watch_terms(load_yaml(WATCHLIST_PATH, {})))

    try:
        with open(INTEL_PATH) as f:
            prev = json.load(f)
        existing = prev.get("items", []) if isinstance(prev, dict) else []
    except (FileNotFoundError, json.JSONDecodeError):
        existing = []

    # Re-classify retained items so rule/watchlist changes apply retroactively.
    for i in existing:
        cats, watch, cves = classify(f"{i.get('title', '')}\n{i.get('summary', '')}", watch_res)
        i.update(categories=cats, watch_matches=watch, cve_ids=cves)
        i["score"] = score_item(cats, watch, cves)
        i["priority"] = priority_label(i["score"])
        i.pop("also_reported_by", None)
    existing = [i for i in existing if i.get("categories") or i.get("watch_matches") or i.get("cve_ids")]

    fresh, feed_status = [], []
    for feed in feeds:
        name, url = feed.get("name"), feed.get("url")
        if not name or not url:
            continue
        try:
            raws = parse_feed(fetch(url))
            items = [b for b in (build_item(r, name, watch_res, now) for r in raws) if b]
            fresh.extend(items)
            feed_status.append({"name": name, "ok": True, "items": len(raws), "kept": len(items)})
            log(f"  {name}: {len(raws)} items, {len(items)} kept")
        except Exception as e:  # one broken feed must never fail the run
            feed_status.append({"name": name, "ok": False, "error": str(e)[:160]})
            log(f"  WARN {name}: {e}")

    if feeds and not any(s["ok"] for s in feed_status):
        log("  WARN every intel feed failed this run -- keeping previous intel.json untouched")
        return 0

    items = merge(existing, fresh, now, retention, max_items)
    out = {
        "generated_at": now.isoformat(),
        "category_labels": CATEGORY_LABELS,
        "feeds": feed_status,
        "items": items,
    }
    tmp = INTEL_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, INTEL_PATH)
    log(f"intel.json: {len(items)} items from {sum(s['ok'] for s in feed_status)}/{len(feed_status)} feeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
