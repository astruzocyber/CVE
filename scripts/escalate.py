#!/usr/bin/env python3
"""Environment-aware triage: decide which CVE alerts and threat-intel items
are WORK or ESCALATE *for this estate* (config/environment.yaml).

Reads  docs/data/alerts.json + docs/data/intel.json
Writes docs/data/escalations.json  (consumed by docs/js/escalations.js and
                                    scripts/notify_discord.py)

Deterministic rules only. An item is tiered only if one of the estate's asset
terms appears literally (whole word/phrase, case-insensitive) in the item's
own text -- for CVEs the NVD description / affected packages, for news the
title + summary. Watchlist query labels (matched_keywords) are NOT used as
evidence, because NVD's keywordSearch AND-matches words and produces loose
hits (e.g. "Check Point" matching any text containing "check" and "point").
Every tier carries the literal reasons that produced it.

Tiers
  escalate  in-estate AND (CISA KEV | ransomware use | news-reported exploited
            | EPSS >= escalate_epss | CVSS >= escalate_cvss, network vector,
            on a critical asset)
            in-estate news on a critical/high asset that is exploited /
            ransomware / social engineering
  work      in-estate CVE with CVSS >= work_cvss[criticality] or a
            priority-keyword hit
            any other in-estate news with a category, or an
            exploited/social-engineering item on a medium asset
"""
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(ROOT, "config", "environment.yaml")
WATCHLIST_PATH = os.path.join(ROOT, "config", "watchlist.yaml")
ALERTS_PATH = os.path.join(ROOT, "docs", "data", "alerts.json")
INTEL_PATH = os.path.join(ROOT, "docs", "data", "intel.json")
OUT_PATH = os.path.join(ROOT, "docs", "data", "escalations.json")

TIER_RANK = {"escalate": 0, "work": 1}
CRIT_RANK = {"critical": 0, "high": 1, "medium": 2}
HOT_INTEL = {"exploited", "ransomware", "social_engineering"}


def load_priority_terms(path=WATCHLIST_PATH):
    """watchlist.yaml priority_keywords (the terms that bypass the CVSS floor)."""
    try:
        with open(path, encoding="utf-8") as fh:
            wl = yaml.safe_load(fh) or {}
    except OSError:
        return []
    return [str(t).strip() for t in wl.get("priority_keywords") or [] if str(t).strip()]


def load_env(path=ENV_PATH, priority_terms=None):
    with open(path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    assets = []
    for a in cfg.get("assets") or []:
        terms = [str(t).strip() for t in (a.get("terms") or []) if str(t).strip()]
        if not a.get("name") or not terms:
            continue
        crit = str(a.get("criticality", "medium")).lower()
        if crit not in CRIT_RANK:
            crit = "medium"
        # longest first so the reported hit is the most specific phrase
        terms.sort(key=len, reverse=True)
        pat = re.compile(r"(?<![\w-])(?:" + "|".join(re.escape(t) for t in terms) + r")(?![\w-])",
                         re.IGNORECASE)
        excl = [str(t).strip() for t in (a.get("exclude") or []) if str(t).strip()]
        xpat = re.compile("|".join(re.escape(t) for t in excl), re.IGNORECASE) if excl else None
        assets.append({"name": a["name"], "criticality": crit, "re": pat, "exclude": xpat})
    win = cfg.get("window_days") or {}
    th = cfg.get("thresholds") or {}
    pt = load_priority_terms() if priority_terms is None else priority_terms
    return {
        "assets": assets,
        "priority_re": (re.compile(r"(?<![\w-])(?:" + "|".join(re.escape(t) for t in pt) + r")(?![\w-])",
                                   re.IGNORECASE) if pt else None),
        "cve_days": int(win.get("cve", 14)),
        "intel_days": int(win.get("intel", 7)),
        "work_cvss": {k: float(v) for k, v in {**{"critical": 7.0, "high": 8.8, "medium": 9.8},
                                                **(th.get("work_cvss") or {})}.items()},
        "escalate_cvss": float(th.get("escalate_cvss", 9.0)),
        "escalate_epss": float(th.get("escalate_epss", 0.5)),
    }


def match_assets(text, assets):
    """[(asset, matched_term)] for every asset whose term appears in text."""
    hits = []
    for a in assets:
        m = a["re"].search(text or "")
        if m and not (a["exclude"] and a["exclude"].search(text or "")):
            hits.append((a, m.group(0)))
    return hits


def _dt(value):
    if not value:
        return None
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        try:
            d = datetime.strptime(str(value)[:10], "%Y-%m-%d")
        except ValueError:
            return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _hits_desc(hits):
    return "; ".join(f"{a['name']} (\"{term}\")" for a, term in hits)


def classify_alert(alert, env):
    text = " ".join([alert.get("description") or ""] + [str(x) for x in alert.get("affected") or []])
    hits = match_assets(text, env["assets"])
    if not hits:
        return None
    best = min(CRIT_RANK[a["criticality"]] for a, _ in hits)
    cvss, epss = _num(alert.get("cvss_score")), _num(alert.get("epss_score"))
    av = ((alert.get("cvss_vector_components") or {}).get("attack_vector") or "").upper()
    kws = alert.get("matched_keywords") or []
    esc, work = [], []
    if alert.get("kev"):
        esc.append(f"CISA KEV: actively exploited (added {alert.get('kev_date_added') or '?'}, "
                   f"federal due date {alert.get('kev_due_date') or '?'})")
    if alert.get("kev_ransomware_use"):
        esc.append("CISA KEV: known ransomware use")
    if "news: reported exploited" in kws:
        esc.append("Security news reports this CVE as exploited")
    if epss is not None and epss >= env["escalate_epss"]:
        esc.append(f"EPSS {epss:.2f} >= {env['escalate_epss']} (high exploitation likelihood)")
    if cvss is not None and cvss >= env["escalate_cvss"] and av == "NETWORK" and best == 0:
        esc.append(f"CVSS {cvss} network-reachable on a critical asset")
    crit = min((a["criticality"] for a, _ in hits), key=lambda c: CRIT_RANK[c])
    floor = env["work_cvss"].get(crit, 7.0)
    if cvss is not None and cvss >= floor:
        work.append(f"CVSS {cvss} >= {floor} work threshold for a {crit} asset")
    pm = env.get("priority_re") and env["priority_re"].search(alert.get("description") or "")
    if pm:
        work.append(f"Priority watch term \"{pm.group(0)}\" (any CVSS)")
    if not esc and not work:
        return None
    tier = "escalate" if esc else "work"
    cid = alert.get("cve_id")
    return {
        "key": f"cve:{cid}",
        "kind": "cve",
        "ref": cid,
        "title": f"{cid}: {(alert.get('description') or '').strip()[:220]}",
        "link": f"#{cid}",
        "date": alert.get("kev_date_added") or alert.get("first_seen"),
        "tier": tier,
        "assets": sorted({a["name"] for a, _ in hits}),
        "criticality": min((a["criticality"] for a, _ in hits), key=lambda c: CRIT_RANK[c]),
        "reasons": [f"In your estate: {_hits_desc(hits)}"] + esc + work,
        "score": _num(alert.get("risk_score")) or 0,
        "cvss": cvss,
        "kev": bool(alert.get("kev")),
    }


def classify_intel(item, env, labels):
    hits = match_assets(f"{item.get('title') or ''} {item.get('summary') or ''}", env["assets"])
    if not hits:
        return None
    cats = list(item.get("categories") or [])
    if not cats and item.get("priority") != "high":
        return None
    best = min(CRIT_RANK[a["criticality"]] for a, _ in hits)
    hot = [c for c in cats if c in HOT_INTEL]
    reasons = [f"In your estate: {_hits_desc(hits)}"]
    if cats:
        reasons.append("Category: " + ", ".join(labels.get(c, c) for c in cats))
    if item.get("priority") == "high":
        reasons.append(f"High news priority (rule score {item.get('score')})")
    if item.get("cve_ids"):
        reasons.append("Names " + ", ".join(item["cve_ids"][:5]))
    if hot and (best <= CRIT_RANK["high"] or "exploited" in hot):
        tier = "escalate"
    else:
        tier = "work"
    return {
        "key": f"intel:{item.get('id')}",
        "kind": "intel",
        "ref": item.get("id"),
        "title": item.get("title") or "",
        "link": item.get("link") or "",
        "source": item.get("source"),
        "date": item.get("published") or item.get("first_seen"),
        "tier": tier,
        "assets": sorted({a["name"] for a, _ in hits}),
        "criticality": min((a["criticality"] for a, _ in hits), key=lambda c: CRIT_RANK[c]),
        "reasons": reasons,
        "score": _num(item.get("score")) or 0,
        "categories": cats,
        "cve_ids": item.get("cve_ids") or [],
    }


def build(alerts, intel, env, now=None):
    now = now or datetime.now(timezone.utc)
    cve_cut = now - timedelta(days=env["cve_days"])
    intel_cut = now - timedelta(days=env["intel_days"])
    out = []
    for a in alerts or []:
        if a.get("vuln_status") == "Rejected":
            continue
        # Relevance = when the CVE was published or CISA flagged it, NOT when this
        # dashboard first saw it (a backfill would otherwise resurface 2019 CVEs).
        dates = [d for d in (_dt(a.get("published")), _dt(a.get("kev_date_added"))) if d]
        if not dates or max(dates) < cve_cut:
            continue
        r = classify_alert(a, env)
        if r:
            out.append(r)
    labels = (intel or {}).get("category_labels") or {}
    for it in (intel or {}).get("items") or []:
        d = _dt(it.get("published")) or _dt(it.get("first_seen"))
        if not d or d < intel_cut:
            continue
        r = classify_intel(it, env, labels)
        if r:
            out.append(r)
    out.sort(key=lambda r: (TIER_RANK[r["tier"]], CRIT_RANK[r["criticality"]], -(r["score"] or 0),
                            r["key"]))
    return {
        "generated_at": now.isoformat(),
        "window_days": {"cve": env["cve_days"], "intel": env["intel_days"]},
        "assets": [{"name": a["name"], "criticality": a["criticality"]} for a in env["assets"]],
        "counts": {t: sum(1 for r in out if r["tier"] == t) for t in TIER_RANK},
        "items": out,
    }


def _load(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def main():
    if not os.path.exists(ENV_PATH):
        print("config/environment.yaml missing -- escalation board disabled.")
        return 0
    env = load_env()
    result = build(_load(ALERTS_PATH, []), _load(INTEL_PATH, {}), env)
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    c = result["counts"]
    print(f"Escalations: {c['escalate']} escalate, {c['work']} work "
          f"(CVE window {env['cve_days']}d, intel window {env['intel_days']}d)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
