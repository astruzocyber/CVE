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
TRIAGE_PATH = os.path.join(ROOT, "config", "triage.yaml")

TIER_RANK = {"escalate": 0, "work": 1}
CRIT_RANK = {"critical": 0, "high": 1, "medium": 2}
HOT_INTEL = {"exploited", "ransomware", "social_engineering"}
# Shared team triage (config/triage.yaml, edited in the GitHub web UI).
TRIAGE_STATUSES = {"acknowledged", "in_progress", "escalated", "resolved", "false_positive",
                   "accepted_risk"}
CLOSED_STATUSES = {"resolved", "false_positive", "accepted_risk"}


def load_triage(path=TRIAGE_PATH):
    """{key: {status, owner, note, date}} from config/triage.yaml. Unknown
    statuses are dropped (printed) rather than guessed."""
    try:
        with open(path, encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
    except OSError:
        return {}
    except yaml.YAMLError as e:
        # keep the board running; validate_data.py fails CI on the same typo
        print(f"WARNING: config/triage.yaml is not valid YAML, triage ignored: {e}")
        return {}
    if not isinstance(cfg, dict) or not isinstance(cfg.get("entries") or {}, dict):
        print("WARNING: config/triage.yaml 'entries' must be a mapping, triage ignored")
        return {}
    out = {}
    for key, v in (cfg.get("entries") or {}).items():
        if not isinstance(v, dict):
            continue
        status = str(v.get("status") or "").strip().lower()
        if status not in TRIAGE_STATUSES:
            print(f"triage.yaml: ignoring {key!r} -- unknown status {status!r}")
            continue
        out[str(key).strip()] = {
            "status": status,
            "owner": str(v.get("owner") or "").strip(),
            "note": str(v.get("note") or "").strip(),
            "date": str(v.get("date") or "").strip(),
        }
    return out


def load_priority_terms(path=WATCHLIST_PATH):
    """watchlist.yaml priority_keywords (the terms that bypass the CVSS floor)."""
    try:
        with open(path, encoding="utf-8") as fh:
            wl = yaml.safe_load(fh) or {}
    except OSError:
        return []
    return [str(t).strip() for t in wl.get("priority_keywords") or [] if str(t).strip()]


# Generic security-news vocabulary: sharing these says nothing about being the same incident.
_GENERIC = set("""
about after again against alert alerts allow allows amid analysis attack attackers attacks being bypass
bypasses campaign check checks critical customers cyber data details disclosed discovered exploit
exploitation exploited exploits files firms fixes flaw flaws hacker hackers hits impact including
issue issues just latest malicious malware million more news over patch patched patches patching
people report reports research researchers security servers service steal than that their them these
threat threats through under update updates urged used users using vulnerabilities vulnerability warn
warning warns week what when where which while with without zero-day zero-days zeroday active actively
remote code execution severity high medium critical october november september release new year
""".split())


def _words(text):
    return {w.strip("-") for w in re.split(r"[^a-z0-9-]+", (text or "").lower())
            if len(w.strip("-")) >= 4 and not w.strip("-").isdigit()}


def load_env(path=ENV_PATH, priority_terms=None):
    with open(path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    assets, vendor_words = [], set()
    for a in cfg.get("assets") or []:
        terms = [str(t).strip() for t in (a.get("terms") or []) if str(t).strip()]
        if not a.get("name") or not terms:
            continue
        crit = str(a.get("criticality", "medium")).lower()
        if crit not in CRIT_RANK:
            crit = "medium"
        # longest first so the reported hit is the most specific phrase
        terms.sort(key=len, reverse=True)
        flags = 0 if a.get("match_case") else re.IGNORECASE
        # boundaries also reject URL/hostname context ("https://github.com/x" is a
        # reference link, not a GitHub product CVE)
        pat = re.compile(r"(?<![\w./-])(?:" + "|".join(re.escape(t) for t in terms) + r")(?![\w-]|\.\w)",
                         flags)
        excl = [str(t).strip() for t in (a.get("exclude") or []) if str(t).strip()]
        xpat = re.compile("|".join(re.escape(t) for t in excl), re.IGNORECASE) if excl else None
        assets.append({"name": a["name"], "criticality": crit, "re": pat, "exclude": xpat})
        for t in terms:
            vendor_words.update(_words(t))
    win = cfg.get("window_days") or {}
    th = cfg.get("thresholds") or {}
    pt = load_priority_terms() if priority_terms is None else priority_terms
    return {
        "assets": assets,
        "vendor_words": vendor_words,
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
        "published": (alert.get("published") or "")[:10] or None,
        "tier": tier,
        "assets": sorted({a["name"] for a, _ in hits}),
        "criticality": min((a["criticality"] for a, _ in hits), key=lambda c: CRIT_RANK[c]),
        "reasons": [f"In your estate: {_hits_desc(hits)}"] + esc + work,
        "score": _num(alert.get("risk_score")) or 0,
        "cvss": cvss,
        "kev": bool(alert.get("kev")),
    }


def current_categories(item):
    text = f"{item.get('title') or ''} {item.get('summary') or ''}"
    try:
        from fetch_intel import CATEGORY_RES
    except Exception:  # pragma: no cover - fall back to the stored labels
        return list(item.get("categories") or [])
    return [k for k, _, rx in CATEGORY_RES if rx.search(text)]


def classify_intel(item, env, labels):
    hits = match_assets(f"{item.get('title') or ''} {item.get('summary') or ''}", env["assets"])
    if not hits:
        return None
    # Re-classify with the CURRENT rules instead of trusting the label stored
    # when the story was fetched: rule fixes (new exploitation phrasings,
    # removed false positives) then apply to the whole 45-day window at once.
    cats = current_categories(item)
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
    # Official vendor bulletin rating a CVE Critical on a critical asset: act
    # on the vendor's rating instead of waiting days for NVD to score it.
    vendor_critical = (item.get("kind") == "advisory" and item.get("advisory_severity") == "critical"
                       and best == CRIT_RANK["critical"])
    if vendor_critical:
        crit = [a["cve"] for a in item.get("advisory") or [] if a.get("severity") == "critical"]
        reasons.append("Vendor rates Critical: " + ", ".join(crit[:5]))
    if vendor_critical or (hot and (best <= CRIT_RANK["high"] or "exploited" in hot)):
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


BUNDLE_MIN = 4  # >= this many same-day WORK CVEs on the same assets -> one bundle item


def _slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40]


def bundle_work(items, triage, min_size=BUNDLE_MIN):
    """Collapse same-asset, same-publish-day WORK CVEs (a Chrome release, a Patch
    Tuesday) into one bundle item: one patch cycle = one work item. ESCALATE items
    and anything the team triaged individually are never bundled, and every
    member CVE id is kept on the bundle so nothing disappears."""
    groups, keep = {}, []
    for it in items:
        if (it["kind"] == "cve" and it["tier"] == "work" and it.get("published")
                and it["key"] not in triage):
            groups.setdefault((tuple(it["assets"]), it["published"]), []).append(it)
        else:
            keep.append(it)
    for (assets, day), members in groups.items():
        if len(members) < min_size:
            keep.extend(members)
            continue
        members.sort(key=lambda m: (-(m["cvss"] or 0), m["ref"]))
        ids = [m["ref"] for m in members]
        top = max((m["cvss"] for m in members if m["cvss"] is not None), default=None)
        label = " + ".join(assets)
        keep.append({
            "key": f"bundle:{_slug(label)}:{day}",
            "kind": "bundle",
            "ref": ids[0],
            "title": f"{len(ids)} {label} CVEs published {day} -- one patch cycle"
                     + (f" (highest CVSS {top})" if top is not None else ""),
            "link": f"#{ids[0]}",
            "date": max((m["date"] or "") for m in members) or day,
            "published": day,
            "tier": "work",
            "assets": list(assets),
            "criticality": min((m["criticality"] for m in members), key=lambda c: CRIT_RANK[c]),
            "reasons": [members[0]["reasons"][0],
                        f"{len(ids)} CVEs at/above the WORK threshold, all published {day} "
                        "(typically one vendor release -- patch together)",
                        "CVEs: " + ", ".join(ids)],
            "score": max((m["score"] or 0) for m in members),
            "cvss": top,
            "kev": False,
            "cve_ids": ids,
        })
    return keep


STORY_DAYS = 3  # same-asset coverage published within this many days = one incident

_TITLE_NOISE = re.compile(r"\s+[-|\u2013\u2014]\s+[^-|\u2013\u2014]{2,60}$")


def _norm_title(t):
    return re.sub(r"[^a-z0-9]+", " ", _TITLE_NOISE.sub("", t or "").lower()).strip()


def group_stories(items, triage, days=STORY_DAYS, vendor_words=None):
    """Fold duplicate press coverage of ONE incident (the same zero-day reported by
    20 outlets / Google News) into a single news card. Two stories are the same
    incident when they hit a shared asset AND (name a common CVE, OR were
    published within `days` of each other without naming DIFFERENT CVEs).
    The card keeps every outlet's headline + link under `coverage`; its key is
    the earliest member's intel key, so triage entries and Discord dedupe that
    already reference it keep working. Individually-triaged stories stay apart."""
    news = [it for it in items if it["kind"] == "intel" and it["key"] not in triage]
    rest = [it for it in items if not (it["kind"] == "intel" and it["key"] not in triage)]
    news.sort(key=lambda it: (it.get("date") or "", it["key"]))
    vendor_words = vendor_words or set()
    # document frequency of each title word inside this window -> "rare" words are
    # campaign / malware names (PEERSTITCH, ClickFix) that pin a story to one incident
    df = {}
    for it in news:
        for w in _words(_TITLE_NOISE.sub("", it["title"])):
            df[w] = df.get(w, 0) + 1
    rare_cut = max(2, len(news) // 50)

    def sig(it):
        ws = _words(_TITLE_NOISE.sub("", it["title"])) - _GENERIC
        return ws - vendor_words, ws & vendor_words

    def names(it):
        # campaign / malware / actor names are written as ALLCAPS or CamelCase
        # (PEERSTITCH, ROMULUS, ClickFix) -- ordinary words never are
        raw = _TITLE_NOISE.sub("", it["title"])
        return {w.lower() for w in re.findall(r"\b(?:[A-Z]{5,}|[A-Z][a-z]+[A-Z][A-Za-z]+)\b", raw)} \
            - _GENERIC - vendor_words

    def same_topic(a, b):
        """2 = shares a distinctive campaign/malware name, 1 = shares 2+ topic words, 0 = no."""
        (na, va), (nb, vb) = sig(a), sig(b)
        shared = na & nb
        if any(df.get(w, 0) <= max(rare_cut, 12) for w in names(a) & names(b)):
            return 2
        return 1 if len(shared) + (1 if va & vb else 0) >= 2 else 0

    # Greedy, NON-transitive: an item joins a cluster only if it matches that
    # cluster's FIRST report directly, so roundup articles naming several vendors
    # ("CISA adds PAN-OS, BeyondTrust ... to KEV") cannot chain incidents together.
    clusters = []  # [seed, cve_set, members]
    for it in news:
        ci, di = set(it.get("cve_ids") or []), _dt(it.get("date"))
        home = None
        for cl in clusters:      # 1) a shared CVE id is decisive
            if ci & cl[1]:
                home = cl
                break
        if home is None:
            for cl in clusters:  # 2) same incident told without (conflicting) CVE ids
                seed, cset = cl[0], cl[1]
                ds = _dt(seed.get("date"))
                topic = same_topic(it, seed)
                if (ci and cset and not ci & cset and topic < 2) or not (di and ds) \
                        or abs((di - ds).total_seconds()) > days * 86400 \
                        or not set(it["assets"]) & set(seed["assets"]):
                    continue
                if set(it["assets"]) == set(seed["assets"]) or topic:
                    home = cl
                    break
        if home is None:
            clusters.append([it, set(ci), [it]])
        else:
            if len(ci) <= 3:     # roundups naming many CVEs don't widen the cluster
                home[1] |= ci
            home[2].append(it)
    def _campaign_link(ma, mb):
        # same named campaign/malware (e.g. PEERSTITCH) on an overlapping asset, within `days`
        for x in ma:
            for y in mb:
                dx, dy = _dt(x.get("date")), _dt(y.get("date"))
                if dx and dy and abs((dx - dy).total_seconds()) <= days * 86400 \
                        and set(x["assets"]) & set(y["assets"]) and same_topic(x, y) == 2:
                    return True
        return False

    # 3) a CVE id introduced by a later report can join two clusters that started apart
    merged = True
    while merged:
        merged = False
        for a in range(len(clusters)):
            for b in range(a + 1, len(clusters)):
                if clusters[a][1] & clusters[b][1] or _campaign_link(clusters[a][2], clusters[b][2]):
                    clusters[a][1] |= clusters[b][1]
                    clusters[a][2] += clusters[b][2]
                    clusters[a][2].sort(key=lambda it: (it.get("date") or "", it["key"]))
                    del clusters[b]
                    merged = True
                    break
            if merged:
                break
    groups = {n: cl[2] for n, cl in enumerate(clusters)}
    out = list(rest)
    for members in groups.values():
        if len(members) == 1:
            out.append(members[0])
            continue
        lead = min(members, key=lambda m: (TIER_RANK[m["tier"]], CRIT_RANK[m["criticality"]],
                                           -(m["score"] or 0), m.get("date") or ""))
        first = members[0]  # earliest -> stable key
        cves = sorted({c for m in members for c in m.get("cve_ids") or []})
        cats = []
        for m in members:
            cats += [c for c in m.get("categories") or [] if c not in cats]
        seen_titles, coverage = set(), []
        for m in sorted(members, key=lambda m: m.get("date") or ""):
            nt = _norm_title(m["title"])
            coverage.append({"title": m["title"], "link": m["link"], "source": m.get("source"),
                             "date": m.get("date"), "dup": nt in seen_titles})
            seen_titles.add(nt)
        story = dict(lead)
        story.update({
            "key": first["key"],
            "ref": first["ref"],
            "tier": lead["tier"],
            "date": max((m.get("date") or "") for m in members),
            "first_reported": first.get("date"),
            "assets": sorted({a for m in members for a in m["assets"]}),
            "criticality": min((m["criticality"] for m in members), key=lambda c: CRIT_RANK[c]),
            "categories": cats,
            "cve_ids": cves,
            "member_keys": [m["key"] for m in members],
            "coverage": coverage,
            "reasons": list(lead["reasons"]) + [
                f"Same incident reported by {len(members)} sources "
                f"({len({m.get('source') for m in members})} outlets/feeds) -- first seen "
                f"{(first.get('date') or '')[:10]}"],
        })
        if cves and not any(r.startswith("Names ") for r in story["reasons"]):
            story["reasons"].insert(-1, "Names " + ", ".join(cves[:5]))
        out.append(story)
    return out


ADVISORY_MIN = 3  # >= this many WORK advisories from one feed on one asset within STORY_DAYS


def batch_advisories(items, triage, min_size=ADVISORY_MIN, days=STORY_DAYS):
    """A vendor PSIRT publishing 6 separate WORK advisories in one release cycle is one
    patch task, not 6. Groups single-feed, same-asset WORK news items that each name
    CVE ids (and are not multi-source stories) into one card; all CVEs + links kept."""
    cand = [it for it in items if it["kind"] == "intel" and it["tier"] == "work"
            and it.get("cve_ids") and not it.get("coverage") and it["key"] not in triage]
    keys = {id(it) for it in cand}
    rest = [it for it in items if id(it) not in keys]
    cand.sort(key=lambda it: (it.get("date") or "", it["key"]))
    groups = []
    for it in cand:
        di = _dt(it.get("date"))
        for g in groups:
            s0 = g[0]
            ds = _dt(s0.get("date"))
            if (s0.get("source") == it.get("source") and s0["assets"] == it["assets"]
                    and di and ds and abs((di - ds).total_seconds()) <= days * 86400):
                g.append(it)
                break
        else:
            groups.append([it])
    out = rest
    for g in groups:
        if len(g) < min_size:
            out.extend(g)
            continue
        first = g[0]
        cves = sorted({c for m in g for c in m["cve_ids"]})
        label = " + ".join(first["assets"])
        lo, hi = (first.get("date") or "")[:10], max((m.get("date") or "") for m in g)[:10]
        card = dict(max(g, key=lambda m: (m["score"] or 0)))
        card.update({
            "key": first["key"], "ref": first["ref"], "link": first["link"],
            "title": f"{len(g)} {first.get('source') or 'vendor'} advisories for {label} "
                     f"({lo}{'' if lo == hi else ' to ' + hi}) -- one patch cycle",
            "date": max((m.get("date") or "") for m in g),
            "first_reported": first.get("date"),
            "cve_ids": cves,
            "member_keys": [m["key"] for m in g],
            "advisory_batch": True,
            "coverage": [{"title": m["title"], "link": m["link"], "source": m.get("source"),
                          "date": m.get("date"), "dup": False} for m in g],
            "reasons": [first["reasons"][0],
                        f"{len(g)} advisories from {first.get('source')} within {days} days "
                        "(one vendor release -- patch together)",
                        "Names " + ", ".join(cves[:8]) + (" …" if len(cves) > 8 else "")],
        })
        out.append(card)
    return out


def build(alerts, intel, env, now=None, triage=None):
    now = now or datetime.now(timezone.utc)
    triage = triage or {}
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
    out = bundle_work(out, triage)
    out = group_stories(out, triage, vendor_words=env.get("vendor_words"))
    out = batch_advisories(out, triage)
    for r in out:
        t = triage.get(r["key"])
        if t:
            r["triage"] = t
            r["closed"] = t["status"] in CLOSED_STATUSES
    out.sort(key=lambda r: (bool(r.get("closed")), TIER_RANK[r["tier"]], CRIT_RANK[r["criticality"]],
                            -(r["score"] or 0), r["key"]))
    return {
        "generated_at": now.isoformat(),
        "window_days": {"cve": env["cve_days"], "intel": env["intel_days"]},
        "assets": [{"name": a["name"], "criticality": a["criticality"]} for a in env["assets"]],
        "counts": {t: sum(1 for r in out if r["tier"] == t) for t in TIER_RANK},
        "open": {t: sum(1 for r in out if r["tier"] == t and not r.get("closed")) for t in TIER_RANK},
        "triaged": sum(1 for r in out if r.get("triage")),
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
    result = build(_load(ALERTS_PATH, []), _load(INTEL_PATH, {}), env, triage=load_triage())
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    c = result["counts"]
    print(f"Escalations: {c['escalate']} escalate, {c['work']} work, "
          f"{result['triaged']} triaged "
          f"(CVE window {env['cve_days']}d, intel window {env['intel_days']}d)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
