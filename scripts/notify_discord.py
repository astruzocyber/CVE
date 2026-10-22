#!/usr/bin/env python3
"""Post NEW "Escalate" items (docs/data/escalations.json) to a Discord channel.

Env
  DISCORD_WEBHOOK_URL  repo secret. Absent -> do nothing (exit 0, state untouched).
  DISCORD_SEED_ONLY    "1" -> record current items as already-sent without posting.
  SKIP_ISSUES, LOOKBACK_DAYS, NORMAL_LOOKBACK_DAYS (default 4)
                       a skip_issues run with a longer lookback (backfill) only
                       records items as sent, so it never floods the channel. A
                       skip_issues run at the normal lookback (re-running the
                       pipeline after a fix) touches nothing: its new items are
                       posted by the next normal run instead of being recorded as
                       sent and never announced (run 39660604872 swallowed two
                       Escalate stories that way).
  DISCORD_MIN_TIER     "escalate" (default) or "work" to also post Work items.
  DASHBOARD_URL        link target (default https://astruzocyber.github.io/CVE/).

State: docs/data/discord_notified.json  {"seeded": bool, "sent": {key: iso_date}}
  - The first run with a webhook only seeds state and posts ONE "connected"
    message listing how many items are already on the board -- no backlog flood.
  - A key is recorded only after Discord accepts the message containing it, so
    a failed post is retried next run.
  - Keys older than 60 days are pruned.

Safety: the webhook URL is never printed; only discord.com webhook URLs are
accepted; allowed_mentions is empty so feed text can never @everyone/@here.
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ESC_PATH = os.path.join(ROOT, "docs", "data", "escalations.json")
STATE_PATH = os.path.join(ROOT, "docs", "data", "discord_notified.json")
WEBHOOK_RE = re.compile(r"^https://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+$")
UA = "DiscordBot (https://github.com/astruzocyber/CVE, 1.0)"
TIER_RANK = {"escalate": 0, "work": 1}
COLORS = {"escalate": 0xE53935, "work": 0xFFB020}
EMBEDS_PER_MSG = 10
MAX_ITEMS_PER_RUN = 30
PRUNE_DAYS = 60


def _load(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _clip(text, n):
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text if len(text) <= n else text[: n - 1] + "…"


def select_new(items, sent, min_tier="escalate"):
    limit = TIER_RANK.get(min_tier, 0)
    # items the team already triaged in config/triage.yaml are never announced
    return [it for it in items if TIER_RANK.get(it.get("tier"), 9) <= limit
            and not any(k in sent for k in (it.get("member_keys") or [it.get("key")]))
            and not it.get("triage")]


def build_embed(it, dashboard):
    url = f"{dashboard}#alert-{it['ref']}" if it.get("kind") == "cve" else (it.get("link") or dashboard)
    if not str(url).startswith(("https://", "http://")):
        url = dashboard
    reasons = "\n".join(f"• {_clip(r, 180)}" for r in (it.get("reasons") or [])[1:6]) or "—"
    src = "CVE" if it.get("kind") == "cve" else f"News · {it.get('source') or ''}"
    return {
        "title": _clip(f"[{it.get('tier', '').upper()}] {it.get('title')}", 256),
        "url": url,
        "color": COLORS.get(it.get("tier"), 0x4F9DFF),
        "description": _clip(reasons.replace("\n", " \n"), 1500).replace(" \n", "\n"),
        "fields": [
            {"name": "Assets", "value": _clip(", ".join(it.get("assets") or []) or "—", 300), "inline": True},
            {"name": "Criticality", "value": it.get("criticality") or "—", "inline": True},
            {"name": "Source", "value": _clip(f"{src} · {str(it.get('date') or '')[:10]}", 200), "inline": True},
        ],
    }


def post(webhook, payload, attempts=4):
    """True on success. Honors Discord 429 retry_after. Never logs the URL."""
    body = dict(payload, allowed_mentions={"parse": []})
    data = json.dumps(body).encode("utf-8")
    for _ in range(attempts):
        req = urllib.request.Request(webhook + "?wait=true", data=data, method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=20) as res:
                return 200 <= res.status < 300
        except urllib.error.HTTPError as e:
            if e.code == 429:
                try:
                    wait = float(json.loads(e.read().decode() or "{}").get("retry_after", 2))
                except ValueError:
                    wait = 2.0
                time.sleep(min(wait, 30) + 0.5)
                continue
            print(f"Discord rejected the message: HTTP {e.code}")
            return False
        except urllib.error.URLError as e:
            print(f"Discord unreachable: {e.reason}")
            time.sleep(2)
    return False


def prune(sent, now):
    cut = (now - timedelta(days=PRUNE_DAYS)).isoformat()
    return {k: v for k, v in sent.items() if str(v) >= cut}


def run(webhook, esc, state, now, seed_only=False, min_tier="escalate", dashboard="", poster=post):
    """Returns (new_state, n_posted). Pure apart from `poster`."""
    sent = dict(state.get("sent") or {})
    items = esc.get("items") or []
    new = select_new(items, sent, min_tier)
    stamp = now.isoformat()

    if seed_only or not state.get("seeded"):
        for it in new:
            sent[it["key"]] = stamp
        if not seed_only:
            n_esc = sum(1 for it in items if it.get("tier") == "escalate" and not it.get("closed"))
            n_work = sum(1 for it in items if it.get("tier") == "work" and not it.get("closed"))
            ok = poster(webhook, {"content": (
                f"✅ CVE dashboard connected. {n_esc} Escalate / {n_work} Work items are already on the board "
                f"({dashboard}). From now on, only NEW Escalate items will be posted here.")})
            if not ok:
                return state, 0
        # no digest on the connect run -- the connect message already summarises the board
        new_state = {**state, "seeded": True, "sent": prune(sent, now)}
        if not seed_only:
            new_state["digest_date"] = now.date().isoformat()
        return new_state, 0

    posted = 0
    batch = new[:MAX_ITEMS_PER_RUN]
    for i in range(0, len(batch), EMBEDS_PER_MSG):
        chunk = batch[i:i + EMBEDS_PER_MSG]
        payload: dict = {"embeds": [build_embed(it, dashboard) for it in chunk]}
        if i == 0:
            payload["content"] = f"🚨 {len(new)} new item(s) for our environment — {dashboard}"
        if not poster(webhook, payload):
            break
        for it in chunk:
            sent[it["key"]] = stamp
        posted += len(chunk)
        time.sleep(1)
    # anything beyond MAX_ITEMS_PER_RUN is left unsent and goes out next run
    return {**state, "seeded": True, "sent": prune(sent, now)}, posted


def build_digest(esc, dashboard, limit=10):
    """Daily summary of what is still OPEN (not closed in triage.yaml)."""
    items = [it for it in esc.get("items") or [] if not it.get("closed")]
    esc_items = [it for it in items if it.get("tier") == "escalate"]
    n_work = sum(1 for it in items if it.get("tier") == "work")
    lines = [f"🗓️ Daily briefing — {len(esc_items)} open Escalate · {n_work} open Work · "
             f"{esc.get('triaged', 0)} triaged by the team. {dashboard}"]
    for it in esc_items[:limit]:
        t = it.get("triage") or {}
        tag = f" [{t['status']}{(' · ' + t['owner']) if t.get('owner') else ''}]" if t else " [untriaged]"
        lines.append(f"• {_clip(it.get('title'), 150)}{tag}")
    if len(esc_items) > limit:
        lines.append(f"…and {len(esc_items) - limit} more on the board.")
    if not esc_items:
        lines.append("Nothing open at Escalate level.")
    text = "\n".join(lines)   # keep line breaks (_clip would collapse them)
    return text if len(text) <= 1900 else text[:1899] + "…"


def run_digest(webhook, esc, state, now, hour_utc=12, dashboard="", poster=post):
    """Posts the daily digest once per UTC day, on the first run at/after hour_utc.
    Returns (new_state, posted_bool). The day is recorded only after Discord accepts."""
    today = now.date().isoformat()
    if not state.get("seeded") or state.get("digest_date") == today or now.hour < hour_utc:
        return state, False
    if not poster(webhook, {"content": build_digest(esc, dashboard)}):
        return state, False
    return {**state, "digest_date": today}, True


def run_mode(env):
    """'post' (normal), 'seed' (record without posting) or 'defer' (do nothing,
    leave state untouched so the next normal run posts the new items).
    An unparseable lookback counts as a backfill, so an unclear run never floods."""
    if env.get("DISCORD_SEED_ONLY") == "1":
        return "seed"
    if str(env.get("SKIP_ISSUES") or "").strip().lower() not in ("1", "true", "yes"):
        return "post"
    try:
        backfill = int(str(env.get("LOOKBACK_DAYS") or "4").strip()) > \
            int(str(env.get("NORMAL_LOOKBACK_DAYS") or "4").strip())
    except ValueError:
        backfill = True
    return "seed" if backfill else "defer"


def main():
    mode = run_mode(os.environ)
    if mode == "defer":
        print("skip_issues at the normal window: Discord deferred; new items go out on the next normal run.")
        return 0
    webhook = (os.environ.get("DISCORD_WEBHOOK_URL") or "").strip()
    if not webhook:
        print("DISCORD_WEBHOOK_URL not set -- Discord notifications disabled.")
        return 0
    if not WEBHOOK_RE.match(webhook):
        print("DISCORD_WEBHOOK_URL is not a discord.com webhook URL -- skipping.")
        return 0
    esc = _load(ESC_PATH, None)
    if not isinstance(esc, dict):
        print("escalations.json missing -- nothing to notify.")
        return 0
    state = _load(STATE_PATH, {}) or {}
    now = datetime.now(timezone.utc)
    dashboard = os.environ.get("DASHBOARD_URL") or "https://astruzocyber.github.io/CVE/"
    seed_only = mode == "seed"
    new_state, n = run(
        webhook, esc, state, now, seed_only=seed_only,
        min_tier=(os.environ.get("DISCORD_MIN_TIER") or "escalate").strip().lower(),
        dashboard=dashboard,
    )
    if not seed_only and (os.environ.get("DISCORD_DIGEST") or "1") != "0":
        try:
            hour = int(os.environ.get("DISCORD_DIGEST_HOUR_UTC") or 12)
        except ValueError:
            hour = 12
        new_state, sent_digest = run_digest(webhook, esc, new_state, now, hour, dashboard)
        if sent_digest:
            print("Discord: daily digest posted.")
    with open(STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump(new_state, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print(f"Discord: posted {n} item(s); tracking {len(new_state.get('sent') or {})} key(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
