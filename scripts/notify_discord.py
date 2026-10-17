#!/usr/bin/env python3
"""Post NEW "Escalate" items (docs/data/escalations.json) to a Discord channel.

Env
  DISCORD_WEBHOOK_URL  repo secret. Absent -> do nothing (exit 0, state untouched).
  DISCORD_SEED_ONLY    "1" -> record current items as already-sent without posting
                       (used on backfill runs so they never flood the channel).
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
    return [it for it in items if TIER_RANK.get(it.get("tier"), 9) <= limit and it.get("key") not in sent]


def build_embed(it, dashboard):
    url = f"{dashboard}#{it['ref']}" if it.get("kind") == "cve" else (it.get("link") or dashboard)
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
            n_esc = sum(1 for it in items if it.get("tier") == "escalate")
            n_work = sum(1 for it in items if it.get("tier") == "work")
            ok = poster(webhook, {"content": (
                f"✅ CVE dashboard connected. {n_esc} Escalate / {n_work} Work items are already on the board "
                f"({dashboard}). From now on, only NEW Escalate items will be posted here.")})
            if not ok:
                return state, 0
        return {"seeded": True, "sent": prune(sent, now)}, 0

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
    return {"seeded": True, "sent": prune(sent, now)}, posted


def main():
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
    new_state, n = run(
        webhook, esc, state, datetime.now(timezone.utc),
        seed_only=os.environ.get("DISCORD_SEED_ONLY") == "1",
        min_tier=(os.environ.get("DISCORD_MIN_TIER") or "escalate").strip().lower(),
        dashboard=os.environ.get("DASHBOARD_URL") or "https://astruzocyber.github.io/CVE/",
    )
    with open(STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump(new_state, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print(f"Discord: posted {n} item(s); tracking {len(new_state.get('sent') or {})} key(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
