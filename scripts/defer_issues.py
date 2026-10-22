#!/usr/bin/env python3
"""
scripts/defer_issues.py

Carries new alerts from a skip_issues run over to the next run that opens issues.

aggregate.py marks every new alert as seen the moment it is written to
docs/data/new_alerts.json. On a skip_issues dispatch the "Notify via GitHub
Issues" step does not run, so before this script existed those alerts were
never notified at all: they were seen, so no later run listed them as new.
That was intended for a backfill (a long lookback that surfaces hundreds of
old CVEs at once), but routine skip_issues dispatches at the normal window
(re-running the pipeline after a fix) silently swallowed real new CVEs.

Runs after aggregate.py and BEFORE the data commit:
  * skip_issues at the normal lookback -> append this run's new alerts to
    docs/data/issues_deferred.json (they get issues on the next normal run).
  * skip_issues with a longer lookback (backfill) -> nothing is deferred; the
    backfill's alerts stay seen without issues, as before.
  * normal run -> add the deferred alerts that are still on the board to
    new_alerts.json (alerts pruned or suppressed meanwhile are dropped), then
    clear the deferred list. The notifier's per-run cap + digest still applies.

Env: SKIP_ISSUES ("true"/"1"), LOOKBACK_DAYS, NORMAL_LOOKBACK_DAYS (default 4).
"""
import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(REPO_ROOT, "docs", "data")
NEW_ALERTS_PATH = os.path.join(DATA_DIR, "new_alerts.json")
ALERTS_PATH = os.path.join(DATA_DIR, "alerts.json")
DEFERRED_PATH = os.path.join(DATA_DIR, "issues_deferred.json")


def _truthy(value):
    return str(value or "").strip().lower() in ("1", "true", "yes")


def is_backfill(lookback_days, normal_days):
    """A lookback longer than the scheduled one is a backfill. Unparseable
    values count as a backfill, so an unclear run never defers a flood."""
    try:
        return int(str(lookback_days).strip()) > int(str(normal_days).strip())
    except (TypeError, ValueError):
        return True


def plan(new_alerts, deferred_ids, current_alerts, skip, backfill):
    """Return (alerts_to_notify, deferred_ids_after, message)."""
    new_ids = [a.get("cve_id") for a in new_alerts if a.get("cve_id")]
    if skip:
        if backfill:
            return [], list(deferred_ids), (f"Backfill with skip_issues: {len(new_ids)} new alert(s) "
                                            f"recorded as seen without issues; nothing deferred.")
        merged = list(deferred_ids)
        for cid in new_ids:
            if cid not in merged:
                merged.append(cid)
        return [], merged, (f"skip_issues at the normal window: deferred {len(merged) - len(deferred_ids)} "
                            f"new alert(s) to the next run that opens issues ({len(merged)} pending).")
    by_id = {}
    for a in current_alerts:
        by_id.setdefault(a.get("cve_id"), a)
    out = list(new_alerts)
    carried, gone = 0, []
    for cid in deferred_ids:
        if cid in new_ids:
            continue
        if cid in by_id:
            out.append(by_id[cid])
            new_ids.append(cid)
            carried += 1
        else:
            gone.append(cid)
    msg = f"Carried {carried} deferred alert(s) into this run's issues."
    if gone:
        msg += f" {len(gone)} deferred alert(s) left the board meanwhile, not notified: {', '.join(gone[:20])}"
    return out, [], msg


def _load(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return default
    return data if isinstance(data, type(default)) else default


def main():
    skip = _truthy(os.environ.get("SKIP_ISSUES"))
    backfill = is_backfill(os.environ.get("LOOKBACK_DAYS") or "4",
                           os.environ.get("NORMAL_LOOKBACK_DAYS") or "4")
    new_alerts = _load(NEW_ALERTS_PATH, [])
    deferred = [c for c in _load(DEFERRED_PATH, []) if isinstance(c, str)]
    current = _load(ALERTS_PATH, []) if (deferred and not skip) else []
    notify, deferred_after, msg = plan(new_alerts, deferred, current, skip, backfill)
    print(msg)
    if not skip:
        with open(NEW_ALERTS_PATH, "w", encoding="utf-8") as fh:
            json.dump(notify, fh, indent=2)
    if deferred_after != deferred or not os.path.exists(DEFERRED_PATH):
        with open(DEFERRED_PATH, "w", encoding="utf-8") as fh:
            json.dump(deferred_after, fh, indent=2)
            fh.write("\n")


if __name__ == "__main__":
    main()
