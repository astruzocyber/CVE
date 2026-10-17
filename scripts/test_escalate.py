#!/usr/bin/env python3
"""Tests for environment tiering (scripts/escalate.py) and the Discord
notifier (scripts/notify_discord.py). No network: the poster is injected."""
import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import escalate as E  # noqa: E402
import notify_discord as D  # noqa: E402
import fetch_intel as F  # noqa: E402

NOW = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
CFG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "environment.yaml")


def env():
    return E.load_env(CFG, priority_terms=["Active Directory Federation Services"])


def alert(cid, desc, cvss=5.0, **kw):
    a = {"cve_id": cid, "description": desc, "cvss_score": cvss, "published": "2026-10-13T19:00:00",
         "first_seen": "2026-10-14T00:00:00", "matched_keywords": [], "affected": [],
         "cvss_vector_components": {"attack_vector": "NETWORK"}}
    a.update(kw)
    return a


def intel(iid, title, cats, summary="", priority="high"):
    return {"id": iid, "title": title, "summary": summary, "link": f"https://example.com/{iid}",
            "source": "Test", "categories": cats, "priority": priority, "score": 70,
            "published": "2026-10-15T10:00:00+00:00", "cve_ids": []}


def tiers(out):
    return {it["ref"]: it["tier"] for it in out["items"]}


class EscalateTests(unittest.TestCase):
    def test_kev_windows_shell_escalates(self):
        out = E.build([alert("CVE-2026-96951", "Command injection in Windows Shell allows bypass.", 8.8,
                             kev=True, kev_date_added="2026-10-13")], {}, env(), NOW)
        self.assertEqual(tiers(out), {"CVE-2026-96951": "escalate"})
        self.assertIn("Windows Shell", out["items"][0]["reasons"][0])

    def test_low_cvss_adfs_is_work_via_priority_term(self):
        out = E.build([alert("CVE-2026-69982", "Weak authentication in Active Directory Federation Services "
                             "(AD FS) allows spoofing.", 5.9)], {}, env(), NOW)
        self.assertEqual(tiers(out), {"CVE-2026-69982": "work"})

    def test_critical_network_cvss_on_critical_asset_escalates(self):
        out = E.build([alert("CVE-2026-96252", "Improper signature verification in Active Directory "
                             "Federation Services (AD FS).", 9.1)], {}, env(), NOW)
        self.assertEqual(tiers(out)["CVE-2026-96252"], "escalate")

    def test_out_of_estate_is_ignored_even_if_kev(self):
        out = E.build([alert("CVE-2026-1", "RCE in Acme Router firmware.", 9.8, kev=True,
                             kev_date_added="2026-10-14")], {}, env(), NOW)
        self.assertEqual(out["items"], [])

    def test_watchlist_label_alone_is_not_evidence(self):
        # NVD keyword search AND-matches words; the label must not count.
        out = E.build([alert("CVE-2026-2", "A check on the access point is missing in FooCMS.", 9.8,
                             matched_keywords=["Check Point"], kev=True, kev_date_added="2026-10-14")],
                      {}, env(), NOW)
        self.assertEqual(out["items"], [])

    def test_old_cve_resurfaced_by_backfill_is_ignored(self):
        out = E.build([alert("CVE-2019-1579", "RCE in PAN-OS GlobalProtect.", 8.1,
                             published="2019-07-19T00:00:00", first_seen="2026-10-16T00:00:00")],
                      {}, env(), NOW)
        self.assertEqual(out["items"], [])

    def test_wordpress_plugin_excluded(self):
        out = E.build([alert("CVE-2026-3", "The Foo plugin for WordPress is vulnerable to SQLi.", 9.8)],
                      {}, env(), NOW)
        self.assertEqual(out["items"], [])

    def test_teams_vishing_news_escalates(self):
        out = E.build([], {"items": [intel("t1", "Hackers pose as IT support in Microsoft Teams calls",
                                           ["social_engineering"])]}, env(), NOW)
        self.assertEqual(tiers(out), {"t1": "escalate"})

    def test_vendor_issue_news_is_work(self):
        out = E.build([], {"items": [intel("b1", "Windows 11 update causes black screens on AVD with FSLogix",
                                           ["vendor_issue"])]}, env(), NOW)
        self.assertEqual(tiers(out), {"b1": "work"})

    def test_generic_windows_malware_news_not_escalated(self):
        out = E.build([], {"items": [intel("g1", "New stealer lures Windows users with fake updates",
                                           ["social_engineering"], priority="medium")]}, env(), NOW)
        self.assertEqual(tiers(out), {"g1": "work"})

    def test_escalate_sorted_first(self):
        out = E.build([alert("CVE-2026-69982", "Weak authentication in Active Directory Federation "
                             "Services.", 5.9)],
                      {"items": [intel("t1", "Vishing via Microsoft Teams", ["social_engineering"])]}, env(), NOW)
        self.assertEqual(out["items"][0]["tier"], "escalate")
        self.assertEqual(out["counts"], {"escalate": 1, "work": 1})


class EstateAndTriageTests(unittest.TestCase):
    def test_url_hostname_is_not_a_product_match(self):
        out = E.build([alert("CVE-2026-2", "Path traversal in Acme Notes, see https://github.com/acme/notes "
                             "for the fix.", 9.8)], {}, env(), NOW)
        self.assertEqual(out["items"], [])

    def test_inventory_app_matches(self):
        out = E.build([alert("CVE-2026-3", "Remote code execution in AnyDesk for Windows.", 9.8,
                             kev=True, kev_date_added="2026-10-14")], {}, env(), NOW)
        self.assertEqual(tiers(out), {"CVE-2026-3": "escalate"})

    def test_match_case_common_word_names(self):
        self.assertEqual(E.build([alert("CVE-2026-4", "A flaw lets users workday schedules leak.", 9.8)],
                                 {}, env(), NOW)["items"], [])

    def test_triage_is_attached_and_closed_is_flagged(self):
        a = alert("CVE-2026-5", "Remote code execution in AnyDesk for Windows.", 9.8,
                  kev=True, kev_date_added="2026-10-14")
        tri = {"cve:CVE-2026-5": {"status": "resolved", "owner": "GMS", "note": "patched", "date": "2026-10-16"}}
        out = E.build([a], {}, env(), NOW, triage=tri)
        it = out["items"][0]
        self.assertEqual(it["triage"]["status"], "resolved")
        self.assertTrue(it["closed"])
        self.assertEqual(out["open"]["escalate"], 0)

    def test_load_triage_drops_unknown_status_and_survives_bad_yaml(self):
        import tempfile
        d = tempfile.mkdtemp()
        good, bad = os.path.join(d, "g.yaml"), os.path.join(d, "b.yaml")
        open(good, "w").write('entries:\n  "cve:CVE-2026-5":\n    status: resolved\n'
                              '  "cve:CVE-2026-6":\n    status: maybe\n')
        open(bad, "w").write("entries:\n  - [unclosed\n")
        self.assertEqual(list(E.load_triage(good)), ["cve:CVE-2026-5"])
        self.assertEqual(E.load_triage(bad), {})
        self.assertEqual(E.load_triage(os.path.join(d, "missing.yaml")), {})

    def _work(self, n, day="2026-10-13"):
        return [alert(f"CVE-2026-10{i:02d}", "Use after free in Google Chrome allows heap corruption.", 8.8,
                      published=f"{day}T19:00:00") for i in range(n)]

    def test_same_day_release_is_bundled_with_every_id_kept(self):
        out = E.build(self._work(6), {}, env(), NOW)
        bundles = [i for i in out["items"] if i["kind"] == "bundle"]
        self.assertEqual(len(bundles), 1)
        self.assertEqual(len(bundles[0]["cve_ids"]), 6)
        self.assertEqual(bundles[0]["tier"], "work")
        self.assertFalse(any(i["kind"] == "cve" for i in out["items"]))

    def test_small_groups_and_triaged_items_not_bundled(self):
        self.assertTrue(all(i["kind"] == "cve" for i in E.build(self._work(3), {}, env(), NOW)["items"]))
        tri = {"cve:CVE-2026-1000": {"status": "in_progress"}}
        out = E.build(self._work(5), {}, env(), NOW, triage=tri)
        kinds = sorted(i["kind"] for i in out["items"])
        self.assertEqual(kinds, ["bundle", "cve"])

    def test_stale_stored_category_is_reclassified(self):
        it = intel("pan1", "Palo Alto Networks Patches PAN-OS RCE Flaw Amid Active Exploitation",
                   ["patch", "vulnerability"], priority="medium")
        out = E.build([], {"items": [it]}, env(), NOW)
        self.assertEqual(out["items"][0]["tier"], "escalate")

    def _pan(self, i, title, day, cves=None):
        x = intel(f"pan{i}", title, ["exploited"], priority="high")
        x["published"] = f"2026-10-{day}T12:00:00+00:00"
        x["cve_ids"] = cves or []
        return x

    def test_duplicate_coverage_folds_into_one_story(self):
        items = [self._pan(1, "Palo Alto Networks PAN-OS zero-day exploited", 14, ["CVE-2026-0322"]),
                 self._pan(2, "PAN-OS flaw exploited, Palo Alto Networks warns - Outlet", 15),
                 self._pan(3, "CISA: Palo Alto Networks bug exploited", 15, ["CVE-2026-0322"])]
        out = E.build([], {"items": items}, env(), NOW)
        self.assertEqual(len(out["items"]), 1)
        s = out["items"][0]
        self.assertEqual(s["key"], "intel:pan1")
        self.assertEqual(s["tier"], "escalate")
        self.assertEqual(len(s["coverage"]), 3)
        self.assertEqual(sorted(s["member_keys"]), ["intel:pan1", "intel:pan2", "intel:pan3"])

    def test_different_cves_or_far_apart_stay_separate(self):
        items = [self._pan(1, "Palo Alto Networks bug A exploited", 14, ["CVE-2026-1"]),
                 self._pan(2, "Palo Alto Networks bug B exploited", 14, ["CVE-2026-2"]),
                 self._pan(3, "Palo Alto Networks bug C exploited", 10)]
        self.assertEqual(len(E.build([], {"items": items}, env(), NOW)["items"]), 3)

    def test_campaign_name_links_reports_with_different_old_cves(self):
        items = [self._pan(1, "PEERSTITCH malware deployed via FortiOS flaw", 15, ["CVE-2025-1"]),
                 self._pan(2, "Unit 42 uncovers PEERSTITCH, a stealthy FortiGate implant", 16),
                 self._pan(3, "Fortinet FortiWeb flaw exploited in attacks", 10)]
        out = E.build([], {"items": items}, env(), NOW)
        sizes = sorted(len(i.get("coverage") or [i]) for i in out["items"])
        self.assertEqual(sizes, [1, 2])

    def test_later_cve_joins_clusters(self):
        items = [self._pan(1, "Palo Alto Networks bug one", 10, ["CVE-2026-1"]),
                 self._pan(2, "Palo Alto Networks bug two", 11, ["CVE-2026-2"]),
                 self._pan(3, "Palo Alto Networks chained bugs", 12, ["CVE-2026-1", "CVE-2026-2"])]
        out = E.build([], {"items": items}, env(), NOW)
        self.assertEqual(len(out["items"]), 1)

    def test_psirt_work_advisories_batched(self):
        items = []
        for i, d in enumerate([14, 14, 15, 16]):
            x = intel(f"ps{i}", f"CVE-2026-03{i} PAN-OS: Denial of Service (Severity: MEDIUM)", ["vulnerability"])
            x["published"] = f"2026-10-{d}T12:00:00+00:00"
            x["cve_ids"] = [f"CVE-2026-03{i}"]
            x["source"] = "Palo Alto PSIRT"
            items.append(x)
        out = E.build([], {"items": items}, env(), NOW)
        work = [i for i in out["items"] if i["tier"] == "work"]
        if work:  # only meaningful when these advisories reach WORK at all
            self.assertEqual(len(work), 1)
            self.assertEqual(len(work[0]["cve_ids"]), 4)
            self.assertEqual(work[0]["key"], "intel:ps0")

    def test_story_already_announced_via_member_not_reposted(self):
        story = {"key": "intel:a", "tier": "escalate", "member_keys": ["intel:a", "intel:b"]}
        self.assertEqual(D.select_new([story], {"intel:b": "x"}), [])
        self.assertEqual(len(D.select_new([story], {})), 1)

    def test_triaged_item_never_posted_to_discord(self):
        esc_doc = {"items": [{"key": "cve:A", "tier": "escalate", "title": "A", "triage": {"status": "acknowledged"}}]}
        self.assertEqual(D.select_new(esc_doc["items"], {}), [])


class IntelRuleRegressionTests(unittest.TestCase):
    """False positives found while building the Escalate board."""
    def cats(self, text):
        return F.classify(text, [])[0]

    def test_anti_phishing_is_not_social_engineering(self):
        self.assertNotIn("social_engineering", self.cats("enclave that handles passwords for a Windows anti-phishing feature"))

    def test_failure_is_not_a_lure(self):
        self.assertNotIn("social_engineering", self.cats("a configuration failure caused the outage"))

    def test_real_lures_still_match(self):
        self.assertIn("social_engineering", self.cats("attackers use invoice lures and phishing pages"))
        self.assertIn("social_engineering", self.cats("a new tech scam targets retirees"))

    def test_active_exploitation_phrasing(self):
        self.assertIn("exploited", self.cats("Palo Alto Networks Patches PAN-OS Flaw Amid Active Exploitation"))
        self.assertIn("exploited", self.cats("PEERSTITCH Malware Deployed via FortiOS Flaw"))


def esc(*items):
    return {"items": [{"key": f"cve:{k}", "kind": "cve", "ref": k, "title": k, "tier": t,
                       "assets": ["Identity"], "criticality": "critical",
                       "reasons": ["In your estate: x", "CISA KEV"]} for k, t in items]}


class DiscordTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        D.time.sleep = lambda s: None

    def poster(self, ok=True):
        def p(url, payload):
            self.calls.append(payload)
            return ok
        return p

    def test_first_run_seeds_without_flood(self):
        st, n = D.run("u", esc(("A", "escalate"), ("B", "escalate")), {}, NOW, poster=self.poster())
        self.assertEqual(n, 0)
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn("embeds", self.calls[0])
        self.assertTrue(st["seeded"])
        self.assertEqual(set(st["sent"]), {"cve:A", "cve:B"})

    def test_only_new_escalate_items_posted(self):
        state = {"seeded": True, "sent": {"cve:A": NOW.isoformat()}}
        st, n = D.run("u", esc(("A", "escalate"), ("B", "escalate"), ("C", "work")), state, NOW,
                      poster=self.poster())
        self.assertEqual(n, 1)
        self.assertEqual([e["title"] for e in self.calls[0]["embeds"]], ["[ESCALATE] B"])
        self.assertIn("cve:B", st["sent"])
        self.assertNotIn("cve:C", st["sent"])

    def test_failed_post_is_retried_next_run(self):
        state = {"seeded": True, "sent": {}}
        st, n = D.run("u", esc(("B", "escalate")), state, NOW, poster=self.poster(ok=False))
        self.assertEqual(n, 0)
        self.assertNotIn("cve:B", st["sent"])

    def test_seed_only_records_without_posting(self):
        st, n = D.run("u", esc(("B", "escalate")), {"seeded": True, "sent": {}}, NOW, seed_only=True,
                      poster=self.poster())
        self.assertEqual((n, self.calls), (0, []))
        self.assertIn("cve:B", st["sent"])

    def test_batches_of_ten(self):
        items = [(f"X{i}", "escalate") for i in range(23)]
        st, n = D.run("u", esc(*items), {"seeded": True, "sent": {}}, NOW, poster=self.poster())
        self.assertEqual(n, 23)
        self.assertEqual([len(c["embeds"]) for c in self.calls], [10, 10, 3])

    def test_mentions_disabled_and_url_hidden(self):
        sent = []

        class Res:
            status = 204
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, timeout=0):
            sent.append(req.data)
            return Res()
        orig = D.urllib.request.urlopen
        D.urllib.request.urlopen = fake_urlopen
        try:
            self.assertTrue(D.post("https://discord.com/api/webhooks/1/abc", {"content": "@everyone hi"}))
        finally:
            D.urllib.request.urlopen = orig
        self.assertIn(b'"allowed_mentions": {"parse": []}', sent[0])

    def test_digest_once_per_day_after_hour(self):
        doc = esc(("A", "escalate"), ("B", "work"))
        st = {"seeded": True, "sent": {}}
        early = NOW.replace(hour=6)
        self.assertEqual(D.run_digest("u", doc, st, early, 12, poster=self.poster())[1], False)
        st2, ok = D.run_digest("u", doc, st, NOW, 12, poster=self.poster())
        self.assertTrue(ok)
        self.assertIn("1 open Escalate", self.calls[0]["content"])
        self.assertEqual(D.run_digest("u", doc, st2, NOW, 12, poster=self.poster())[1], False)

    def test_connect_run_skips_same_day_digest(self):
        st, _ = D.run("u", esc(("A", "escalate")), {}, NOW, poster=self.poster())
        self.assertEqual(D.run_digest("u", esc(("A", "escalate")), st, NOW, 12, poster=self.poster())[1], False)

    def test_webhook_url_validation(self):
        self.assertTrue(D.WEBHOOK_RE.match("https://discord.com/api/webhooks/123/abc-DEF_1"))
        self.assertFalse(D.WEBHOOK_RE.match("https://evil.example/api/webhooks/123/abc"))


if __name__ == "__main__":
    unittest.main()
