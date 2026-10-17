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
        out = E.build([], {"items": [intel("g1", "New stealer targets Windows users",
                                           ["social_engineering"], priority="medium")]}, env(), NOW)
        self.assertEqual(tiers(out), {"g1": "work"})

    def test_escalate_sorted_first(self):
        out = E.build([alert("CVE-2026-69982", "Weak authentication in Active Directory Federation "
                             "Services.", 5.9)],
                      {"items": [intel("t1", "Vishing via Microsoft Teams", ["social_engineering"])]}, env(), NOW)
        self.assertEqual(out["items"][0]["tier"], "escalate")
        self.assertEqual(out["counts"], {"escalate": 1, "work": 1})


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

    def test_webhook_url_validation(self):
        self.assertTrue(D.WEBHOOK_RE.match("https://discord.com/api/webhooks/123/abc-DEF_1"))
        self.assertFalse(D.WEBHOOK_RE.match("https://evil.example/api/webhooks/123/abc"))


if __name__ == "__main__":
    unittest.main()
