#!/usr/bin/env python3
"""Tests for the threat-intel coverage additions:
  * scripts/fetch_intel.py (news feed parsing / classification / merge)
  * aggregate.py KEV-driven + news-driven ingest and the CVSS-floor bypass

Fixtures mirror the real misses this was built for (Oct 2026): the Windows
Shell MotW zero-day CVE-2026-96951, the AD FS CVEs, the Teams "IT support"
vishing campaign and the Windows 11 black-screen update bug."""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aggregate as A  # noqa: E402
import fetch_intel as F  # noqa: E402

NOW = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
WATCH = F.compile_watch(F.watch_terms({"keywords": ["Windows Shell", "FortiGate"],
                                       "priority_keywords": ["Active Directory Federation Services"]}))

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>Microsoft fixes bug causing Windows black screens, Explorer crashes</title>
<link>https://example.com/a</link><pubDate>Thu, 15 Oct 2026 10:00:00 +0000</pubDate>
<description>&lt;p&gt;An August preview update caused black screens on AVD with FSLogix.&lt;/p&gt;</description></item>
<item><title>Hackers pose as IT support in Microsoft Teams calls to deploy malware</title>
<link>https://example.com/b</link><pubDate>Wed, 14 Oct 2026 09:00:00 GMT</pubDate>
<description>Threat actors impersonate help desk staff over Microsoft Teams.</description></item>
<item><title>Microsoft October Patch Tuesday fixes exploited Windows Shell zero-day CVE-2026-96951</title>
<link>https://example.com/c</link><pubDate>Tue, 13 Oct 2026 18:00:00 GMT</pubDate>
<description>The flaw bypasses Mark of the Web.</description></item>
<item><title>Company announces quarterly earnings</title>
<link>https://example.com/d</link><pubDate>Tue, 13 Oct 2026 18:00:00 GMT</pubDate>
<description>Nothing security related.</description></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0" encoding="utf-8"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Researchers find AD FS spoofing flaw</title><link rel="alternate" href="https://example.com/e"/>
<updated>2026-10-14T08:00:00Z</updated><summary>Active Directory Federation Services vulnerability.</summary></entry>
</feed>"""


def build_all(data):
    return [b for b in (F.build_item(r, "Test", WATCH, NOW) for r in F.parse_feed(data)) if b]


class TestFetchIntel(unittest.TestCase):
    def test_rss_categories_and_noise_drop(self):
        items = {i["link"][-1]: i for i in build_all(RSS)}
        self.assertNotIn("d", items, "non-security item must be dropped")
        self.assertIn("vendor_issue", items["a"]["categories"])
        self.assertIn("social_engineering", items["b"]["categories"])
        self.assertIn("exploited", items["c"]["categories"])
        self.assertIn("patch", items["c"]["categories"])
        self.assertEqual(items["c"]["cve_ids"], ["CVE-2026-96951"])
        self.assertIn("windows shell", items["c"]["watch_matches"])
        self.assertEqual(items["c"]["priority"], "high")
        self.assertEqual(items["a"]["priority"], "high")  # vendor issue on a watched product
        self.assertNotIn("<p>", items["a"]["summary"])

    def test_atom(self):
        items = build_all(ATOM)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["link"], "https://example.com/e")
        self.assertIn("identity", items[0]["categories"])
        self.assertTrue(items[0]["published"].startswith("2026-10-14"))

    def test_cve_ids_only_verbatim(self):
        for it in build_all(RSS) + build_all(ATOM):
            for cid in it["cve_ids"]:
                self.assertIn(cid, f"{it['title']} {it['summary']}")

    def test_hypothetical_exploit_not_tagged_exploited(self):
        cats, _, _ = F.classify("Bug that could be exploited by attackers", WATCH)
        self.assertNotIn("exploited", cats)

    def test_denied_exploitation_not_tagged_exploited(self):
        # real wording: Cisco hardening releases + Docker Hub story (intel.json 2026-10)
        for text in ("These issues were found during internal testing and are not known to be actively exploited.",
                     "Docker says it found no evidence that anyone exploited it.",
                     "There is no evidence of exploitation in the wild.",
                     "The flaw has not been exploited in the wild, Microsoft says",
                     # The Register 2026-10-21 (PHP vs Chainguard disclosure row)
                     "'Coordinated vulnerability disclosure, unless there's evidence of active "
                     "exploits in the wild,' Chainguard CEO tells The Reg",
                     "Details are withheld until the bug is exploited in the wild"):
            self.assertNotIn("exploited", F.classify(text, WATCH)[0], text)
        for text in ("Patch not yet available for actively exploited zero-day in Chrome",
                     "Ivanti says one bug was exploited in attacks; another has not been exploited",
                     "CISA adds actively exploited Fortinet flaw to KEV",
                     "Attackers exploited the zero-day until Fortinet patched it"):
            self.assertIn("exploited", F.classify(text, WATCH)[0], text)
        import escalate as E
        self.assertNotIn("exploited", E.current_categories(
            {"title": "Cisco Meraki Security Hardening Release",
             "summary": "found during internal testing and are not known to be actively exploited."}))

    def test_actor_exploiting_flaw_tagged_exploited(self):
        # Real intel titles/summaries that carried no exploited tag before.
        for text in ("Hackers Exploit Palo Alto Networks PAN-OS Flaw to Bypass MFA and Deploy Ransomware",
                     "Ransomware operators are exploiting a vulnerability in Palo Alto Networks PAN-OS",
                     "Cyber threat actors are actively exploiting the vulnerability to gain initial access",
                     "Cisco Warns of Active Attacks Exploiting New Critical Secure Email Gateway Vulnerability",
                     "Threat actors have begun to exploit a chain of vulnerabilities in Plex Media Server"):
            self.assertIn("exploited", F.classify(text, WATCH)[0], text)
        for text in ("By exploiting this flaw, an attacker with an existing session can mint tokens",
                     "Threat actors are exploiting GTA6 hype with fake leaked downloads",
                     "attackers exploit vulnerable university and government websites to manipulate search results",
                     "Attackers could exploit the flaw to run code",
                     "Hackers are not exploiting the bug yet"):
            self.assertNotIn("exploited", F.classify(text, WATCH)[0], text)

    def test_benchmark_score_not_tagged_exploited(self):
        # Real intel title (2026-10-15): a vendor's AI pentest agent scoring a
        # benchmark, not attackers exploiting AWS. It sat in ESCALATE as
        # "Actively exploited" on the AWS asset.
        for text in ("AWS Security Agent (now part of AWS Continuum) exploited 33 of 37 new real-world CVEs",
                     "GPT-4 agents exploited 87% of one-day vulnerabilities in the benchmark",
                     "The AI model exploited 12 out of 15 test targets"):
            self.assertNotIn("exploited", F.classify(text, WATCH)[0], text)
        for text in ("Hackers exploited 3 of the 5 flaws before patches shipped",
                     "Explained: How AI agents exploited security gaps to access Indian companies' data",
                     "AWS Security Agent exploited 33 of 37 CVEs; separately, attackers exploited a Fortinet zero-day"):
            self.assertIn("exploited", F.classify(text, WATCH)[0], text)

    def test_plural_or_can_update_breakage_is_vendor_issue(self):
        # Real BleepingComputer / GBHackers titles (2026-10): plural "updates"
        # and "can break" missed the vendor_issue rule, so an update breaking
        # Exchange on a watched product scored medium instead of high.
        for text in ("Microsoft: October Windows Server updates break Exchange sign-in, mail flow",
                     "Microsoft Confirms October Windows Updates Can Break Exchange Server Email Services",
                     "Microsoft: October Windows update may break Smart App Control"):
            self.assertIn("vendor_issue", F.classify(text, WATCH)[0], text)
        for text in ("AI-Found Linux Kernel Flaw Gives Local Users Root, and Can Break a Guest Out to the Host",
                     "Frontier AI Broke the Vulnerability Math",
                     "Microsoft Disrupts 3 Phishing Kits Linked to Over 1 Billion Scam Messages"):
            self.assertNotIn("vendor_issue", F.classify(text, WATCH)[0], text)

    def test_bare_teams_not_watch_match(self):
        _, watch, _ = F.classify("How security teams handle alerts", WATCH)
        self.assertNotIn("teams", watch)

    def test_dtd_refused(self):
        with self.assertRaises(ValueError):
            F.parse_feed(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><rss></rss>')

    def test_malformed_xml_regex_fallback(self):
        bad = b"<rss><channel><item><title>Phishing & vishing wave</title><link>https://example.com/z</link></item></channel></rss>"
        items = F.parse_feed(bad)
        self.assertEqual(items[0]["link"], "https://example.com/z")

    def test_unsafe_link_dropped(self):
        self.assertIsNone(F.build_item({"title": "phishing", "link": "javascript:alert(1)"}, "T", WATCH, NOW))

    def test_merge_retention_and_syndication(self):
        a = F.build_item({"title": "Teams phishing wave", "link": "https://x.com/1",
                          "date": "Wed, 14 Oct 2026 09:00:00 GMT"}, "Feed A", WATCH, NOW)
        b = F.build_item({"title": "Teams Phishing Wave", "link": "https://y.com/1",
                          "date": "Wed, 14 Oct 2026 10:00:00 GMT"}, "Feed B", WATCH, NOW)
        old = F.build_item({"title": "Old phishing", "link": "https://z.com/1",
                            "date": "Mon, 01 Jun 2026 09:00:00 GMT"}, "Feed C", WATCH, NOW)
        out = F.merge([old], [a, b], NOW, 30, 100)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["also_reported_by"], ["Feed B"])

    def test_future_date_not_trusted(self):
        it = F.build_item({"title": "phishing", "link": "https://x.com/f",
                           "date": (NOW + timedelta(days=3)).strftime("%a, %d %b %Y %H:%M:%S GMT")}, "T", WATCH, NOW)
        self.assertIsNone(it["published"])

    def test_itemless_feed_response_is_failure_not_ok(self):
        # Oct 2026: Cyber Security News / GBHackers served the CI runner a
        # 200 body with no <item>; the panel then said every feed was OK.
        orig = F.fetch
        try:
            F.fetch = lambda url, timeout=25: b"<html><body>Just a moment...</body></html>"
            with self.assertRaises(ValueError) as cm:
                F.read_feed("https://example.com/feed/")
            self.assertIn("no feed items", str(cm.exception))
            F.fetch = lambda url, timeout=25: RSS
            self.assertEqual(len(F.read_feed("https://example.com/feed/")), 4)
        finally:
            F.fetch = orig


class TestKevAndNewsIngest(unittest.TestCase):
    def test_kev_recent_ids(self):
        kev = {"CVE-2026-96951": {"dateAdded": "2026-10-13"},
               "CVE-2020-0001": {"dateAdded": "2020-01-01"},
               "CVE-2026-1": {"dateAdded": "garbage"}}
        self.assertEqual(A.kev_recent_ids(kev, 14, now=NOW), ["CVE-2026-96951"])

    def test_intel_exploited_ids_only_exploited_and_recent(self):
        intel = {"items": [
            {"categories": ["exploited"], "cve_ids": ["CVE-2026-96951"], "published": "2026-10-13T18:00:00+00:00"},
            {"categories": ["patch"], "cve_ids": ["CVE-2026-69982"], "published": "2026-10-13T18:00:00+00:00"},
            {"categories": ["exploited"], "cve_ids": ["CVE-2025-1111"], "published": "2025-01-01T00:00:00+00:00"},
            {"categories": ["exploited"], "cve_ids": ["not-a-cve"], "published": "2026-10-13T18:00:00+00:00"},
        ]}
        self.assertEqual(A.intel_exploited_cve_ids(intel, 14, now=NOW), ["CVE-2026-96951"])

    def test_kev_fallback_never_invents_score(self):
        e = A.kev_fallback_entry("CVE-2026-96951", {"vendorProject": "Microsoft", "product": "Windows",
                                                    "shortDescription": "Windows Shell command injection"})
        self.assertIsNone(e["cvss_score"])
        self.assertEqual(e["source"], "kev")
        self.assertTrue(e["priority_match"])

    def _entry(self, score, priority=False):
        return {"cve_id": "CVE-2026-69982", "cvss_score": score, "priority_match": priority,
                "matched_keywords": [], "matched_vendor_product": [], "description": "x"}

    def test_priority_keyword_bypasses_cvss_floor(self):
        wl = {"cvss_minimum": 7.0}
        self.assertTrue(A.passes_filters(self._entry(5.9, True), wl, {}, {}, set()))

    def test_kev_bypasses_cvss_floor(self):
        wl = {"cvss_minimum": 7.0}
        self.assertTrue(A.passes_filters(self._entry(None), wl, {"CVE-2026-69982": {}}, {}, set()))

    def test_suppression_still_wins(self):
        wl = {"cvss_minimum": 7.0}
        self.assertFalse(A.passes_filters(self._entry(9.8, True), wl, {"CVE-2026-69982": {}}, {}, {"CVE-2026-69982"}))


if __name__ == "__main__":
    unittest.main()
