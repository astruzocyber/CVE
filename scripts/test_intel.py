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

    def test_zdi_0day_disclosure_not_tagged_exploited(self):
        # Real ZDI titles (2026-10): "(0Day)" means published without a vendor
        # patch, not exploited. All 13 were tagged "Actively exploited" and two
        # CVEs entered the board as "news: reported exploited".
        for text in ("ZDI-26-708: (0Day) Microsoft Windows HTTP Proxy Link Following Local Privilege "
                     "Escalation Vulnerability\nUser interaction is required to exploit this vulnerability",
                     "ZDI-26-757: (0Day) Telegram rlottie Numeric Truncation Remote Code Execution Vulnerability",
                     "ZDI-26-705: ( 0-Day ) BusyBox Arbitrary File Creation Vulnerability",
                     "The ZDI is publishing this case as a zero-day advisory."):
            self.assertNotIn("exploited", F.classify(text, WATCH)[0], text)
        for text in ("BeyondTrust 0-Day Vulnerability Exploited Since August",
                     "Palo Alto Warns of PAN-OS 0-day Flaw Actively Exploited in Attacks",
                     "Cisco make-me-root email bug exploited as a 0-day by unknown crims",
                     "Threat Brief: NetScaler Zero Days CVE-2026-88771 and CVE-2026-88772",
                     "ZDI-26-800: (0Day) Foo RCE, now exploited in the wild"):
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

    def test_large_advisory_feed_is_read_and_cap_still_applies(self):
        # CISA all.xml was 5.7 MB (30 full-body advisories) on 2026-10-22; the
        # old 5 MB cap failed the feed on every run.
        class Resp:
            def __init__(self, body):
                self.body = body

            def read(self, n=-1):
                return self.body if n < 0 else self.body[:n]

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        orig = F.urllib.request.urlopen
        try:
            big = b"<rss>" + b" " * int(5.7 * 1024 * 1024) + b"</rss>"
            F.urllib.request.urlopen = lambda req, timeout=25: Resp(big)
            self.assertEqual(F.fetch("https://example.com/all.xml"), big)
            F.urllib.request.urlopen = lambda req, timeout=25: Resp(b"x" * (F.MAX_BYTES + 1))
            with self.assertRaises(ValueError) as cm:
                F.fetch("https://example.com/huge.xml")
            self.assertIn("larger than", str(cm.exception))
        finally:
            F.urllib.request.urlopen = orig


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

    def test_window_edges_and_bad_dates(self):
        # Mutation probe 2026-10-22: '>= cutoff' -> '>', '< cutoff' -> '<=' and
        # skipping the unparseable-date 'continue' all left the suite green
        # (a bad date silently reused the previous item's date).
        kev = {"CVE-2026-1": {"dateAdded": "2026-10-13"},       # recent
               "CVE-2026-2": {"dateAdded": "garbage"},          # must be skipped
               "CVE-2026-3": {"dateAdded": "2026-10-02"},       # exactly 14 days: inside
               "CVE-2026-4": {"dateAdded": "2026-10-01"}}       # 15 days: outside
        self.assertEqual(A.kev_recent_ids(kev, 14, now=NOW), ["CVE-2026-1", "CVE-2026-3"])
        edge = (NOW - timedelta(days=14)).isoformat()
        intel = {"items": [
            {"categories": ["exploited"], "cve_ids": ["CVE-2026-0001"], "published": "2026-10-13T18:00:00+00:00"},
            {"categories": ["exploited"], "cve_ids": ["CVE-2026-0002"], "published": "not a date"},
            {"categories": ["exploited"], "cve_ids": ["CVE-2026-0003"], "published": edge},
            {"categories": ["exploited"], "cve_ids": ["CVE-2026-0004"], "published": "2026-10-02T11:59:59"},
        ]}
        self.assertEqual(A.intel_exploited_cve_ids(intel, 14, now=NOW), ["CVE-2026-0001", "CVE-2026-0003"])

    def test_news_exploited_label_withdrawn_when_news_no_longer_says_so(self):
        # Real case 2026-10-22: ZDI "(0Day)" advisories put CVE-2026-88794 and
        # CVE-2026-111105 on the board as "news: reported exploited" only.
        lbl = A.NEWS_EXPLOITED_LABEL
        intel = {"items": [
            {"categories": ["vulnerability"], "cve_ids": ["CVE-2026-88794", "CVE-2026-111105"]},
            {"categories": ["vulnerability"], "cve_ids": ["CVE-2026-110936"]},
            {"categories": ["exploited"], "cve_ids": ["CVE-2026-0257"]},
        ]}
        alerts = [
            {"cve_id": "CVE-2026-88794", "source": "nvd", "affected": [], "kev": False, "matched_keywords": [lbl]},
            {"cve_id": "CVE-2026-111105", "source": "nvd", "affected": [], "kev": False,
             "matched_keywords": [lbl, "Telegram"]},
            {"cve_id": "CVE-2026-110936", "source": "nvd", "kev": True, "matched_keywords": [lbl, "CISA KEV"]},
            {"cve_id": "CVE-2026-0257", "source": "nvd", "kev": True, "matched_keywords": [lbl, "CISA KEV"]},
            # stories aged out of intel.json: nothing to re-check, label kept
            {"cve_id": "CVE-2026-102255", "source": "nvd", "matched_keywords": [lbl]},
        ]
        kept, withdrawn, removed = A.withdraw_news_exploited(alerts, intel)
        self.assertEqual(removed, ["CVE-2026-88794"])
        self.assertEqual(withdrawn, ["CVE-2026-88794", "CVE-2026-111105", "CVE-2026-110936"])
        by = {a["cve_id"]: a["matched_keywords"] for a in kept}
        self.assertEqual(by, {"CVE-2026-111105": ["Telegram"], "CVE-2026-110936": ["CISA KEV"],
                              "CVE-2026-0257": [lbl, "CISA KEV"], "CVE-2026-102255": [lbl]})
        self.assertEqual(A.withdraw_news_exploited([], {}), ([], [], []))

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

    # The CVSS floor itself had no test: deleting either reject branch below
    # left the suite green, i.e. the board's main admission gate was unguarded.
    def test_cvss_floor_rejects_below_and_unscored(self):
        wl = {"cvss_minimum": 7.0, "require_kev_or_high_epss": False}
        self.assertFalse(A.passes_filters(self._entry(6.9), wl, {}, {}, set()))
        self.assertFalse(A.passes_filters(self._entry(None), wl, {}, {}, set()))  # unknown never passes
        self.assertTrue(A.passes_filters(self._entry(7.0), wl, {}, {}, set()))    # floor is inclusive

    def test_require_kev_or_high_epss_gate(self):
        wl = {"cvss_minimum": 7.0, "require_kev_or_high_epss": True, "epss_high_threshold": 0.5}
        cid = "CVE-2026-69982"
        self.assertFalse(A.passes_filters(self._entry(9.8), wl, {}, {}, set()))
        self.assertFalse(A.passes_filters(self._entry(9.8), wl, {}, {cid: {"epss": None}}, set()))
        self.assertFalse(A.passes_filters(self._entry(9.8), wl, {}, {cid: {"epss": 0.49}}, set()))
        self.assertTrue(A.passes_filters(self._entry(9.8), wl, {}, {cid: {"epss": 0.5}}, set()))
        self.assertTrue(A.passes_filters(self._entry(9.8), wl, {cid: {}}, {}, set()))

    def test_withdraw_keeps_alert_justified_by_pair_or_non_nvd_source(self):
        lbl = A.NEWS_EXPLOITED_LABEL
        intel = {"items": [{"categories": ["vulnerability"], "cve_ids": ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"]}]}
        alerts = [
            {"cve_id": "CVE-2026-1", "source": "nvd", "affected": ["sparx/ea"], "matched_keywords": [lbl]},
            {"cve_id": "CVE-2026-2", "source": "ghsa", "affected": [], "matched_keywords": [lbl]},
            {"cve_id": "CVE-2026-3", "source": "nvd", "affected": [], "matched_keywords": [lbl]},
        ]
        kept, withdrawn, removed = A.withdraw_news_exploited(alerts, intel)
        self.assertEqual(removed, ["CVE-2026-3"])
        self.assertEqual(sorted(a["cve_id"] for a in kept), ["CVE-2026-1", "CVE-2026-2"])
        self.assertTrue(all(a["matched_keywords"] == [] for a in kept))

    def test_suppression_still_wins(self):
        wl = {"cvss_minimum": 7.0}
        self.assertFalse(A.passes_filters(self._entry(9.8, True), wl, {"CVE-2026-69982": {}}, {}, {"CVE-2026-69982"}))

    def test_tracked_alert_gets_news_exploited_label(self):
        # Real case 2026-10-22: CVE-2026-110447 (Collabora/Nextcloud RCE, CVSS
        # 9.2) was on the board via the "Nextcloud" keyword when BleepingComputer
        # reported it exploited; the news-only ingest skips tracked CVEs, so it
        # never got the label and escalate.py left it in 'work'.
        lbl = A.NEWS_EXPLOITED_LABEL
        intel = {"items": [
            {"categories": ["exploited", "vulnerability"], "cve_ids": ["CVE-2026-110447"],
             "published": "2026-10-15T20:25:00+00:00"},
            {"categories": ["patch"], "cve_ids": ["CVE-2026-69982"], "published": "2026-10-15T20:25:00+00:00"},
        ]}
        alerts = [
            {"cve_id": "CVE-2026-110447", "source": "nvd", "matched_keywords": ["Nextcloud"]},
            {"cve_id": "CVE-2026-69982", "source": "nvd", "matched_keywords": ["Jira"]},
            {"cve_id": "CVE-2026-0257", "source": "nvd", "matched_keywords": [lbl, "CISA KEV"]},
            {"cve_id": "CVE-2026-109618", "source": "nvd", "matched_keywords": None},
        ]
        ids = A.intel_exploited_cve_ids(intel, 14, now=NOW) + ["CVE-2026-0257", "cve-2026-109618"]
        self.assertEqual(A.label_news_exploited(alerts, ids), ["CVE-2026-110447", "CVE-2026-109618"])
        by = {a["cve_id"]: a["matched_keywords"] for a in alerts}
        self.assertEqual(by["CVE-2026-110447"], ["Nextcloud", lbl])
        self.assertEqual(by["CVE-2026-69982"], ["Jira"])               # patch news only: untouched
        self.assertEqual(by["CVE-2026-0257"], [lbl, "CISA KEV"])       # no duplicate label
        self.assertEqual(by["CVE-2026-109618"], [lbl])
        self.assertEqual(A.label_news_exploited(alerts, ids), [])      # idempotent
        # and the withdraw pass on the next run keeps it (news still says exploited)
        kept, withdrawn, removed = A.withdraw_news_exploited(alerts, intel)
        self.assertEqual((withdrawn, removed), ([], []))

    def test_main_labels_tracked_alerts(self):
        import inspect
        src = inspect.getsource(A.main)
        self.assertIn("label_news_exploited(existing_by_key.values(), news_ids)", src)
        self.assertLess(src.index("news_ids = intel_exploited_cve_ids("), src.index("label_news_exploited("))


if __name__ == "__main__":
    unittest.main()
