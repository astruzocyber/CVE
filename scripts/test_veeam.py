#!/usr/bin/env python3
"""Tests for the Veeam ecosystem integration and the multi-word keyword fix.

Fixture text is copied from the real Veeam KB security feed
(https://www.veeam.com/services/open/kb/security-feed, fetched 2026-10-20).
"""
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aggregate as A  # noqa: E402
import escalate as E  # noqa: E402
import fetch_intel as F  # noqa: E402

NOW = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
WATCH = F.compile_watch(F.watch_terms({"keywords": ["Veeam"]}))

BODY = (
    "<p>Article Applicability All vulnerabilities listed in this article: Affect only Veeam Backup &amp; "
    "Replication 12.3.2 P3 (build 12.3.2.4854) and older builds.</p> Issue Details "
    "<h3>CVE-2025-64393</h3><p>A vulnerability allowing a low-privileged user with the Backup Viewer role to "
    "perform remote code execution (RCE) on the Veeam Backup Server.</p><p>Severity: Critical</p>"
    "<p>CVSS v4.0 Score: 9.4</p><p>Solution This vulnerability was fixed starting in the following build: "
    "Veeam Backup &amp; Replication 12.3.2 P4 (build 12.3.2.4934)</p>"
    "<h3>CVE-2026-93026</h3><p>A vulnerability allowing an authenticated user with the Backup Viewer role to "
    "modify or delete the Enterprise Manager master key.</p><p>Severity: Medium</p><p>CVSS v4.0 Score: 6.1</p>"
    "<p>Note: see also CVE-2025-64393.</p>"
)
ATOM = f"""<?xml version="1.0" encoding="utf-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>Veeam</title>
<entry><title>Vulnerabilities Resolved in Veeam Backup &amp; Replication 12.3.2 P4</title>
<link href="https://www.veeam.com/kb4830"/><updated>2026-10-06T10:00:00Z</updated>
<summary>Vulnerabilities Resolved in Veeam Backup &amp; Replication 12.3.2 P4</summary>
<content type="html">{BODY.replace('&', '&amp;').replace('<', '&lt;')}</content></entry>
<entry><title>List of Security Fixes and Improvements in Veeam ONE</title>
<link href="https://www.veeam.com/kb4700"/><updated>2026-08-25T10:00:00Z</updated>
<summary>This article describes all security-related fixes and improvements introduced in each release or update of Veeam ONE.</summary>
<content type="html">CVE-2024-42019 CVE-2024-42020 CVE-2024-42021</content></entry>
</feed>""".encode()


class TestVeeamAdvisoryParsing(unittest.TestCase):
    def setUp(self):
        self.raws = F.parse_feed(ATOM)
        self.items = [F.build_item(r, "Veeam Security KB", WATCH, NOW, advisory=True) for r in self.raws]

    def test_atom_content_is_captured(self):
        self.assertIn("CVE-2025-64393", self.raws[0]["content"])

    def test_per_cve_vendor_rating(self):
        adv = {a["cve"]: a for a in self.items[0]["advisory"]}
        self.assertEqual(adv["CVE-2025-64393"]["severity"], "critical")
        self.assertEqual(adv["CVE-2025-64393"]["cvss"], 9.4)
        self.assertEqual(adv["CVE-2025-64393"]["cvss_version"], "4.0")
        self.assertIn("12.3.2.4934", adv["CVE-2025-64393"]["fixed_in"])
        self.assertEqual(adv["CVE-2026-93026"]["severity"], "medium")
        self.assertEqual(adv["CVE-2026-93026"]["cvss"], 6.1)

    def test_cross_reference_does_not_overwrite(self):
        # "see also CVE-2025-64393" inside the 93026 block must not re-rate 64393
        adv = {a["cve"]: a for a in self.items[0]["advisory"]}
        self.assertEqual(len(self.items[0]["advisory"]), 2)
        self.assertEqual(adv["CVE-2025-64393"]["cvss"], 9.4)

    def test_item_fields(self):
        it = self.items[0]
        self.assertEqual(it["kind"], "advisory")
        self.assertEqual(it["advisory_severity"], "critical")
        self.assertEqual(it["priority"], "high")
        self.assertIn("veeam", it["watch_matches"])
        self.assertEqual(set(it["cve_ids"]), {"CVE-2025-64393", "CVE-2026-93026"})
        # summary replaces the title-only <summary> with facts from the body
        self.assertTrue(it["summary"].startswith("2 CVEs: 1 Critical, 1 Medium; highest CVSS 9.4 (v4.0)."))
        self.assertIn("12.3.2 P3", it["summary"])

    def test_changelog_index_page_has_no_advisory_rows(self):
        it = self.items[1]
        self.assertEqual(it["advisory"], [])
        self.assertEqual(it["cve_ids"], [])
        self.assertIsNone(it["advisory_severity"])

    def test_non_advisory_feed_unchanged(self):
        it = F.build_item(self.raws[0], "News", WATCH, NOW)
        self.assertNotIn("kind", it)
        self.assertNotIn("advisory", it)

    def test_unrated_cve_is_none_not_guessed(self):
        adv = F.parse_advisory("CVE-2026-11111 A vulnerability with no rating text.")
        self.assertEqual(adv, [{"cve": "CVE-2026-11111", "severity": None, "cvss": None,
                                "cvss_version": None, "description": None, "fixed_in": None}])

    def test_source_retention_keeps_old_advisories(self):
        old = {"id": "a" * 16, "title": "t", "link": "https://x", "source": "Veeam Security KB",
               "published": "2026-03-12T00:00:00+00:00", "score": 65}
        news = dict(old, id="b" * 16, source="News")
        kept = F.merge([old, news], [], NOW, 45, 500, {"Veeam Security KB": 365})
        self.assertEqual([i["source"] for i in kept], ["Veeam Security KB"])


class TestVeeamEscalation(unittest.TestCase):
    def setUp(self):
        self.env = E.load_env()
        self.item = F.build_item(F.parse_feed(ATOM)[0], "Veeam Security KB", WATCH, NOW, advisory=True)
        self.item["id"] = "c" * 16

    def test_veeam_is_a_critical_asset(self):
        hits = E.match_assets("Veeam Backup & Replication", self.env["assets"])
        self.assertTrue(hits)
        self.assertEqual(hits[0][0]["criticality"], "critical")

    def test_vendor_critical_bulletin_escalates(self):
        out = E.classify_intel(self.item, self.env, {})
        self.assertEqual(out["tier"], "escalate")
        self.assertTrue(any("Vendor rates Critical: CVE-2025-64393" in r for r in out["reasons"]))

    def test_vendor_medium_bulletin_does_not_escalate(self):
        it = dict(self.item, advisory_severity="medium",
                  advisory=[dict(a, severity="medium") for a in self.item["advisory"]])
        out = E.classify_intel(it, self.env, {})
        self.assertNotEqual(out["tier"], "escalate")


class TestPhraseMatching(unittest.TestCase):
    WL = {"keywords": ["Check Point", "Windows Kernel", "Exchange Online", "Veeam"], "priority_keywords": []}

    def test_phrase_in(self):
        self.assertTrue(A.phrase_in("Check Point", "a Check Point Harmony flaw"))
        self.assertTrue(A.phrase_in("Check Point", "check-point gateway"))
        self.assertFalse(A.phrase_in("Check Point", "check the null pointer at this point"))
        self.assertFalse(A.phrase_in("Windows Kernel", "Linux kernel ... on Windows"))

    def test_prune_drops_loose_only_alerts(self):
        alerts = [
            {"cve_id": "CVE-1", "source": "nvd", "matched_keywords": ["Check Point"],
             "description": "In the Linux kernel, check ... at point x"},
            {"cve_id": "CVE-2", "source": "nvd", "matched_keywords": ["Check Point"],
             "description": "Check Point Harmony Email"},
            {"cve_id": "CVE-3", "source": "nvd", "matched_keywords": ["Check Point"], "kev": True,
             "description": "kernel check point"},  # literal -> kept anyway
            {"cve_id": "CVE-4", "source": "nvd", "matched_keywords": ["Check Point"], "kev": True,
             "description": "check at point"},  # KEV justifies it
            {"cve_id": "CVE-5", "source": "kev", "matched_keywords": ["Windows Kernel"],
             "description": "kernel of windows"},  # non-NVD source justifies it
            {"cve_id": "CVE-6", "source": "nvd", "matched_keywords": ["Microsoft Exchange Server"],
             "description": "SSRF in Microsoft Exchange Online"},  # re-attributed
        ]
        wl = dict(self.WL, keywords=self.WL["keywords"] + ["Microsoft Exchange Server"])
        kept, removed = A.prune_loose_phrase_matches(alerts, wl)
        self.assertEqual(removed, ["CVE-1"])
        by = {a["cve_id"]: a for a in kept}
        self.assertEqual(by["CVE-4"]["matched_keywords"], [])
        self.assertEqual(by["CVE-6"]["matched_keywords"], ["Exchange Online"])

    def test_nvd_uses_exact_match_for_phrases_only(self):
        seen = []

        def fake(params, api_key):
            seen.append(dict(params))
            return {"vulnerabilities": [], "totalResults": 0}

        with mock.patch.object(A, "nvd_query", side_effect=fake), mock.patch.object(A.time, "sleep"):
            A.fetch_nvd_candidates({"keywords": ["Check Point", "Veeam"], "vendors_products": [],
                                    "priority_keywords": []}, None)
        by_kw = {p.get("keywordSearch"): p for p in seen if p.get("keywordSearch")}
        self.assertIn("keywordExactMatch", by_kw["Check Point"])
        self.assertNotIn("keywordExactMatch", by_kw["Veeam"])


if __name__ == "__main__":
    unittest.main()
