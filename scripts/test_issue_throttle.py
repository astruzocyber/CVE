#!/usr/bin/env python3
"""Tests for the GitHub-issue notifier's rate-limit safety (per-run cap,
overflow digest, Retry-After handling). No network."""
import os
import sys
import unittest
import json
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import notify_github_issues as N  # noqa: E402


class ThrottleTests(unittest.TestCase):
    def setUp(self):
        self._orig = N._board_tiers

    def tearDown(self):
        N._board_tiers = self._orig

    def test_cap_keeps_board_items_first_and_overflows_rest(self):
        N._board_tiers = lambda: {"cve:CVE-2026-9": "escalate", "cve:CVE-2026-8": "work"}
        alerts = [{"cve_id": f"CVE-2026-{i}", "risk_score": 90 - i} for i in range(10)]
        keep, over = N.split_for_cap(alerts, cap=3)
        self.assertEqual([a["cve_id"] for a in keep], ["CVE-2026-9", "CVE-2026-8", "CVE-2026-0"])
        self.assertEqual(len(keep) + len(over), 10)

    def test_overflow_digest_lists_every_alert(self):
        over = [{"cve_id": f"CVE-2026-{i}", "cvss_score": 7.5, "risk_score": 50} for i in range(12)]
        body = N.build_digest_body(over)
        for a in over:
            self.assertIn(a["cve_id"], body)

    def test_retry_after_is_honoured_and_capped(self):
        self.assertEqual(N.retry_wait({"Retry-After": "30"}, 0), 30)
        self.assertEqual(N.retry_wait({"Retry-After": "9999"}, 0), 120)
        self.assertEqual(N.retry_wait({}, 0), 15)
        self.assertEqual(N.retry_wait({}, 5), 120)


class NetworkErrorTests(unittest.TestCase):
    """A timeout/reset on one issue POST raised out of create_issue() and ended
    main(), so every later alert of that run lost its issue for good (seen_ids
    is committed before the notifier runs)."""

    def setUp(self):
        self._sleep, N.time.sleep = N.time.sleep, (lambda s: None)
        self._tiers, N._board_tiers = N._board_tiers, (lambda: {})

    def tearDown(self):
        N.time.sleep, N._board_tiers = self._sleep, self._tiers

    def _ok(self, number):
        resp = mock.MagicMock()
        resp.__enter__.return_value.read.return_value = json.dumps({"number": number}).encode()
        return resp

    def test_network_error_is_retried(self):
        with mock.patch.object(N.urllib.request, "urlopen",
                               side_effect=[TimeoutError("read timed out"), self._ok(7)]) as m:
            self.assertTrue(N.create_issue("o/r", "t", "x", "b", []))
        self.assertEqual(m.call_count, 2)

    def test_persistent_network_error_does_not_stop_later_alerts(self):
        alerts = [{"cve_id": "CVE-2026-1", "risk_score": 90}, {"cve_id": "CVE-2026-2", "risk_score": 10}]
        effects = [urllib.error.URLError("down")] * 4 + [self._ok(8)]
        env = {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r"}
        with mock.patch.dict(os.environ, env), \
             mock.patch.object(N, "load_new_alerts", return_value=alerts), \
             mock.patch.object(N.urllib.request, "urlopen", side_effect=effects) as m:
            N.main()
        self.assertEqual(m.call_count, 5)
        posted = json.loads(m.call_args_list[-1].args[0].data)
        self.assertIn("CVE-2026-2", posted["title"])


class RiskMethodTests(unittest.TestCase):
    """The issue body explains how the risk score was computed. Real case: issue
    #2086 (CVE-2026-108444, CVSS 8.8, EPSS not published yet, not KEV) said
    'risk 51.3 (35% CVSS + 40% EPSS + 25% KEV bonus)', but those weights give
    30.8; the pipeline had redistributed EPSS's weight onto CVSS (58.3%)."""

    def test_redistributed_weights_are_stated(self):
        import aggregate
        score, bd = aggregate.composite_risk_score(8.8, None, False)
        a = {"cve_id": "CVE-2026-108444", "cvss_score": 8.8, "epss_score": None,
             "risk_score": score, "risk_score_breakdown": bd}
        body = N.build_issue_body(a)
        line = next(ln for ln in body.splitlines() if ln.startswith("**Composite risk score:**"))
        self.assertIn("51.3/100", line)
        self.assertNotIn("35% CVSS + 40% EPSS", line)
        self.assertIn("EPSS not published yet", line)
        self.assertIn("58.3% of (CVSS/10)", line)

    def test_standard_weights_when_nothing_missing(self):
        import aggregate
        score, bd = aggregate.composite_risk_score(9.8, 0.5, True)
        a = {"cve_id": "CVE-2026-1", "risk_score": score, "risk_score_breakdown": bd}
        self.assertIn("(35% CVSS + 40% EPSS + 25% KEV bonus", N.build_issue_body(a))
        # alerts without a breakdown (old data) keep the documented default text
        self.assertIn("(35% CVSS + 40% EPSS + 25% KEV bonus", N.build_issue_body({"risk_score": 50}))


class WhatMatchedLabelTests(unittest.TestCase):
    """Real case (run 40240601329): CVE-2026-53943 (Ghost CMS, keyword
    'content management system', no CPE pair) got the issue title
    '... (risk 33.8) - nvd' and 'nvd' in the digest's Affected column. 'nvd' is
    the data source, not an affected product; 222 open issues read that way."""

    def test_keyword_only_alert_names_its_keyword_not_the_source(self):
        a = {"cve_id": "CVE-2026-53943", "risk_score": 33.8, "source": "nvd", "affected": [],
             "matched_keywords": ["content management system"], "cvss_score": 9.6}
        title = N.issue_title(a)
        self.assertTrue(title.endswith(" - keyword: content management system"), title)
        self.assertNotIn("| nvd |", N.build_digest_body([a]))
        self.assertIn("| keyword: content management system |", N.build_digest_body([a]))

    def test_pairs_win_and_source_is_last_resort(self):
        a = {"cve_id": "CVE-1", "source": "nvd", "affected": ["php/php"], "matched_keywords": ["x"]}
        self.assertTrue(N.issue_title(a).endswith(" - php/php"))
        b = {"cve_id": "CVE-2", "source": "ghsa", "affected": [], "matched_keywords": []}
        self.assertTrue(N.issue_title(b).endswith(" - ghsa"))
        c = {"cve_id": "CVE-3", "affected": ["a/b", "c/d"], "matched_keywords": ["k1", "k2"]}
        self.assertTrue(N.issue_title(c).endswith(" - a/b, c/d"))
        c["affected"] = []
        self.assertTrue(N.issue_title(c).endswith(" - keyword: k1, k2"))
        self.assertEqual(N.what_matched({}), "unknown")


class TitleAndDigestFormatTests(unittest.TestCase):
    """The title is what the team reads in the issue list and what the closers
    parse the ID from; the digest must stay a valid table and say how many
    rows it left out. Example alert is real board data (CVE-2021-42287)."""

    REAL = {"cve_id": "CVE-2021-42287", "kev": True, "kev_ransomware_use": True, "risk_score": 82.1,
            "affected": ["microsoft/active directory"], "source": "kev", "cvss_score": 7.5}

    def setUp(self):
        self._orig, N._board_tiers = N._board_tiers, (lambda: {})

    def tearDown(self):
        N._board_tiers = self._orig

    def test_title_tags(self):
        self.assertEqual(N.issue_title(self.REAL),
                         "[VULN ALERT] CVE-2021-42287 [KEV] [RANSOMWARE] (risk 82.1) - microsoft/active directory")
        plain = dict(self.REAL, kev=False, kev_ransomware_use=False, risk_score=None)
        self.assertEqual(N.issue_title(plain), "[VULN ALERT] CVE-2021-42287 - microsoft/active directory")
        # a 0.0 score is a real score, not a missing one
        self.assertIn("(risk 0.0)", N.issue_title(dict(plain, risk_score=0.0)))
        self.assertIn("UNKNOWN", N.issue_title({"affected": ["a/b"]}))

    def test_digest_row_is_a_valid_table_row(self):
        body = N.build_digest_body([self.REAL, dict(self.REAL, cve_id="CVE-2026-2", kev=False,
                                                    affected=["x|y/z"])])
        self.assertIn("| CVE-2021-42287 | 7.5 | 82.1 | yes | microsoft/active directory |", body)
        self.assertIn("| CVE-2026-2 | 7.5 | 82.1 |  | x/y/z |", body)

    def test_digest_lists_300_and_counts_the_rest(self):
        over = [{"cve_id": f"CVE-2026-{i}", "affected": ["v/p"]} for i in range(305)]
        body = N.build_digest_body(over)
        rows = [ln for ln in body.splitlines() if ln.startswith("| CVE-")]
        self.assertEqual(len(rows), 300)
        self.assertIn("…and 5 more (see the dashboard).", body)
        self.assertNotIn("more (see the dashboard)", N.build_digest_body(over[:300]))
        self.assertIn("…and 1 more (see the dashboard).", N.build_digest_body(over[:301]))
        self.assertEqual(body.count("\n\n…and"), 1)


class MentionTests(unittest.TestCase):
    """Upstream text (NVD/GHSA descriptions, credits) is pasted into issues on a
    public repo. GitHub turns '@handle' into a user mention and notifies that
    stranger (real case: CVE-2026-11325 'Thanks to @agentka99 and @beg1nn3r')."""
    MENTION = r"(?<![A-Za-z0-9_`])@[A-Za-z0-9]"

    def test_issue_body_never_mentions_users(self):
        a = {"cve_id": "CVE-2026-11325", "description": "Thanks to @agentka99 and @beg1nn3r. "
             "In @payloadcms/plugin-form-builder. Mail sec@example.com.",
             "affected": ["@scope/pkg"], "matched_keywords": ["@x"], "kev": True,
             "kev_required_action": "ask @someone"}
        body = N.build_issue_body(a)
        self.assertNotRegex(body, self.MENTION)
        self.assertIn("sec@example.com", body)          # emails untouched
        self.assertIn("payloadcms/plugin-form-builder", body)   # text otherwise intact
        self.assertNotRegex(N.issue_title(a), self.MENTION)
        self.assertNotRegex(N.build_digest_body([a]), self.MENTION)

    def test_issue_body_never_references_issues(self):
        # Real cases: CVE-2026-46052 "Not tainted 6.18.17-i1-amd #950", CVE-2025-40273
        # "[#1] SMP", CVE-2025-62429 "Prior to version 5.5.2 #147" -> cross-referenced
        # this repo's unrelated issues #1/#950/#147.
        a = {"cve_id": "CVE-2025-62429", "description": "Not tainted 6.8.6 #1 Hardware. "
             "Oops [#1] SMP. Prior to 5.5.2 #147, see GH-12 and other/repo#34. "
             "Ref https://x.example/page#1 and https://github.com/a/b#5 &#35;9 C# code.",
             "affected": ["php/php"]}
        body = N.build_issue_body(a)
        self.assertIn("6.8.6 #\u200b1 Hardware", body)
        self.assertIn("other/repo#\u200b34", body)
        self.assertIn("5.5.2 #\u200b147", body)
        self.assertIn("[#\u200b1]", body)
        self.assertIn("GH-\u200b12", body)
        self.assertIn("https://x.example/page#1", body)       # URL fragments untouched
        self.assertIn("https://github.com/a/b#5", body)
        self.assertIn("&#35;9", body)
        self.assertIn("### Triage checklist", body)          # headings untouched


if __name__ == "__main__":
    unittest.main()
