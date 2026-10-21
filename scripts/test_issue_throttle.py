#!/usr/bin/env python3
"""Tests for the GitHub-issue notifier's rate-limit safety (per-run cap,
overflow digest, Retry-After handling). No network."""
import os
import sys
import unittest

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
