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


if __name__ == "__main__":
    unittest.main()
