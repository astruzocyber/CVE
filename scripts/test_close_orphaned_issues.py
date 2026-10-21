import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from close_orphaned_issues import board_ids, plan_closures  # noqa: E402


def iss(n, title, pr=False):
    d = {"number": n, "title": title}
    if pr:
        d["pull_request"] = {}
    return d


class TestPlanClosures(unittest.TestCase):
    IDS = {f"CVE-2026-{i:05d}" for i in range(1000, 2100)}

    def test_orphan_closed_board_member_kept(self):
        plan = plan_closures([iss(1, "[VULN ALERT] CVE-2026-01000 (risk 30) - x"),
                              iss(2, "[VULN ALERT] CVE-2025-99999 (risk 26) - php/php")], self.IDS)
        self.assertEqual(plan, [(2, "orphan", "CVE-2025-99999", None)])

    def test_small_board_refuses(self):
        self.assertEqual(plan_closures([iss(2, "[VULN ALERT] CVE-2025-99999")], {"CVE-2026-01000"}), [])

    def test_suppressed_digest_and_pr_skipped(self):
        plan = plan_closures([iss(3, "[VULN ALERT] CVE-2025-11111"), iss(4, "[VULN DIGEST] 8 more"),
                              iss(5, "[VULN ALERT] CVE-2025-22222", pr=True)], self.IDS,
                             suppressed=["cve-2025-11111"])
        self.assertEqual(plan, [])

    def test_duplicate_keeps_oldest(self):
        plan = plan_closures([iss(2377, "[VULN ALERT] CVE-2026-01500 - nvd"),
                              iss(2181, "[VULN ALERT] CVE-2026-01500 - kev")], self.IDS)
        self.assertEqual(plan, [(2377, "duplicate", "CVE-2026-01500", 2181)])

    def test_prefix_id_is_not_a_match(self):
        # CVE-2026-0150 must not count as present because CVE-2026-01500 is on the board
        plan = plan_closures([iss(9, "[VULN ALERT] CVE-2026-0150 - x")], self.IDS)
        self.assertEqual(plan, [(9, "orphan", "CVE-2026-0150", None)])

    def test_cap(self):
        issues = [iss(i, f"[VULN ALERT] CVE-2020-{i:05d}") for i in range(1, 80)]
        self.assertEqual(len(plan_closures(issues, self.IDS, max_close=50)), 50)

    def test_aliases_count_as_board(self):
        ids = board_ids([{"cve_id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2024-12345"]}])
        self.assertIn("CVE-2024-12345", ids)


if __name__ == "__main__":
    unittest.main()
