#!/usr/bin/env python3
"""Tests for carrying skip_issues-run alerts over to the next issue run. No network."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import defer_issues as D  # noqa: E402


def A(cid, risk=50):
    return {"cve_id": cid, "risk_score": risk}


class PlanTests(unittest.TestCase):
    def test_skip_at_normal_window_defers_new_alerts(self):
        out, deferred, _ = D.plan([A("CVE-1"), A("CVE-2")], ["CVE-0"], [], skip=True, backfill=False)
        self.assertEqual(out, [])
        self.assertEqual(deferred, ["CVE-0", "CVE-1", "CVE-2"])

    def test_skip_on_backfill_defers_nothing(self):
        out, deferred, _ = D.plan([A("CVE-1")] * 300, [], [], skip=True, backfill=True)
        self.assertEqual((out, deferred), ([], []))

    def test_normal_run_notifies_deferred_still_on_board_once(self):
        board = [A("CVE-0", 70), A("CVE-1"), A("CVE-9")]
        out, deferred, msg = D.plan([A("CVE-9")], ["CVE-0", "CVE-9", "CVE-gone"], board,
                                    skip=False, backfill=False)
        self.assertEqual([a["cve_id"] for a in out], ["CVE-9", "CVE-0"])  # no duplicate CVE-9
        self.assertEqual(out[1]["risk_score"], 70)                          # current board data
        self.assertEqual(deferred, [])
        self.assertIn("CVE-gone", msg)

    def test_backfill_detection(self):
        self.assertFalse(D.is_backfill("4", "4"))
        self.assertFalse(D.is_backfill("2", "4"))
        self.assertTrue(D.is_backfill("30", "4"))
        self.assertTrue(D.is_backfill("abc", "4"))


class MainTests(unittest.TestCase):
    """End to end over files: a skip run then a normal run opens the skipped alerts."""

    def test_skip_then_normal_run(self):
        with tempfile.TemporaryDirectory() as d:
            paths = {"NEW_ALERTS_PATH": os.path.join(d, "new.json"),
                     "ALERTS_PATH": os.path.join(d, "alerts.json"),
                     "DEFERRED_PATH": os.path.join(d, "deferred.json")}
            with mock.patch.multiple(D, **paths):
                json.dump([A("CVE-1")], open(paths["NEW_ALERTS_PATH"], "w"))
                json.dump([A("CVE-1")], open(paths["ALERTS_PATH"], "w"))
                with mock.patch.dict(os.environ, {"SKIP_ISSUES": "true", "LOOKBACK_DAYS": "4"}):
                    D.main()
                self.assertEqual(json.load(open(paths["DEFERRED_PATH"])), ["CVE-1"])
                # next scheduled run: nothing new, skip_issues unset
                json.dump([], open(paths["NEW_ALERTS_PATH"], "w"))
                with mock.patch.dict(os.environ, {"SKIP_ISSUES": "", "LOOKBACK_DAYS": "4"}):
                    D.main()
                self.assertEqual([a["cve_id"] for a in json.load(open(paths["NEW_ALERTS_PATH"]))], ["CVE-1"])
                self.assertEqual(json.load(open(paths["DEFERRED_PATH"])), [])


if __name__ == "__main__":
    unittest.main()
