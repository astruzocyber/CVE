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


class WorkflowContractTests(unittest.TestCase):
    """The deferral only works if the workflow wires it up the way main()
    expects: the step runs after the aggregator and before the data commit and
    the issue step, and its 'normal window' equals the lookback a plain
    skip_issues dispatch actually uses. If the default lookback is raised
    without NORMAL_LOOKBACK_DAYS, every skip_issues dispatch counts as a
    backfill and its new alerts are dropped again."""

    WF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".github", "workflows",
                      "cve-alerts.yml")
    LOOKBACK_RE = r"\$\{\{\s*inputs\.lookback_days \|\| '(\d+)'\s*\}\}"

    def load(self):
        import yaml
        with open(self.WF, encoding="utf-8") as fh:
            wf = yaml.safe_load(fh)
        return wf, wf["jobs"]["aggregate"]["steps"]

    def step_index(self, steps, pred, what):
        idx = [i for i, s in enumerate(steps) if pred(s)]
        self.assertEqual(len(idx), 1, f"expected exactly one {what} step")
        return idx[0]

    def test_step_order(self):
        _, steps = self.load()
        agg = self.step_index(steps, lambda s: s.get("run") == "python scripts/aggregate.py", "aggregator")
        defer = self.step_index(steps, lambda s: s.get("run") == "python scripts/defer_issues.py", "defer")
        commit = self.step_index(steps, lambda s: "git commit" in str(s.get("run") or ""), "data commit")
        issues = self.step_index(steps, lambda s: s.get("run") == "python scripts/notify_github_issues.py",
                                 "issue notifier")
        self.assertLess(agg, defer)
        self.assertLess(defer, commit)   # issues_deferred.json must be committed
        self.assertLess(commit, issues)
        # the issue step is skipped exactly when defer_issues sees SKIP_ISSUES
        self.assertEqual(str(steps[issues].get("if", "")).replace(" ", ""), "${{!inputs.skip_issues}}")

    def test_normal_window_matches_default_lookback(self):
        import re
        wf, steps = self.load()
        on = wf.get("on", wf.get(True))   # PyYAML reads the bare key 'on' as True
        input_default = str(on["workflow_dispatch"]["inputs"]["lookback_days"]["default"])
        agg = next(s for s in steps if s.get("run") == "python scripts/aggregate.py")
        agg_default = re.search(self.LOOKBACK_RE, str(agg["env"]["LOOKBACK_DAYS"])).group(1)
        self.assertEqual(agg_default, input_default)
        users = [s for s in steps if "NORMAL_LOOKBACK_DAYS" in (s.get("env") or {})]
        self.assertTrue(any(s.get("run") == "python scripts/defer_issues.py" for s in users))
        for s in users:
            env = s["env"]
            self.assertEqual(str(env["NORMAL_LOOKBACK_DAYS"]), agg_default, s.get("name"))
            m = re.search(self.LOOKBACK_RE, str(env.get("LOOKBACK_DAYS", "")))
            self.assertIsNotNone(m, f"{s.get('name')}: LOOKBACK_DAYS must use the dispatch input")
            self.assertEqual(m.group(1), agg_default, s.get("name"))

    def step_env(self, skip_issues, lookback):
        import re
        _, steps = self.load()
        step = next(s for s in steps if s.get("run") == "python scripts/defer_issues.py")
        out = {}
        for k, v in (step.get("env") or {}).items():
            v = re.sub(r"\$\{\{\s*inputs\.skip_issues && '([^']*)' \|\| '' \s*\}\}",
                       lambda m: m.group(1) if skip_issues else "", str(v))
            v = re.sub(self.LOOKBACK_RE, lambda m: str(lookback) if lookback else m.group(1), v)
            self.assertNotIn("${{", v, f"unhandled expression in {k}")
            out[k] = v
        return out

    def test_plain_skip_dispatch_defers_and_backfill_does_not(self):
        with tempfile.TemporaryDirectory() as d:
            paths = {"NEW_ALERTS_PATH": os.path.join(d, "new.json"),
                     "ALERTS_PATH": os.path.join(d, "alerts.json"),
                     "DEFERRED_PATH": os.path.join(d, "deferred.json")}
            with mock.patch.multiple(D, **paths):
                json.dump([A("CVE-1")], open(paths["ALERTS_PATH"], "w"))
                json.dump([A("CVE-1")], open(paths["NEW_ALERTS_PATH"], "w"))
                with mock.patch.dict(os.environ, self.step_env(True, 30), clear=True):
                    D.main()   # backfill: nothing deferred
                self.assertEqual(json.load(open(paths["DEFERRED_PATH"])), [])
                with mock.patch.dict(os.environ, self.step_env(True, None), clear=True):
                    D.main()   # dispatch with only skip_issues ticked
                self.assertEqual(json.load(open(paths["DEFERRED_PATH"])), ["CVE-1"])
                json.dump([], open(paths["NEW_ALERTS_PATH"], "w"))
                with mock.patch.dict(os.environ, self.step_env(False, None), clear=True):
                    D.main()   # next scheduled run
                self.assertEqual([a["cve_id"] for a in json.load(open(paths["NEW_ALERTS_PATH"]))], ["CVE-1"])
                self.assertEqual(json.load(open(paths["DEFERRED_PATH"])), [])


if __name__ == "__main__":
    unittest.main()
